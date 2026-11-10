//! Message routing on the structural classifier, plus the raw primitives used
//! for key-publication proof of possession.

use openssl::encrypt::Decrypter;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Padding;
use openssl::sign::{RsaPssSaltlen, Signer};
use scomm_smime_core::*;
use yasna::models::ObjectIdentifier;

use crate::bundle::{b64_decode, KeyBundle, KeyEntry};
use crate::cert::{ed25519_sign, rsa_from_pkcs8};
use crate::classify::{classify, Kind, Recipient};
use openssl::x509::X509;

use crate::kekri::Scheme;
use crate::{kekri, legacy, reader, signed};

pub(crate) fn oid(slice: &[u64]) -> ObjectIdentifier {
    ObjectIdentifier::from_slice(slice)
}

pub(crate) fn rsa_pub_from_cert_pem(pem: &str) -> Result<PKey<openssl::pkey::Public>> {
    let key = X509::from_pem(pem.as_bytes())
        .and_then(|c| c.public_key())
        .map_err(|_| reader::ossl_failed(SmimeError::InvalidKey("X.509".into())))?;
    if key.id() != openssl::pkey::Id::RSA {
        return Err(SmimeError::InvalidKey("RSA SPKI".into()));
    }
    Ok(key)
}

pub fn inspect_cms(cms: &[u8]) -> Result<MessageInfo> {
    Ok(match classify(cms)?.kind {
        Kind::Enveloped { recipients, .. } => {
            let hybrid = recipients.contains(&Recipient::LegacyHybrid)
                || recipients.contains(&Recipient::ScommKem(Scheme::MlKem768X25519));
            let x25519 = recipients.contains(&Recipient::LegacyX25519)
                || recipients.contains(&Recipient::ScommKem(Scheme::X25519));
            MessageInfo {
                encrypted: true,
                signed: false,
                pqc: hybrid,
                classical_recipient: x25519,
                algorithm: if hybrid {
                    ALG_MLKEM_HYBRID
                } else if x25519 {
                    ALG_X25519
                } else {
                    ALG_RSA_OAEP
                }
                .to_string(),
            }
        }
        Kind::LegacySigned { algorithm } => MessageInfo {
            signed: true,
            pqc: algorithm == ALG_MLDSA65,
            algorithm: algorithm.to_string(),
            ..Default::default()
        },
        Kind::Signed => MessageInfo {
            signed: true,
            ..Default::default()
        },
        Kind::Other => MessageInfo::default(),
    })
}

pub fn decrypt_with_bundle(cms: &[u8], bundle: &KeyBundle) -> Result<DecryptResult> {
    let parsed = classify(cms)?;
    match &parsed.kind {
        Kind::Enveloped {
            authenticated,
            recipients,
        } if is_standard(*authenticated, recipients) => {
            open_standard(&parsed.der, *authenticated, recipients, bundle)
        }
        Kind::Enveloped {
            authenticated: false,
            recipients,
        } => legacy::decrypt(&parsed.der, recipients, bundle),
        Kind::Enveloped { .. } => Err(SmimeError::UnsupportedAlgorithm("recipient type".into())),
        _ => Err(SmimeError::MalformedMessage),
    }
}

/// Opened by OpenSSL: any RSA key transport, or Scomm KEKRI inside
/// AuthEnvelopedData (F1 only; KEKRI in EnvelopedData is not ours).
fn is_standard(authenticated: bool, recipients: &[Recipient]) -> bool {
    recipients.iter().any(|r| match r {
        Recipient::KeyTransport => true,
        Recipient::ScommKem(_) => authenticated,
        _ => false,
    })
}

/// D2 then D3 on the same message (D4: one failing path does not stop the
/// other). A key that matched but did not open wins over "no key matched".
fn open_standard(
    der: &[u8],
    authenticated: bool,
    recipients: &[Recipient],
    bundle: &KeyBundle,
) -> Result<DecryptResult> {
    let schemes: Vec<Scheme> = recipients
        .iter()
        .filter_map(|r| match r {
            Recipient::ScommKem(s) if authenticated => Some(*s),
            _ => None,
        })
        .collect();
    let mut failure = SmimeError::WrongPrivateKey;
    if recipients.contains(&Recipient::KeyTransport) {
        match reader::decrypt(der, authenticated, bundle) {
            Ok(r) => return Ok(r),
            Err(SmimeError::WrongPrivateKey) => {}
            Err(e) => failure = e,
        }
    }
    if !schemes.is_empty() {
        match kekri::decrypt_with_bundle(der, &schemes, bundle) {
            Ok(r) => return Ok(r),
            Err(SmimeError::WrongPrivateKey) => {}
            Err(e) => failure = e,
        }
    }
    Err(failure)
}

/// S1 through OpenSSL CMS, S0 through the legacy reader (structural
/// routing, R8). `public` holds keys already known for the sender.
pub fn verify_detached(
    data: &[u8],
    signature: &[u8],
    public: Option<&KeyBundle>,
    sender: Option<&str>,
) -> Result<SignatureVerdict> {
    let parsed = match classify(signature) {
        Ok(p) => p,
        Err(SmimeError::MalformedMessage) => return Ok(SignatureVerdict::malformed()),
        Err(e) => return Err(e),
    };
    match parsed.kind {
        Kind::Signed => {
            let known: Vec<X509> = public
                .into_iter()
                .flat_map(|b| b.signing_entries())
                .filter(|e| !e.cert_pem.is_empty())
                .filter_map(|e| X509::from_pem(e.cert_pem.as_bytes()).ok())
                .collect();
            let _ = openssl::error::ErrorStack::get();
            signed::verify(data, &parsed.der, &known, sender)
        }
        Kind::LegacySigned { .. } => match public {
            Some(bundle) => legacy::verify(data, &parsed.der, bundle),
            None => Ok(SignatureVerdict {
                validity: SignatureValidity::UnknownSigner,
                format: Some(SignatureFormat::S0),
                ..SignatureVerdict::malformed()
            }),
        },
        _ => Ok(SignatureVerdict::malformed()),
    }
}

/// Validity only, for callers that predate the verdict.
pub fn verify_signature(
    data: &[u8],
    signature: &[u8],
    public: &KeyBundle,
) -> Result<VerificationResult> {
    Ok(VerificationResult {
        validity: verify_detached(data, signature, Some(public), None)?.validity,
    })
}

pub(crate) fn oaep_decrypt(sk: &PKey<Private>, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let internal = |e: openssl::error::ErrorStack| SmimeError::Internal(e.to_string());
    let mut dec = Decrypter::new(sk).map_err(internal)?;
    dec.set_rsa_padding(Padding::PKCS1_OAEP).map_err(internal)?;
    dec.set_rsa_oaep_md(MessageDigest::sha256())
        .map_err(internal)?;
    dec.set_rsa_mgf1_md(MessageDigest::sha256())
        .map_err(internal)?;
    let mut out = vec![0u8; dec.decrypt_len(ciphertext).map_err(internal)?];
    let n = dec
        .decrypt(ciphertext, &mut out)
        .map_err(|_| SmimeError::DecryptionFailed)?;
    out.truncate(n);
    Ok(out)
}

/// Raw Ed25519 signature over [data], with no pre-hash. The directory
/// verifies these bytes directly for `smime-ed25519` proof of possession.
pub fn sign_ed25519_raw(data: &[u8], entry: &KeyEntry) -> Result<Vec<u8>> {
    let encoded = entry
        .pkcs8_b64
        .as_ref()
        .ok_or(SmimeError::NoSuitableSigningKey)?;
    let seed = b64_decode(encoded)?;
    ed25519_sign(&seed, data)
}

/// RSA-PSS-SHA256 signature without any CMS wrapping — for artifact
/// proof-of-possession, where the server verifies the raw signature bytes.
pub fn sign_pss_raw(data: &[u8], entry: &KeyEntry) -> Result<Vec<u8>> {
    let pkcs8 = entry
        .pkcs8_b64
        .as_ref()
        .ok_or(SmimeError::NoSuitableSigningKey)?;
    let sk = rsa_from_pkcs8(pkcs8.as_bytes())?;
    let internal = |e: openssl::error::ErrorStack| SmimeError::Internal(e.to_string());
    let mut signing = Signer::new(MessageDigest::sha256(), &sk).map_err(internal)?;
    signing
        .set_rsa_padding(Padding::PKCS1_PSS)
        .map_err(internal)?;
    signing
        .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
        .map_err(internal)?;
    signing.update(data).map_err(internal)?;
    signing
        .sign_to_vec()
        .map_err(|_| SmimeError::Internal("rsa-pss".into()))
}

/// Raw RSA-OAEP-SHA256 decrypt of [ciphertext], with no CMS parsing. For
/// artifact proof-of-possession, where the server sends a small
/// directly-RSA-encrypted nonce, not a full CMS message.
pub fn rsa_oaep_decrypt_raw(ciphertext: &[u8], entry: &KeyEntry) -> Result<Vec<u8>> {
    let pkcs8 = entry
        .pkcs8_b64
        .as_ref()
        .ok_or(SmimeError::NoSuitableEncryptionKey)?;
    let sk = rsa_from_pkcs8(pkcs8.as_bytes())?;
    oaep_decrypt(&sk, ciphertext)
}

pub fn pem_pkcs7(der: &[u8]) -> Vec<u8> {
    ::pem::Pem::new("PKCS7", der.to_vec())
        .to_string()
        .into_bytes()
}
