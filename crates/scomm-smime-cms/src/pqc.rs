use openssl::hash::{hash, MessageDigest};
use openssl::rand::rand_bytes;
use ossl::asymcipher::{EncOp, OsslAsymcipher};
use ossl::pkey::{EvpPkey, EvpPkeyType, MlkeyData, PkeyData};
use ossl::signature::{OsslSignature, SigAlg, SigOp};
use ossl::OsslSecret;
use scomm_smime_core::*;

use crate::bundle::{b64_decode, b64_encode, KeyEntry};
use crate::cert::{x25519_dh, x25519_public, x25519_raw_from_spki_or_raw};

pub(crate) const MLKEM_CT_LEN: usize = 1088;
pub(crate) const MLKEM_EK_LEN: usize = 1184;
pub(crate) const MLKEM_SEED_LEN: usize = 64;

fn ctx() -> ossl::OsslContext {
    ossl::OsslContext::new_lib_ctx()
}

/// An ML-DSA-65 key as an ordinary OpenSSL key in the default library
/// context, so CMS and X.509 code can use it. The `openssl` crate has no
/// ML-DSA constructor.
fn mldsa_default_ctx<T>(data: MlkeyData) -> Result<openssl::pkey::PKey<T>> {
    use foreign_types::ForeignType;
    // A null context is OpenSSL's default one; dropping it frees nothing.
    let c = ossl::OsslContext::from_ctx(std::ptr::null_mut());
    let mut key = EvpPkey::import(&c, EvpPkeyType::Mldsa65, PkeyData::Mlkey(data))
        .map_err(|_| SmimeError::InvalidKey("ML-DSA key".into()))?;
    unsafe {
        let p = key.as_mut_ptr();
        if openssl_sys::EVP_PKEY_up_ref(p) != 1 {
            return Err(SmimeError::Internal("EVP_PKEY_up_ref".into()));
        }
        Ok(openssl::pkey::PKey::from_ptr(p))
    }
}

/// ML-DSA-65 private key from its 32-byte seed.
pub(crate) fn mldsa_pkey(seed: &[u8]) -> Result<openssl::pkey::PKey<openssl::pkey::Private>> {
    if seed.len() != 32 {
        return Err(SmimeError::InvalidKey("ML-DSA seed".into()));
    }
    mldsa_default_ctx(MlkeyData {
        pubkey: None,
        prikey: None,
        seed: Some(OsslSecret::from_slice(seed)),
    })
}

/// ML-DSA-65 public key from its raw 1952-byte encoding (`spki_b64`).
pub(crate) fn mldsa_public_pkey(raw: &[u8]) -> Result<openssl::pkey::PKey<openssl::pkey::Public>> {
    if raw.len() != 1952 {
        return Err(SmimeError::InvalidKey("ML-DSA public".into()));
    }
    mldsa_default_ctx(MlkeyData {
        pubkey: Some(raw.to_vec()),
        prikey: None,
        seed: None,
    })
}

fn sha256_32(data: &[u8]) -> Result<[u8; 32]> {
    let dig =
        hash(MessageDigest::sha256(), data).map_err(|e| SmimeError::Internal(e.to_string()))?;
    let bytes: [u8; 32] = dig
        .as_ref()
        .try_into()
        .map_err(|_| SmimeError::Internal("sha256".into()))?;
    Ok(bytes)
}

fn random(n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    rand_bytes(&mut buf).map_err(|e| SmimeError::Internal(e.to_string()))?;
    Ok(buf)
}

pub(crate) fn mlkem_decaps(seed: &[u8], ciphertext: &[u8]) -> Result<[u8; 32]> {
    let c = ctx();
    let mut key = EvpPkey::import(
        &c,
        EvpPkeyType::MlKem768,
        PkeyData::Mlkey(MlkeyData {
            pubkey: None,
            prikey: None,
            seed: Some(OsslSecret::from_slice(seed)),
        }),
    )
    .map_err(|_| SmimeError::InvalidKey("ML-KEM-768 seed".into()))?;
    let mut decap = OsslAsymcipher::new(&c, EncOp::Decapsulate, &mut key, None)
        .map_err(|_| SmimeError::DecryptionFailed)?;
    let shared = decap
        .decapsulate(ciphertext)
        .map_err(|_| SmimeError::DecryptionFailed)?;
    let bytes: &[u8] = shared.as_ref();
    bytes.try_into().map_err(|_| SmimeError::DecryptionFailed)
}

pub(crate) fn mlkem_encaps(ek: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    let c = ctx();
    let mut key = EvpPkey::import(
        &c,
        EvpPkeyType::MlKem768,
        PkeyData::Mlkey(MlkeyData {
            pubkey: Some(ek.to_vec()),
            prikey: None,
            seed: None,
        }),
    )
    .map_err(|_| SmimeError::InvalidKey("ML-KEM ek".into()))?;
    let mut enc = OsslAsymcipher::new(&c, EncOp::Encapsulate, &mut key, None)
        .map_err(|_| SmimeError::Internal("encapsulate".into()))?;
    let mut ct = vec![0u8; MLKEM_CT_LEN];
    let (ss, n) = enc
        .encapsulate(&mut ct)
        .map_err(|_| SmimeError::Internal("encapsulate".into()))?;
    ct.truncate(n);
    let shared: [u8; 32] = ss
        .as_slice()
        .try_into()
        .map_err(|_| SmimeError::Internal("ml-kem shared".into()))?;
    Ok((ct, shared))
}

fn mldsa_public(seed: &[u8]) -> Result<Vec<u8>> {
    let c = ctx();
    let key = EvpPkey::import(
        &c,
        EvpPkeyType::Mldsa65,
        PkeyData::Mlkey(MlkeyData {
            pubkey: None,
            prikey: None,
            seed: Some(OsslSecret::from_slice(seed)),
        }),
    )
    .map_err(|_| SmimeError::InvalidKey("ML-DSA seed".into()))?;
    match key
        .export()
        .map_err(|e| SmimeError::Internal(e.to_string()))?
    {
        PkeyData::Mlkey(MlkeyData {
            pubkey: Some(ref pk),
            ..
        }) => Ok(pk.clone()),
        _ => Err(SmimeError::InvalidKey("ML-DSA public".into())),
    }
}

pub fn hybrid_encrypt_entry() -> Result<KeyEntry> {
    let kem_seed = random(MLKEM_SEED_LEN)?;
    let x_seed = random(32)?;
    let c = ctx();
    let kem = EvpPkey::import(
        &c,
        EvpPkeyType::MlKem768,
        PkeyData::Mlkey(MlkeyData {
            pubkey: None,
            prikey: None,
            seed: Some(OsslSecret::from_slice(&kem_seed)),
        }),
    )
    .map_err(|_| SmimeError::InvalidKey("ML-KEM-768 seed".into()))?;
    let ek = match kem
        .export()
        .map_err(|e| SmimeError::Internal(e.to_string()))?
    {
        PkeyData::Mlkey(MlkeyData {
            pubkey: Some(ref pk),
            ..
        }) => pk.clone(),
        _ => return Err(SmimeError::InvalidKey("ML-KEM ek".into())),
    };
    let x_public = x25519_public(&x_seed)?;
    let mut spki = ek;
    spki.extend_from_slice(&x_public);
    let mut secret = kem_seed;
    secret.extend_from_slice(&x_seed);
    Ok(KeyEntry {
        alg: ALG_MLKEM_HYBRID.to_string(),
        purpose: "encryption".into(),
        cert_pem: String::new(),
        spki_b64: b64_encode(&spki),
        pkcs8_b64: Some(b64_encode(&secret)),
        legacy_key_ids: Vec::new(),
    })
}

/// Self-signed X.509 v3 certificate for an ML-DSA-65 signing entry
/// (`design.md` "Signatures", Q5), built with the OpenSSL X.509 API. Same
/// profile as the Ed25519 signing certificates: `CN=<email>`, SAN
/// rfc822Name, critical key usage digitalSignature, valid 2024-01-01 to
/// 2034-01-01, random 16-byte serial. Seed and public key are unchanged.
pub(crate) fn mldsa_certificate(entry: &KeyEntry, email: &str) -> Result<String> {
    use openssl::asn1::{Asn1Integer, Asn1Time};
    use openssl::bn::BigNum;
    use openssl::x509::extension::{KeyUsage, SubjectAlternativeName};
    use openssl::x509::{X509Name, X509};
    let failed = |what: &str| SmimeError::Internal(format!("ML-DSA certificate: {what}"));
    let seed = b64_decode(entry.pkcs8_b64.as_ref().ok_or(SmimeError::NoSuitableSigningKey)?)?;
    let key = mldsa_pkey(&seed)?;
    let mut name = X509Name::builder().map_err(|_| failed("name"))?;
    name.append_entry_by_text("CN", email).map_err(|_| failed("CN"))?;
    let name = name.build();
    let mut serial = [0u8; 16];
    rand_bytes(&mut serial).map_err(|_| failed("serial"))?;
    serial[0] = (serial[0] & 0x7f) | 0x01; // positive, full 16 bytes
    let serial: Asn1Integer = BigNum::from_slice(&serial)
        .and_then(|b| b.to_asn1_integer())
        .map_err(|_| failed("serial"))?;
    let mut b = X509::builder().map_err(|_| failed("builder"))?;
    b.set_version(2).map_err(|_| failed("version"))?;
    b.set_serial_number(&serial).map_err(|_| failed("serial"))?;
    b.set_subject_name(&name).map_err(|_| failed("subject"))?;
    b.set_issuer_name(&name).map_err(|_| failed("issuer"))?;
    b.set_pubkey(&key).map_err(|_| failed("key"))?;
    let not_before = Asn1Time::from_str("20240101000000Z").map_err(|_| failed("validity"))?;
    let not_after = Asn1Time::from_str("20340101000000Z").map_err(|_| failed("validity"))?;
    b.set_not_before(&not_before)
        .map_err(|_| failed("validity"))?;
    b.set_not_after(&not_after)
        .map_err(|_| failed("validity"))?;
    let ku = KeyUsage::new()
        .critical()
        .digital_signature()
        .build()
        .map_err(|_| failed("key usage"))?;
    b.append_extension(ku).map_err(|_| failed("key usage"))?;
    let san = SubjectAlternativeName::new()
        .email(email)
        .build(&b.x509v3_context(None, None))
        .map_err(|_| failed("SAN"))?;
    b.append_extension(san).map_err(|_| failed("SAN"))?;
    // ML-DSA signs the TBS directly; X509_sign takes no digest.
    b.sign(&key, unsafe { MessageDigest::from_ptr(std::ptr::null()) })
        .map_err(|_| failed("sign"))?;
    let pem = b.build().to_pem().map_err(|_| failed("PEM"))?;
    String::from_utf8(pem).map_err(|_| failed("PEM"))
}

/// The checks a new certificate must pass before the bundle is written
/// back (Q5): it parses, its self-signature holds, it carries exactly the
/// entry's public key and the mailbox address, and the stored seed makes
/// a signature that verifies under it.
fn certificate_is_sound(entry: &KeyEntry, email: &str) -> Result<()> {
    use openssl::x509::X509;
    let bad = || SmimeError::Internal("ML-DSA certificate did not verify".into());
    let cert = X509::from_pem(entry.cert_pem.as_bytes()).map_err(|_| bad())?;
    let in_cert = cert.public_key().map_err(|_| bad())?;
    if !cert.verify(&in_cert).map_err(|_| bad())? {
        return Err(bad());
    }
    let stored = mldsa_public_pkey(&b64_decode(&entry.spki_b64)?)?;
    let der = |k: &openssl::pkey::PKeyRef<openssl::pkey::Public>| k.public_key_to_der().ok();
    if der(&in_cert).is_none() || der(&in_cert) != der(&stored) {
        return Err(bad());
    }
    if !crate::trust::email_match(&cert, email) {
        return Err(bad());
    }
    let probe = b"scomm ML-DSA certificate check";
    let sig = crate::signed::sign(probe, entry, crate::signed::SignAlg::MlDsa65)?;
    let v = crate::signed::verify(probe, &sig, &[], None)?;
    if v.validity != SignatureValidity::CryptographicallyValid {
        return Err(bad());
    }
    let _ = openssl::error::ErrorStack::get();
    Ok(())
}

/// Q5 migration, run on unlock: every ML-DSA signing entry with a seed and
/// no certificate gets one; its previous key ID goes into `legacy_key_ids`.
/// Returns the updated secret bundle, or `None` when nothing changed, so a
/// second run is a no-op. All entries are checked before anything is
/// returned; one failure returns the error and no bundle.
pub fn add_mldsa_certificates(secret_bundle: &[u8], email: &str) -> Result<Option<Vec<u8>>> {
    let email = crate::cert::parse_email(email);
    if !email.contains('@') {
        return Err(SmimeError::InvalidArgument("mailbox address".into()));
    }
    let mut bundle = crate::bundle::KeyBundle::parse(secret_bundle)?;
    let mut changed = false;
    for e in bundle.entries.iter_mut() {
        let wants_cert = e.purpose == "signing"
            && is_pqc_catalog(&e.alg)
            && e.cert_pem.is_empty()
            && e.pkcs8_b64.is_some();
        if !wants_cert {
            continue;
        }
        let mut updated = e.clone();
        updated.cert_pem = mldsa_certificate(e, &email)?;
        certificate_is_sound(&updated, &email)?;
        let old_id = crate::cert::fingerprint_of(e.spki_b64.as_bytes());
        if !updated.legacy_key_ids.contains(&old_id) {
            updated.legacy_key_ids.push(old_id);
        }
        *e = updated;
        changed = true;
    }
    if !changed {
        return Ok(None);
    }
    bundle.to_secret_json().map(Some)
}

pub fn mldsa_sign_entry() -> Result<KeyEntry> {
    let seed = random(32)?;
    let public = mldsa_public(&seed)?;
    Ok(KeyEntry {
        alg: ALG_MLDSA65.to_string(),
        purpose: "signing".into(),
        cert_pem: String::new(),
        spki_b64: b64_encode(&public),
        pkcs8_b64: Some(b64_encode(&seed)),
        legacy_key_ids: Vec::new(),
    })
}

/// The legacy F0-scomm hybrid key-wrap mask `SHA-256(ss_mlkem || ss_x25519)`.
/// Read and written only by the legacy modules; not a KDF.
pub(crate) fn legacy_hybrid_mask(ss: &[u8; 32], shared_x: &[u8; 32]) -> Result<[u8; 32]> {
    let mut concat = Vec::with_capacity(64);
    concat.extend_from_slice(ss);
    concat.extend_from_slice(shared_x);
    sha256_32(&concat)
}

pub(crate) fn hybrid_secret(entry: &KeyEntry) -> Result<(Vec<u8>, [u8; 32])> {
    let secret = b64_decode(
        entry
            .pkcs8_b64
            .as_ref()
            .ok_or(SmimeError::InvalidKey("hybrid sk".into()))?,
    )?;
    if secret.len() < MLKEM_SEED_LEN + 32 {
        return Err(SmimeError::InvalidKey("hybrid secret".into()));
    }
    let x_seed: [u8; 32] = secret[MLKEM_SEED_LEN..MLKEM_SEED_LEN + 32]
        .try_into()
        .map_err(|_| SmimeError::InvalidKey("x25519 seed".into()))?;
    Ok((secret[..MLKEM_SEED_LEN].to_vec(), x_seed))
}

pub fn pop_hybrid(
    entry: &KeyEntry,
    kem_ciphertext: &[u8],
    ephemeral_x25519: &[u8],
) -> Result<Vec<u8>> {
    if kem_ciphertext.len() != MLKEM_CT_LEN {
        return Err(SmimeError::InvalidArgument("ML-KEM-768 ct".into()));
    }
    let (kem_seed, x_seed) = hybrid_secret(entry)?;
    let ss = mlkem_decaps(&kem_seed, kem_ciphertext)?;
    let eph = x25519_raw_from_spki_or_raw(ephemeral_x25519)?;
    let shared_x = x25519_dh(&x_seed, &eph)?;
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&ss);
    out.extend_from_slice(&shared_x);
    Ok(out)
}

pub fn sign_mldsa(data: &[u8], entry: &KeyEntry) -> Result<Vec<u8>> {
    let seed = b64_decode(
        entry
            .pkcs8_b64
            .as_ref()
            .ok_or(SmimeError::NoSuitableSigningKey)?,
    )?;
    if seed.len() != 32 {
        return Err(SmimeError::InvalidKey("ML-DSA seed".into()));
    }
    let c = ctx();
    let mut key = EvpPkey::import(
        &c,
        EvpPkeyType::Mldsa65,
        PkeyData::Mlkey(MlkeyData {
            pubkey: None,
            prikey: None,
            seed: Some(OsslSecret::from_slice(&seed)),
        }),
    )
    .map_err(|_| SmimeError::InvalidKey("ML-DSA seed".into()))?;
    let mut signer = OsslSignature::new(&c, SigOp::Sign, SigAlg::Mldsa65, &mut key, None)
        .map_err(|e| SmimeError::Internal(e.to_string()))?;
    let mut signature = vec![0u8; 3309];
    signer
        .sign(data, Some(&mut signature))
        .map_err(|e| SmimeError::Internal(e.to_string()))?;
    Ok(signature)
}

pub fn verify_mldsa(data: &[u8], sig: &[u8], entry: &KeyEntry) -> bool {
    if sig.len() != 3309 {
        return false;
    }
    let Ok(vk) = b64_decode(&entry.spki_b64) else {
        return false;
    };
    if vk.len() != 1952 {
        return false;
    }
    let c = ctx();
    let Ok(mut key) = EvpPkey::import(
        &c,
        EvpPkeyType::Mldsa65,
        PkeyData::Mlkey(MlkeyData {
            pubkey: Some(vk),
            prikey: None,
            seed: None,
        }),
    ) else {
        return false;
    };
    let Ok(mut verifier) = OsslSignature::new(&c, SigOp::Verify, SigAlg::Mldsa65, &mut key, None)
    else {
        return false;
    };
    verifier.verify(data, Some(sig)).is_ok()
}
