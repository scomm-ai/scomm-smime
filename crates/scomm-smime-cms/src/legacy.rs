//! Read-only support for formats only older Scomm builds write.
//!
//! F0-scomm: AES-256-CBC EnvelopedData with no integrity protection, whose
//! RSA recipients use OAEP-SHA256 under parameters that say SHA-1, and whose
//! X25519 and hybrid recipients wrap the content key with a plain XOR. S0: a
//! `SEQUENCE { algorithm, data, signature }` in place of SignedData.
//!
//! Reached only through [crate::classify]. Nothing here writes; the writers
//! still in use until Release 2 live in [crate::legacy_writer].

use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Padding;
use openssl::sign::{RsaPssSaltlen, Verifier};
use openssl::symm::{Cipher, Crypter, Mode};
use scomm_smime_core::*;
use yasna::models::ObjectIdentifier;
use yasna::Tag;

use crate::bundle::{b64_decode, KeyBundle};
use crate::cert::{ed25519_verify, rsa_from_pkcs8, x25519_dh};
use crate::classify::{Kind, Recipient};
use crate::cms_envelop::{oaep_decrypt, oid, rsa_pub_from_cert_pem};
use crate::pqc;
use crate::reader::{cleanse, ossl_failed};
use crate::trust::spki_fingerprint;

pub(crate) const OID_ENVELOPED: &[u64] = &[1, 2, 840, 113549, 1, 7, 3];
pub(crate) const OID_SIGNED: &[u64] = &[1, 2, 840, 113549, 1, 7, 2];
pub(crate) const OID_RSA_PSS: &[u64] = &[1, 2, 840, 113549, 1, 1, 10];
pub(crate) const OID_ED25519: &[u64] = &[1, 3, 101, 112];
pub(crate) const OID_X25519_ORI: &[u64] = &[1, 3, 101, 110];
/// Not Scomm's arc (IANA PEN 54392 is another organization). Only read, and
/// only inside a legacy OtherRecipientInfo or S0 signature.
pub(crate) const OID_HYBRID_ORI: &[u64] = &[1, 3, 6, 1, 4, 1, 54392, 1, 1];
pub(crate) const OID_MLDSA_ORI: &[u64] = &[1, 3, 6, 1, 4, 1, 54392, 1, 2];

pub(crate) const KEY_CHECK_LEN: usize = 8;

/// Kind of a message OpenSSL could not parse. Anything that is not exactly
/// one of the two legacy shapes is malformed.
pub(crate) fn classify(der: &[u8]) -> Result<Kind> {
    let (content_type, inner) = parse_content_info(der)?;
    if content_type == oid(OID_ENVELOPED) {
        let (recipients, _, _) = read_enveloped_parts(der)?;
        let recipients = ori_list(&recipients)?
            .into_iter()
            .map(|(ori, _)| {
                if ori == oid(OID_X25519_ORI) {
                    Recipient::LegacyX25519
                } else if ori == oid(OID_HYBRID_ORI) {
                    Recipient::LegacyHybrid
                } else {
                    Recipient::Unsupported
                }
            })
            .collect();
        return Ok(Kind::Enveloped {
            authenticated: false,
            recipients,
        });
    }
    if content_type == oid(OID_SIGNED) {
        let (alg, _, _) = parse_s0(&inner)?;
        let algorithm = if alg == oid(OID_ED25519) {
            ALG_ED25519
        } else if alg == oid(OID_RSA_PSS) {
            ALG_RSA_PSS
        } else if alg == oid(OID_MLDSA_ORI) {
            ALG_MLDSA65
        } else {
            ""
        };
        return Ok(Kind::LegacySigned { algorithm });
    }
    Err(SmimeError::MalformedMessage)
}

fn parse_content_info(der: &[u8]) -> Result<(ObjectIdentifier, Vec<u8>)> {
    yasna::parse_der(der, |r| {
        r.read_sequence(|r| {
            let ct = r.next().read_oid()?;
            let inner = r.next().read_tagged(Tag::context(0), |r| r.read_der())?;
            Ok((ct, inner))
        })
    })
    .map_err(|_| SmimeError::MalformedMessage)
}

fn parse_s0(inner: &[u8]) -> Result<(ObjectIdentifier, Vec<u8>, Vec<u8>)> {
    yasna::parse_der(inner, |r| {
        r.read_sequence(|r| {
            let alg = r.next().read_oid()?;
            let data = r.next().read_bytes()?;
            let sig = r.next().read_bytes()?;
            Ok((alg, data, sig))
        })
    })
    .map_err(|_| SmimeError::MalformedMessage)
}

/// `(recipientInfos DER, IV, ciphertext)` of an AES-CBC EnvelopedData.
fn read_enveloped_parts(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let (_ct, inner) = parse_content_info(der)?;
    yasna::parse_der(&inner, |r| {
        r.read_sequence(|r| {
            let _v = r.next().read_u8()?;
            let recip = r.next().read_der()?;
            let (iv, ct) = r.next().read_sequence(|r| {
                let _data = r.next().read_oid()?;
                let iv = r.next().read_sequence(|r| {
                    let _oid = r.next().read_oid()?;
                    r.next().read_bytes()
                })?;
                let tagged = r.next().read_tagged_der()?;
                let raw = tagged.value();
                let ct = if raw.first() == Some(&0x04) {
                    yasna::parse_der(raw, |r| r.read_bytes()).unwrap_or_else(|_| raw.to_vec())
                } else {
                    raw.to_vec()
                };
                Ok((iv, ct))
            })?;
            Ok((recip, iv, ct))
        })
    })
    .map_err(|_| SmimeError::MalformedMessage)
}

/// Every `[4] { oriType, OCTET STRING }` in a legacy recipientInfos SET.
fn ori_list(recip_der: &[u8]) -> Result<Vec<(ObjectIdentifier, Vec<u8>)>> {
    let mut out = Vec::new();
    yasna::parse_der(recip_der, |r| {
        r.read_set_of(|r| {
            out.push(r.read_tagged(Tag::context(4), |r| {
                r.read_sequence(|r| Ok((r.next().read_oid()?, r.next().read_bytes()?)))
            })?);
            Ok(())
        })
    })
    .map_err(|_| SmimeError::MalformedMessage)?;
    Ok(out)
}

fn ori_payloads(recip_der: &[u8], wanted: &[u64]) -> Result<Vec<Vec<u8>>> {
    let wanted = oid(wanted);
    Ok(ori_list(recip_der)?
        .into_iter()
        .filter(|(ori, _)| *ori == wanted)
        .map(|(_, payload)| payload)
        .collect())
}

/// D5 on the legacy path: CBC has no tag, so the padding check is the only
/// failure signal. Every block but the last is already decrypted when it
/// fails, so the buffer is cleansed before the error is returned.
fn aes_cbc_decrypt(cek: &[u8; 32], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let iv: [u8; 16] = iv.try_into().map_err(|_| SmimeError::MalformedMessage)?;
    let cipher = Cipher::aes_256_cbc();
    let mut c = Crypter::new(cipher, Mode::Decrypt, cek, Some(&iv))
        .map_err(|_| ossl_failed(SmimeError::DecryptionFailed))?;
    let mut out = vec![0u8; ciphertext.len() + cipher.block_size()];
    let n = match c.update(ciphertext, &mut out) {
        Ok(n) => c.finalize(&mut out[n..]).map(|m| n + m),
        Err(e) => Err(e),
    };
    match n {
        Ok(n) => {
            cleanse(&mut out[n..]);
            out.truncate(n);
            Ok(out)
        }
        Err(_) => {
            cleanse(&mut out);
            Err(ossl_failed(SmimeError::DecryptionFailed))
        }
    }
}

/// Tag over a recipient's key-wrap mask. ORI recipients carry no identifier and
/// the CEK wrap is a bare XOR, so a non-matching key only fails on AES-CBC
/// padding, which still passes about 1 in 256 times and yields garbage. With
/// several recipients every key meets several ORIs, so multi-recipient
/// payloads append this tag and a non-matching ORI is skipped.
pub(crate) fn key_check(mask: &[u8; 32]) -> Result<[u8; KEY_CHECK_LEN]> {
    let mut input = b"scomm-smime ori key-check".to_vec();
    input.extend_from_slice(mask);
    let digest = openssl::hash::hash(MessageDigest::sha256(), &input)
        .map_err(|e| SmimeError::Internal(e.to_string()))?;
    let mut tag = [0u8; KEY_CHECK_LEN];
    tag.copy_from_slice(&digest[..KEY_CHECK_LEN]);
    Ok(tag)
}

/// Inverse of the legacy XOR wrap; `check` is empty for single-recipient payloads.
fn unwrap_cek(wrapped: &[u8], mask: &[u8; 32], check: &[u8]) -> Result<[u8; 32]> {
    if !check.is_empty() && check != key_check(mask)?.as_slice() {
        return Err(SmimeError::WrongPrivateKey);
    }
    let mut cek: [u8; 32] = wrapped
        .try_into()
        .map_err(|_| SmimeError::MalformedMessage)?;
    for (c, m) in cek.iter_mut().zip(mask.iter()) {
        *c ^= m;
    }
    Ok(cek)
}

fn opened(plaintext: Vec<u8>, algorithm: &str) -> DecryptResult {
    DecryptResult {
        plaintext,
        algorithm: algorithm.to_string(),
        format: FORMAT_F0_SCOMM.to_string(),
    }
}

/// Opens an F0-scomm message with whichever of the bundle's keys matches one
/// of its recipients.
pub(crate) fn decrypt(
    der: &[u8],
    recipients: &[Recipient],
    bundle: &KeyBundle,
) -> Result<DecryptResult> {
    if recipients.contains(&Recipient::LegacyKeyTransport) {
        let mut last = None;
        for e in bundle
            .encryption_entries()
            .filter(|e| e.alg.contains("rsa"))
        {
            if let Some(pkcs8) = e.pkcs8_b64.as_ref() {
                match rsa_from_pkcs8(pkcs8.as_bytes()).and_then(|sk| decrypt_rsa_oaep(der, &sk)) {
                    Ok(pt) => return Ok(opened(pt, ALG_RSA_OAEP)),
                    Err(e) => last = Some(e),
                }
            }
        }
        return Err(last.unwrap_or(SmimeError::WrongPrivateKey));
    }
    // A multi-recipient message may hold X25519 and hybrid ORIs side by side.
    let has_x25519 = recipients.contains(&Recipient::LegacyX25519);
    let has_hybrid = recipients.contains(&Recipient::LegacyHybrid);
    if has_x25519 {
        for e in bundle.encryption_entries().filter(|e| e.alg == ALG_X25519) {
            if let Some(pkcs8) = e.pkcs8_b64.as_ref() {
                let raw = b64_decode(pkcs8)?;
                if let Ok(seed) = <[u8; 32]>::try_from(raw.as_slice()) {
                    if let Ok(pt) = decrypt_x25519(der, &seed) {
                        return Ok(opened(pt, ALG_X25519));
                    }
                }
            }
        }
    }
    if has_hybrid {
        for e in bundle
            .encryption_entries()
            .filter(|e| is_pqc_catalog(&e.alg))
        {
            if let Ok(pt) = decrypt_hybrid(e, der) {
                return Ok(opened(pt, ALG_MLKEM_HYBRID));
            }
        }
    }
    if has_x25519 || has_hybrid {
        return Err(SmimeError::WrongPrivateKey);
    }
    Err(SmimeError::UnsupportedAlgorithm("recipient type".into()))
}

fn decrypt_rsa_oaep(der: &[u8], sk: &PKey<Private>) -> Result<Vec<u8>> {
    let (recip, iv, ct) = read_enveloped_parts(der)?;
    let mut wrapped_keys: Vec<Vec<u8>> = Vec::new();
    yasna::parse_der(&recip, |r| {
        r.read_set_of(|r| {
            let bytes = r.read_sequence(|r| {
                let _v = r.next().read_u8()?;
                let _rid = r.next().read_der()?;
                let _alg = r.next().read_der()?;
                r.next().read_bytes()
            })?;
            wrapped_keys.push(bytes);
            Ok(())
        })
    })
    .map_err(|_| SmimeError::MalformedMessage)?;
    if wrapped_keys.is_empty() {
        return Err(SmimeError::MalformedMessage);
    }
    let mut last = SmimeError::DecryptionFailed;
    for wrapped in wrapped_keys {
        match oaep_decrypt(sk, &wrapped) {
            Ok(cek_vec) => {
                if let Ok(cek) = <[u8; 32]>::try_from(cek_vec.as_slice()) {
                    if let Ok(pt) = aes_cbc_decrypt(&cek, &iv, &ct) {
                        return Ok(pt);
                    }
                }
                last = SmimeError::DecryptionFailed;
            }
            Err(_) => {
                last = SmimeError::Internal(format!("oaep wrapped_len={}", wrapped.len()));
            }
        }
    }
    Err(last)
}

fn decrypt_x25519(der: &[u8], sk: &[u8; 32]) -> Result<Vec<u8>> {
    let (recip, iv, ct) = read_enveloped_parts(der)?;
    for payload in ori_payloads(&recip, OID_X25519_ORI)? {
        if payload.len() != 64 && payload.len() != 64 + KEY_CHECK_LEN {
            continue;
        }
        let eph: [u8; 32] = payload[..32]
            .try_into()
            .map_err(|_| SmimeError::MalformedMessage)?;
        let shared = x25519_dh(sk, &eph)?;
        let Ok(cek) = unwrap_cek(&payload[32..64], &shared, &payload[64..]) else {
            continue;
        };
        if let Ok(pt) = aes_cbc_decrypt(&cek, &iv, &ct) {
            return Ok(pt);
        }
    }
    Err(SmimeError::WrongPrivateKey)
}

fn decrypt_hybrid(entry: &crate::bundle::KeyEntry, der: &[u8]) -> Result<Vec<u8>> {
    let (kem_seed, x_seed) = pqc::hybrid_secret(entry)?;
    let (recip, iv, ct) = read_enveloped_parts(der)?;
    for payload in ori_payloads(&recip, OID_HYBRID_ORI)? {
        let wrap_end = pqc::MLKEM_CT_LEN + 64;
        if payload.len() != wrap_end && payload.len() != wrap_end + KEY_CHECK_LEN {
            continue;
        }
        let eph: [u8; 32] = payload[pqc::MLKEM_CT_LEN..pqc::MLKEM_CT_LEN + 32]
            .try_into()
            .map_err(|_| SmimeError::MalformedMessage)?;
        let Ok(ss) = pqc::mlkem_decaps(&kem_seed, &payload[..pqc::MLKEM_CT_LEN]) else {
            continue;
        };
        let shared_x = x25519_dh(&x_seed, &eph)?;
        let mask = pqc::legacy_hybrid_mask(&ss, &shared_x)?;
        let Ok(cek) = unwrap_cek(
            &payload[pqc::MLKEM_CT_LEN + 32..wrap_end],
            &mask,
            &payload[wrap_end..],
        ) else {
            continue;
        };
        if let Ok(pt) = aes_cbc_decrypt(&cek, &iv, &ct) {
            return Ok(pt);
        }
    }
    Err(SmimeError::WrongPrivateKey)
}

fn pss_verify(pk: &PKey<openssl::pkey::Public>, message: &[u8], sig: &[u8]) -> bool {
    let Ok(mut verifier) = Verifier::new(MessageDigest::sha256(), pk) else {
        return false;
    };
    verifier.set_rsa_padding(Padding::PKCS1_PSS).is_ok()
        && verifier
            .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
            .is_ok()
        && verifier.update(message).is_ok()
        && verifier.verify(sig).unwrap_or(false)
}

/// S0 verdict: never chained or trusted here. The fingerprint is the SPKI
/// hash of the key that verified, the same value S1 reports for that key.
fn verdict(signer: Option<String>) -> SignatureVerdict {
    SignatureVerdict {
        validity: if signer.is_some() {
            SignatureValidity::CryptographicallyValid
        } else {
            SignatureValidity::CryptographicallyInvalid
        },
        format: Some(SignatureFormat::S0),
        signer_fingerprint: signer,
        ..SignatureVerdict::malformed()
    }
}

/// Ed25519 entries store an SPKI (or, in old bundles, the raw 32 bytes).
fn ed25519_key(stored: &[u8]) -> Option<PKey<openssl::pkey::Public>> {
    if stored.len() == 32 {
        PKey::public_key_from_raw_bytes(stored, openssl::pkey::Id::ED25519).ok()
    } else {
        PKey::public_key_from_der(stored).ok()
    }
}

/// Checks an S0 signature over `data` against the keys already held for the
/// sender. Validity only: an S0 signature is never a source of trust.
pub(crate) fn verify(data: &[u8], der: &[u8], public: &KeyBundle) -> Result<SignatureVerdict> {
    let (_, inner) = parse_content_info(der)?;
    let (alg, inner_data, sig) = parse_s0(&inner)?;
    // The encapsulated copy, when present, must be the signed data itself.
    if !inner_data.is_empty() && inner_data != data {
        return Ok(verdict(None));
    }
    let fingerprint = |k: &PKey<openssl::pkey::Public>| spki_fingerprint(k).ok();
    if alg == oid(OID_ED25519) {
        let signer = public
            .signing_entries()
            .filter(|e| e.alg.eq_ignore_ascii_case(ALG_ED25519) && !e.spki_b64.is_empty())
            .filter_map(|e| b64_decode(&e.spki_b64).ok())
            .find(|spki| spki.len() >= 32 && ed25519_verify(&spki[spki.len() - 32..], data, &sig))
            .and_then(|spki| ed25519_key(&spki))
            .and_then(|k| fingerprint(&k));
        return Ok(verdict(signer));
    }
    if alg == oid(OID_RSA_PSS) {
        let signer = public
            .signing_entries()
            .filter(|e| !e.cert_pem.is_empty())
            .filter_map(|e| rsa_pub_from_cert_pem(&e.cert_pem).ok())
            .find(|pk| pss_verify(pk, data, &sig))
            .and_then(|k| fingerprint(&k));
        return Ok(verdict(signer));
    }
    if alg == oid(OID_MLDSA_ORI) {
        let signer = public
            .signing_entries()
            .filter(|e| is_pqc_catalog(&e.alg))
            .find(|e| pqc::verify_mldsa(data, &sig, e))
            .and_then(|e| b64_decode(&e.spki_b64).ok())
            .and_then(|raw| pqc::mldsa_public_pkey(&raw).ok())
            .and_then(|k| fingerprint(&k));
        return Ok(verdict(signer));
    }
    Ok(SignatureVerdict {
        validity: SignatureValidity::UnsupportedAlgorithm,
        format: Some(SignatureFormat::S0),
        ..SignatureVerdict::malformed()
    })
}
