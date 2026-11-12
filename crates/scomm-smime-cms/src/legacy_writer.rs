//! Writers for the F0-scomm and S0 formats, which all builds still send until
//! Release 2 switches to AuthEnvelopedData and SignedData. Release 2 deletes
//! this module; its output is read back only by [crate::legacy].

use openssl::encrypt::Encrypter;
use openssl::hash::MessageDigest;
use openssl::rand::rand_bytes;
use openssl::rsa::Padding;
use openssl::symm::Cipher;
use scomm_smime_core::*;
use yasna::models::ObjectIdentifier;
use yasna::Tag;

use crate::bundle::{b64_decode, KeyEntry};
use crate::cert::{x25519_dh, x25519_public, x25519_raw_from_spki_or_raw};
use crate::cms_envelop::{oid, rsa_pub_from_cert_pem, sign_ed25519_raw, sign_pss_raw};
use crate::legacy::{
    key_check, OID_ED25519, OID_ENVELOPED, OID_HYBRID_ORI, OID_MLDSA_ORI, OID_RSA_PSS, OID_SIGNED,
    OID_X25519_ORI,
};
use crate::pqc;

const OID_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 1];
const OID_RSA_OAEP: &[u64] = &[1, 2, 840, 113549, 1, 1, 7];
const OID_AES256_CBC: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 42];

fn internal(e: impl ToString) -> SmimeError {
    SmimeError::Internal(e.to_string())
}

fn aes_encrypt(cek: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 16])> {
    let mut iv = [0u8; 16];
    rand_bytes(&mut iv).map_err(internal)?;
    let ct = openssl::symm::encrypt(Cipher::aes_256_cbc(), cek, Some(&iv), plaintext)
        .map_err(|_| internal("aes-cbc"))?;
    Ok((ct, iv))
}

fn wrap_content_info(content_type: ObjectIdentifier, inner: Vec<u8>) -> Vec<u8> {
    yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_oid(&content_type);
            w.next().write_tagged(Tag::context(0), |w| {
                w.write_der(&inner);
            });
        });
    })
}

fn rsa_oaep_enveloped(plaintext: &[u8], cert_pems: &[&str]) -> Result<Vec<u8>> {
    if cert_pems.is_empty() {
        return Err(SmimeError::NoSuitableEncryptionKey);
    }
    let mut cek = [0u8; 32];
    rand_bytes(&mut cek).map_err(internal)?;
    let (ct, iv) = aes_encrypt(&cek, plaintext)?;
    let mut recips: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::new();
    for pem in cert_pems {
        let rsa_pub = rsa_pub_from_cert_pem(pem)?;
        let mut enc = Encrypter::new(&rsa_pub).map_err(internal)?;
        enc.set_rsa_padding(Padding::PKCS1_OAEP).map_err(internal)?;
        enc.set_rsa_oaep_md(MessageDigest::sha256())
            .map_err(internal)?;
        enc.set_rsa_mgf1_md(MessageDigest::sha256())
            .map_err(internal)?;
        let mut wrapped = vec![0u8; enc.encrypt_len(&cek).map_err(internal)?];
        let n = enc
            .encrypt(&cek, &mut wrapped)
            .map_err(|_| internal("RSA-OAEP wrap"))?;
        wrapped.truncate(n);
        let cert = openssl::x509::X509::from_pem(pem.as_bytes())
            .map_err(|_| crate::reader::ossl_failed(SmimeError::InvalidKey("X.509".into())))?;
        let issuer = cert
            .issuer_name()
            .to_der()
            .map_err(|_| SmimeError::InvalidKey("X.509 issuer".into()))?;
        // Magnitude only; `write_bigint_bytes(_, true)` adds the sign byte.
        let serial = cert
            .serial_number()
            .to_bn()
            .map_err(|_| SmimeError::InvalidKey("X.509 serial".into()))?
            .to_vec();
        recips.push((issuer, serial, wrapped));
    }

    let enveloped = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_u8(0);
            w.next().write_set_of(|w| {
                for (issuer_der, serial, wrapped) in &recips {
                    w.next().write_sequence(|w| {
                        w.next().write_u8(0);
                        w.next().write_sequence(|w| {
                            w.next().write_der(issuer_der);
                            w.next().write_bigint_bytes(serial, true);
                        });
                        w.next().write_sequence(|w| {
                            w.next().write_oid(&oid(OID_RSA_OAEP));
                        });
                        w.next().write_bytes(wrapped);
                    });
                }
            });
            w.next().write_sequence(|w| {
                w.next().write_oid(&oid(OID_DATA));
                w.next().write_sequence(|w| {
                    w.next().write_oid(&oid(OID_AES256_CBC));
                    w.next().write_bytes(&iv);
                });
                w.next().write_tagged(Tag::context(0), |w| {
                    w.write_bytes(&ct);
                });
            });
        });
    });
    Ok(wrap_content_info(oid(OID_ENVELOPED), enveloped))
}

/// One OtherRecipientInfo per recipient: (ORI type OID, payload).
fn ori_enveloped(plaintext: &[u8], oris: &[(&[u64], Vec<u8>)], cek: &[u8; 32]) -> Result<Vec<u8>> {
    let (ct, iv) = aes_encrypt(cek, plaintext)?;
    let enveloped = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_u8(4);
            w.next().write_set_of(|w| {
                for (ori_oid, payload) in oris {
                    w.next().write_tagged(Tag::context(4), |w| {
                        w.write_sequence(|w| {
                            w.next().write_oid(&oid(ori_oid));
                            w.next().write_bytes(payload);
                        });
                    });
                }
            });
            w.next().write_sequence(|w| {
                w.next().write_oid(&oid(OID_DATA));
                w.next().write_sequence(|w| {
                    w.next().write_oid(&oid(OID_AES256_CBC));
                    w.next().write_bytes(&iv);
                });
                w.next().write_tagged(Tag::context(0), |w| {
                    w.write_bytes(&ct);
                });
            });
        });
    });
    Ok(wrap_content_info(oid(OID_ENVELOPED), enveloped))
}

/// `wrapped || key_check` (multi-recipient) or `wrapped` (single, the
/// original 64-byte X25519 layout older clients still parse).
fn wrap_cek(cek: &[u8; 32], mask: &[u8; 32], with_check: bool) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = cek.iter().zip(mask.iter()).map(|(c, m)| c ^ m).collect();
    if with_check {
        out.extend_from_slice(&key_check(mask)?);
    }
    Ok(out)
}

fn x25519_ori(cek: &[u8; 32], recipient_spki: &[u8], with_check: bool) -> Result<Vec<u8>> {
    let mut eph_secret = [0u8; 32];
    rand_bytes(&mut eph_secret).map_err(internal)?;
    let their = x25519_raw_from_spki_or_raw(recipient_spki)?;
    let shared = x25519_dh(&eph_secret, &their)?;
    let mut payload = x25519_public(&eph_secret)?.to_vec();
    payload.extend_from_slice(&wrap_cek(cek, &shared, with_check)?);
    Ok(payload)
}

/// `ML-KEM ct || ephemeral X25519 public || wrapped CEK [|| key_check]`.
fn hybrid_ori(cek: &[u8; 32], recipient: &KeyEntry, with_check: bool) -> Result<Vec<u8>> {
    let spki = b64_decode(&recipient.spki_b64)?;
    if spki.len() < pqc::MLKEM_EK_LEN + 32 {
        return Err(SmimeError::InvalidKey("hybrid SPKI".into()));
    }
    let x_raw = x25519_raw_from_spki_or_raw(&spki[pqc::MLKEM_EK_LEN..])?;
    let (mut payload, ss) = pqc::mlkem_encaps(&spki[..pqc::MLKEM_EK_LEN])?;
    let mut eph = [0u8; 32];
    rand_bytes(&mut eph).map_err(internal)?;
    let shared_x = x25519_dh(&eph, &x_raw)?;
    let mask = pqc::legacy_hybrid_mask(&ss, &shared_x)?;
    payload.extend_from_slice(&x25519_public(&eph)?);
    payload.extend_from_slice(&wrap_cek(cek, &mask, with_check)?);
    Ok(payload)
}

pub fn encrypt_to_entries(plaintext: &[u8], entries: &[&KeyEntry]) -> Result<Vec<u8>> {
    let enc: Vec<&KeyEntry> = entries
        .iter()
        .copied()
        .filter(|e| e.purpose == "encryption")
        .collect();
    let enc = if enc.is_empty() {
        entries.to_vec()
    } else {
        enc
    };
    if enc.is_empty() {
        return Err(SmimeError::NoSuitableEncryptionKey);
    }
    let rsa_pems: Vec<&str> = enc
        .iter()
        .filter(|e| e.alg.contains("rsa-oaep") || e.alg.contains("rsa"))
        .filter(|e| !e.cert_pem.is_empty())
        .map(|e| e.cert_pem.as_str())
        .collect();
    if !rsa_pems.is_empty() {
        // KeyTransRecipientInfo and ORI recipients are not mixed: building
        // either kind alone would leave the other recipients unable to read it.
        if rsa_pems.len() != enc.len() {
            return Err(SmimeError::UnsupportedAlgorithm(
                "RSA recipients mixed with X25519/ML-KEM recipients".into(),
            ));
        }
        return rsa_oaep_enveloped(plaintext, &rsa_pems);
    }
    let mut cek = [0u8; 32];
    rand_bytes(&mut cek).map_err(internal)?;
    let with_check = enc.len() > 1;
    let mut oris: Vec<(&[u64], Vec<u8>)> = Vec::with_capacity(enc.len());
    for entry in &enc {
        if entry.alg.eq_ignore_ascii_case(ALG_MLKEM_HYBRID) || is_pqc_catalog(&entry.alg) {
            oris.push((OID_HYBRID_ORI, hybrid_ori(&cek, entry, with_check)?));
        } else if entry.alg.eq_ignore_ascii_case(ALG_X25519) {
            let spki = b64_decode(&entry.spki_b64)?;
            oris.push((OID_X25519_ORI, x25519_ori(&cek, &spki, with_check)?));
        } else if entry.alg.contains("rsa") {
            return Err(SmimeError::InvalidKey("RSA cert PEM".into()));
        } else {
            return Err(SmimeError::UnsupportedAlgorithm(entry.alg.clone()));
        }
    }
    ori_enveloped(plaintext, &oris, &cek)
}

fn s0(alg: &[u64], data: &[u8], sig: &[u8]) -> Vec<u8> {
    let signed = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_oid(&oid(alg));
            w.next().write_bytes(data);
            w.next().write_bytes(sig);
        });
    });
    wrap_content_info(oid(OID_SIGNED), signed)
}

pub fn sign_ed25519(data: &[u8], entry: &KeyEntry) -> Result<Vec<u8>> {
    Ok(s0(OID_ED25519, data, &sign_ed25519_raw(data, entry)?))
}

pub fn sign_pss(data: &[u8], entry: &KeyEntry) -> Result<Vec<u8>> {
    Ok(s0(OID_RSA_PSS, data, &sign_pss_raw(data, entry)?))
}

pub fn sign_mldsa(data: &[u8], entry: &KeyEntry) -> Result<Vec<u8>> {
    Ok(s0(OID_MLDSA_ORI, data, &pqc::sign_mldsa(data, entry)?))
}
