use rand::rngs::OsRng;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
use rsa::sha2::Sha256 as RsaSha256;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::{RsaPrivateKey, RsaPublicKey};
use scomm_smime_core::*;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use yasna::models::ObjectIdentifier;
use yasna::Tag;

use crate::bundle::{b64_encode, KeyEntry};

pub fn parse_email(userid: &str) -> String {
    if let (Some(start), Some(end)) = (userid.find('<'), userid.find('>')) {
        if end > start {
            return userid[start + 1..end].trim().to_string();
        }
    }
    userid.trim().to_string()
}

pub fn rsa_pkcs8(bits: usize) -> Result<(RsaPrivateKey, Vec<u8>)> {
    let mut rng = OsRng;
    let key = RsaPrivateKey::new(&mut rng, bits)
        .map_err(|e| SmimeError::Internal(format!("rsa generate: {e}")))?;
    let der = key
        .to_pkcs1_der()
        .map_err(|e| SmimeError::Internal(format!("pkcs1: {e}")))?;
    Ok((key, der.as_bytes().to_vec()))
}

fn oid(slice: &[u64]) -> ObjectIdentifier {
    ObjectIdentifier::from_slice(slice)
}

/// Minimal self-signed v3 cert (CN + rfc822Name SAN, KU).
pub fn self_signed_rsa(
    userid: &str,
    pkcs8: &[u8],
    encrypt: bool,
    sign: bool,
) -> Result<String> {
    let email = parse_email(userid);
    let sk = RsaPrivateKey::from_pkcs1_der(pkcs8)
        .or_else(|_| RsaPrivateKey::from_pkcs8_der(pkcs8))
        .or_else(|_| RsaPrivateKey::from_pkcs8_pem(&String::from_utf8_lossy(pkcs8)))
        .map_err(|_| SmimeError::InvalidKey("PKCS#8".into()))?;
    let pk = RsaPublicKey::from(&sk);
    let spki = pk
        .to_public_key_der()
        .map_err(|e| SmimeError::Internal(format!("spki: {e}")))?
        .to_vec();

    let mut ku: u8 = 0;
    if encrypt {
        ku |= 0b0010_0000; // keyEncipherment bit 2 (from left in 7-bit unused...)
    }
    // Digital signature = bit 0 of KeyUsage: 0x80 in a single-byte BIT STRING with unused bits 7.
    // Encode KU as BIT STRING: unused bits 7, value byte.
    let ku_byte = {
        let mut b = 0u8;
        if sign {
            b |= 0x80;
        }
        if encrypt {
            b |= 0x20;
        }
        b
    };

    let cn = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_set_of(|w| {
                w.next().write_sequence(|w| {
                    w.next()
                        .write_oid(&oid(&[2, 5, 4, 3]));
                    w.next().write_utf8_string(&email);
                });
            });
        });
    });

    let san = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_tagged(Tag::context(1), |w| {
                w.write_ia5_string(&email);
            });
        });
    });

    let ku_ext = yasna::construct_der(|w| {
        w.write_bitvec_bytes(&[ku_byte], 8)
    });
    let _ = ku;

    let extensions = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_sequence(|w| {
                w.next().write_oid(&oid(&[2, 5, 29, 15]));
                w.next().write_bool(true);
                w.next().write_bytes(&ku_ext);
            });
            w.next().write_sequence(|w| {
                w.next().write_oid(&oid(&[2, 5, 29, 17]));
                w.next().write_bytes(&san);
            });
        });
    });

    let tbs = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_tagged(Tag::context(0), |w| {
                w.write_u8(2);
            });
            w.next().write_u64(1);
            w.next().write_sequence(|w| {
                w.next().write_oid(&oid(&[1, 2, 840, 113549, 1, 1, 11]));
                w.next().write_null();
            });
            w.next().write_der(&cn);
            w.next().write_sequence(|w| {
                w.next().write_der(&generalized_time("20240101000000Z"));
                w.next().write_der(&generalized_time("20340101000000Z"));
            });
            w.next().write_der(&cn);
            w.next().write_der(&spki);
            w.next().write_tagged(Tag::context(3), |w| {
                w.write_der(&extensions);
            });
        });
    });

    let signing = SigningKey::<RsaSha256>::new(sk);
    let sig = signing.sign(&tbs);

    let cert_der = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_der(&tbs);
            w.next().write_sequence(|w| {
                w.next().write_oid(&oid(&[1, 2, 840, 113549, 1, 1, 11]));
                w.next().write_null();
            });
            w.next().write_bitvec_bytes(sig.to_bytes().as_ref(), sig.to_bytes().as_ref().len() * 8);
        });
    });

    Ok(pem::Pem::new("CERTIFICATE", cert_der).to_string())
}

fn generalized_time(s: &str) -> Vec<u8> {
    let mut out = vec![0x18, s.len() as u8];
    out.extend_from_slice(s.as_bytes());
    out
}

pub fn x25519_pair() -> (StaticSecret, X25519Public, Vec<u8>) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = X25519Public::from(&secret);
    let spki = x25519_spki(public.as_bytes());
    (secret, public, spki)
}

pub fn x25519_spki(raw32: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(44);
    out.extend_from_slice(&[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
    ]);
    out.extend_from_slice(raw32);
    out
}

pub fn x25519_raw_from_spki_or_raw(bytes: &[u8]) -> Result<[u8; 32]> {
    if bytes.len() == 32 {
        return bytes
            .try_into()
            .map_err(|_| SmimeError::InvalidKey("x25519".into()));
    }
    if bytes.len() >= 44 {
        let raw = &bytes[bytes.len() - 32..];
        return raw
            .try_into()
            .map_err(|_| SmimeError::InvalidKey("x25519 spki".into()));
    }
    Err(SmimeError::InvalidKey("x25519 public key".into()))
}

pub fn rsa_from_pkcs8(pkcs8: &[u8]) -> Result<RsaPrivateKey> {
    let text = String::from_utf8_lossy(pkcs8);
    let der = if text.contains("BEGIN") {
        return RsaPrivateKey::from_pkcs1_pem(&text)
            .or_else(|_| RsaPrivateKey::from_pkcs8_pem(&text))
            .map_err(|_| SmimeError::InvalidKey("RSA PEM".into()));
    } else {
        crate::bundle::b64_decode(&text).unwrap_or_else(|_| pkcs8.to_vec())
    };
    RsaPrivateKey::from_pkcs1_der(&der)
        .or_else(|_| RsaPrivateKey::from_pkcs8_der(&der))
        .map_err(|_| {
            SmimeError::InvalidKey(format!(
                "RSA PKCS#8 len={} prefix={:?}",
                der.len(),
                der.get(..16)
            ))
        })
}

pub fn fingerprint_of(bytes: &[u8]) -> String {
    let d = Sha256::digest(bytes);
    d.iter().map(|b| format!("{b:02X}")).collect()
}

pub fn rsa_encrypt_entry(userid: &str) -> Result<KeyEntry> {
    let (_key, pkcs8) = rsa_pkcs8(2048)?;
    let cert = self_signed_rsa(userid, &pkcs8, true, false)?;
    Ok(KeyEntry {
        alg: ALG_RSA_OAEP.to_string(),
        purpose: "encryption".into(),
        cert_pem: cert,
        spki_b64: String::new(),
        pkcs8_b64: Some(b64_encode(&pkcs8)),
    })
}

pub fn rsa_sign_entry(userid: &str) -> Result<KeyEntry> {
    let (_key, pkcs8) = rsa_pkcs8(2048)?;
    let cert = self_signed_rsa(userid, &pkcs8, false, true)?;
    Ok(KeyEntry {
        alg: ALG_RSA_PSS.to_string(),
        purpose: "signing".into(),
        cert_pem: cert,
        spki_b64: String::new(),
        pkcs8_b64: Some(b64_encode(&pkcs8)),
    })
}

pub fn x25519_encrypt_entry() -> KeyEntry {
    let (secret, _public, spki) = x25519_pair();
    KeyEntry {
        alg: ALG_X25519.to_string(),
        purpose: "encryption".into(),
        cert_pem: String::new(),
        spki_b64: b64_encode(&spki),
        pkcs8_b64: Some(b64_encode(secret.as_bytes())),
    }
}
