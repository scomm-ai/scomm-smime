//! Minimal RFC 5652 EnvelopedData / SignedData for first-ship algorithms.

use aes::Aes256;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::pkcs8::DecodePublicKey;
use rsa::pss::{BlindedSigningKey, Signature as PssSignature, VerifyingKey as PssVerifyingKey};
use rsa::sha2::Sha256 as RsaSha256;
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use scomm_smime_core::*;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use x509_parser::prelude::{FromDer, X509Certificate};
use yasna::models::ObjectIdentifier;
use yasna::Tag;

use crate::bundle::{b64_decode, KeyBundle, KeyEntry};
use crate::cert::{rsa_from_pkcs8, x25519_raw_from_spki_or_raw};
use crate::pqc;

const OID_ENVELOPED: &[u64] = &[1, 2, 840, 113549, 1, 7, 3];
const OID_SIGNED: &[u64] = &[1, 2, 840, 113549, 1, 7, 2];
const OID_DATA: &[u64] = &[1, 2, 840, 113549, 1, 7, 1];
const OID_RSA_OAEP: &[u64] = &[1, 2, 840, 113549, 1, 1, 7];
const OID_AES256_CBC: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 1, 42];
const OID_RSA_PSS: &[u64] = &[1, 2, 840, 113549, 1, 1, 10];
const OID_X25519_ORI: &[u64] = &[1, 3, 101, 110];
/// Scomm hybrid ML-KEM-768+X25519 CMS OtherRecipientInfo (until composite-KEM CMS is RFC).
const OID_HYBRID_ORI: &[u64] = &[1, 3, 6, 1, 4, 1, 54392, 1, 1];
const OID_MLDSA_ORI: &[u64] = &[1, 3, 6, 1, 4, 1, 54392, 1, 2];

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

fn oid(slice: &[u64]) -> ObjectIdentifier {
    ObjectIdentifier::from_slice(slice)
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let parsed = ::pem::parse(pem.as_bytes())
        .map_err(|_| SmimeError::InvalidKey("PEM".into()))?;
    Ok(parsed.contents().to_vec())
}

fn rsa_pub_from_cert_pem(pem: &str) -> Result<RsaPublicKey> {
    let der = pem_to_der(pem)?;
    let (_, cert) = X509Certificate::from_der(&der)
        .map_err(|_| SmimeError::InvalidKey("X.509".into()))?;
    let spki = cert.public_key().raw;
    RsaPublicKey::from_public_key_der(spki)
        .map_err(|_| SmimeError::InvalidKey("RSA SPKI".into()))
}

fn aes_encrypt(cek: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 16])> {
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);
    let ct = Aes256CbcEnc::new(cek.into(), &iv.into())
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext);
    Ok((ct, iv))
}

fn aes_decrypt(cek: &[u8; 32], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let iv: [u8; 16] = iv
        .try_into()
        .map_err(|_| SmimeError::MalformedMessage)?;
    Aes256CbcDec::new(cek.into(), &iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| SmimeError::DecryptionFailed)
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
    OsRng.fill_bytes(&mut cek);
    let (ct, iv) = aes_encrypt(&cek, plaintext)?;
    let mut recips: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::new();
    for pem in cert_pems {
        let rsa_pub = rsa_pub_from_cert_pem(pem)?;
        let wrapped = rsa_pub
            .encrypt(&mut OsRng, Oaep::new::<Sha256>(), &cek)
            .map_err(|_| SmimeError::Internal("RSA-OAEP wrap".into()))?;
        let der = pem_to_der(pem)?;
        let (_, cert) = X509Certificate::from_der(&der)
            .map_err(|_| SmimeError::InvalidKey("X.509".into()))?;
        recips.push((
            cert.issuer().as_raw().to_vec(),
            cert.raw_serial().to_vec(),
            wrapped,
        ));
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

fn ori_enveloped(
    plaintext: &[u8],
    ori_oid: &[u64],
    ori_payload: &[u8],
    cek: &[u8; 32],
) -> Result<Vec<u8>> {
    let (ct, iv) = aes_encrypt(cek, plaintext)?;
    let enveloped = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_u8(4);
            w.next().write_set_of(|w| {
                w.next().write_tagged(Tag::context(4), |w| {
                    w.write_sequence(|w| {
                        w.next().write_oid(&oid(ori_oid));
                        w.next().write_bytes(ori_payload);
                    });
                });
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

fn x25519_enveloped(plaintext: &[u8], recipient_spki: &[u8]) -> Result<Vec<u8>> {
    let mut cek = [0u8; 32];
    OsRng.fill_bytes(&mut cek);
    let eph_secret = StaticSecret::random_from_rng(OsRng);
    let eph_public = X25519Public::from(&eph_secret);
    let their = x25519_raw_from_spki_or_raw(recipient_spki)?;
    let shared = eph_secret.diffie_hellman(&X25519Public::from(their));
    let mut wrapped = cek;
    for (w, s) in wrapped.iter_mut().zip(shared.as_bytes().iter()) {
        *w ^= s;
    }
    let mut payload = Vec::with_capacity(64);
    payload.extend_from_slice(eph_public.as_bytes());
    payload.extend_from_slice(&wrapped);
    ori_enveloped(plaintext, OID_X25519_ORI, &payload, &cek)
}

fn hybrid_enveloped(plaintext: &[u8], recipient: &KeyEntry) -> Result<Vec<u8>> {
    let mut cek = [0u8; 32];
    OsRng.fill_bytes(&mut cek);
    let (payload, kek_material) = pqc::encapsulate_hybrid(recipient)?;
    let mut wrapped = cek;
    for (w, s) in wrapped.iter_mut().zip(kek_material.iter()) {
        *w ^= s;
    }
    let mut ori = payload;
    ori.extend_from_slice(&wrapped);
    ori_enveloped(plaintext, OID_HYBRID_ORI, &ori, &cek)
}

pub fn encrypt_to_entries(plaintext: &[u8], entries: &[&KeyEntry]) -> Result<Vec<u8>> {
    let enc: Vec<&KeyEntry> = entries
        .iter()
        .copied()
        .filter(|e| e.purpose == "encryption")
        .collect();
    let enc = if enc.is_empty() { entries.to_vec() } else { enc };
    if enc.is_empty() {
        return Err(SmimeError::NoSuitableEncryptionKey);
    }
    let rsa_pems: Vec<&str> = enc
        .iter()
        .filter(|e| e.alg.contains("rsa-oaep") || e.alg.contains("rsa"))
        .filter(|e| !e.cert_pem.is_empty())
        .map(|e| e.cert_pem.as_str())
        .collect();
    if enc.len() > 1 && !rsa_pems.is_empty() {
        return rsa_oaep_enveloped(plaintext, &rsa_pems);
    }
    let entry = enc[0];
    if entry.alg.eq_ignore_ascii_case(ALG_MLKEM_HYBRID) || is_pqc_catalog(&entry.alg) {
        return hybrid_enveloped(plaintext, entry);
    }
    if entry.alg.eq_ignore_ascii_case(ALG_RSA_OAEP) || entry.alg.contains("rsa-oaep") {
        if entry.cert_pem.is_empty() {
            return Err(SmimeError::InvalidKey("RSA cert PEM".into()));
        }
        return rsa_oaep_enveloped(plaintext, &[entry.cert_pem.as_str()]);
    }
    if entry.alg.eq_ignore_ascii_case(ALG_X25519) {
        let spki = b64_decode(&entry.spki_b64)?;
        return x25519_enveloped(plaintext, &spki);
    }
    Err(SmimeError::UnsupportedAlgorithm(entry.alg.clone()))
}

fn parse_content_info(cms: &[u8]) -> Result<(ObjectIdentifier, Vec<u8>)> {
    yasna::parse_der(cms, |r| {
        r.read_sequence(|r| {
            let ct = r.next().read_oid()?;
            let inner = r.next().read_tagged(Tag::context(0), |r| r.read_der())?;
            Ok((ct, inner))
        })
    })
    .map_err(|_| SmimeError::MalformedMessage)
}

pub fn inspect_cms(cms: &[u8]) -> Result<MessageInfo> {
    let der = maybe_pem_cms(cms)?;
    let (ct, _inner) = parse_content_info(&der)?;
    let enveloped = ct == oid(OID_ENVELOPED);
    let signed = ct == oid(OID_SIGNED);
    let mut pqc = false;
    let mut algorithm = if enveloped {
        ALG_RSA_OAEP.to_string()
    } else if signed {
        ALG_RSA_PSS.to_string()
    } else {
        String::new()
    };
    if contains_oid(&der, OID_HYBRID_ORI) || contains_oid(&der, OID_MLDSA_ORI) {
        pqc = true;
        algorithm = if signed {
            ALG_MLDSA65.to_string()
        } else {
            ALG_MLKEM_HYBRID.to_string()
        };
    } else if contains_oid(&der, OID_X25519_ORI) && enveloped {
        algorithm = ALG_X25519.to_string();
    }
    Ok(MessageInfo {
        encrypted: enveloped,
        signed,
        pqc,
        algorithm,
    })
}

fn contains_oid(der: &[u8], oid_arc: &[u64]) -> bool {
    let encoded = yasna::construct_der(|w| w.write_oid(&oid(oid_arc)));
    der.windows(encoded.len()).any(|w| w == encoded.as_slice())
}

pub fn maybe_pem_cms(bytes: &[u8]) -> Result<Vec<u8>> {
    let text = String::from_utf8_lossy(bytes);
    if text.contains("BEGIN PKCS7") || text.contains("BEGIN CMS") {
        let p = ::pem::parse(bytes).map_err(|_| SmimeError::MalformedMessage)?;
        return Ok(p.contents().to_vec());
    }
    Ok(bytes.to_vec())
}

pub fn decrypt_with_bundle(cms: &[u8], bundle: &KeyBundle) -> Result<DecryptResult> {
    let der = maybe_pem_cms(cms)?;
    let info = inspect_cms(&der)?;
    if !info.encrypted {
        return Err(SmimeError::MalformedMessage);
    }
    if info.algorithm == ALG_RSA_OAEP {
        let mut last = None;
        for e in bundle.encryption_entries().filter(|e| e.alg.contains("rsa")) {
            if let Some(pkcs8) = e.pkcs8_b64.as_ref() {
                match rsa_from_pkcs8(pkcs8.as_bytes()) {
                    Ok(sk) => match decrypt_rsa_oaep(&der, &sk) {
                        Ok(pt) => {
                            return Ok(DecryptResult {
                                plaintext: pt,
                                algorithm: ALG_RSA_OAEP.to_string(),
                            });
                        }
                        Err(e) => last = Some(e),
                    },
                    Err(e) => last = Some(e),
                }
            }
        }
        return Err(last.unwrap_or(SmimeError::WrongPrivateKey));
    }
    if info.algorithm == ALG_X25519 {
        for e in bundle.encryption_entries().filter(|e| e.alg == ALG_X25519) {
            if let Some(pkcs8) = e.pkcs8_b64.as_ref() {
                let raw = b64_decode(pkcs8)?;
                if raw.len() == 32 {
                    let mut seed = [0u8; 32];
                    seed.copy_from_slice(&raw);
                    let sk = StaticSecret::from(seed);
                    if let Ok(pt) = decrypt_x25519(&der, &sk) {
                        return Ok(DecryptResult {
                            plaintext: pt,
                            algorithm: ALG_X25519.to_string(),
                        });
                    }
                }
            }
        }
        return Err(SmimeError::WrongPrivateKey);
    }
    if info.pqc || info.algorithm == ALG_MLKEM_HYBRID {
        for e in bundle
            .encryption_entries()
            .filter(|e| is_pqc_catalog(&e.alg))
        {
            if let Ok(pt) = pqc::decapsulate_and_decrypt(e, &der) {
                return Ok(DecryptResult {
                    plaintext: pt,
                    algorithm: ALG_MLKEM_HYBRID.to_string(),
                });
            }
        }
        return Err(SmimeError::WrongPrivateKey);
    }
    Err(SmimeError::UnsupportedAlgorithm(info.algorithm))
}

fn read_enveloped_parts(
    cms: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let der = maybe_pem_cms(cms)?;
    let (_ct, inner) = parse_content_info(&der)?;
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

fn decrypt_rsa_oaep(cms: &[u8], sk: &RsaPrivateKey) -> Result<Vec<u8>> {
    let (recip, iv, ct) = read_enveloped_parts(cms)?;
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
        match sk.decrypt(Oaep::new::<Sha256>(), &wrapped) {
            Ok(cek_vec) => {
                if let Ok(cek) = <[u8; 32]>::try_from(cek_vec.as_slice()) {
                    if let Ok(pt) = aes_decrypt(&cek, &iv, &ct) {
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

fn decrypt_x25519(cms: &[u8], sk: &StaticSecret) -> Result<Vec<u8>> {
    let (recip, iv, ct) = read_enveloped_parts(cms)?;
    let payload = extract_ori_payload(&recip)?;
    if payload.len() != 64 {
        return Err(SmimeError::MalformedMessage);
    }
    let eph: [u8; 32] = payload[..32]
        .try_into()
        .map_err(|_| SmimeError::MalformedMessage)?;
    let mut wrapped = [0u8; 32];
    wrapped.copy_from_slice(&payload[32..]);
    let shared = sk.diffie_hellman(&X25519Public::from(eph));
    let mut cek = wrapped;
    for (w, s) in cek.iter_mut().zip(shared.as_bytes().iter()) {
        *w ^= s;
    }
    aes_decrypt(&cek, &iv, &ct)
}

pub fn extract_ori_payload(recip_der: &[u8]) -> Result<Vec<u8>> {
    let mut payload = None;
    yasna::parse_der(recip_der, |r| {
        r.read_set_of(|r| {
            let bytes = r.read_tagged(Tag::context(4), |r| {
                r.read_sequence(|r| {
                    let _oid = r.next().read_oid()?;
                    r.next().read_bytes()
                })
            })?;
            payload = Some(bytes);
            Ok(())
        })
    })
    .map_err(|_| SmimeError::MalformedMessage)?;
    payload.ok_or(SmimeError::MalformedMessage)
}

pub fn extract_ori_iv_ct(cms: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    read_enveloped_parts(cms)
}

pub fn aes_decrypt_pub(cek: &[u8; 32], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    aes_decrypt(cek, iv, ct)
}

fn rsa_pub_from_entry(entry: &KeyEntry) -> Result<RsaPublicKey> {
    rsa_pub_from_cert_pem(&entry.cert_pem)
}

pub fn sign_pss(data: &[u8], entry: &KeyEntry) -> Result<Vec<u8>> {
    let sig_bytes = sign_pss_raw(data, entry)?;
    let signed = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_oid(&oid(OID_RSA_PSS));
            w.next().write_bytes(data);
            w.next().write_bytes(&sig_bytes);
        });
    });
    Ok(wrap_content_info(oid(OID_SIGNED), signed))
}

/// The same RSA-PSS-SHA256 signature [sign_pss] produces, without the CMS
/// SignedData `ContentInfo` wrapping — for artifact proof-of-possession,
/// where the server verifies the raw signature bytes directly.
pub fn sign_pss_raw(data: &[u8], entry: &KeyEntry) -> Result<Vec<u8>> {
    let pkcs8 = entry
        .pkcs8_b64
        .as_ref()
        .ok_or(SmimeError::NoSuitableSigningKey)?;
    let sk = rsa_from_pkcs8(pkcs8.as_bytes())?;
    let signing = BlindedSigningKey::<RsaSha256>::new(sk);
    let sig = signing.sign_with_rng(&mut OsRng, data);
    Ok(sig.to_vec())
}

/// Raw RSA-OAEP-SHA256 decrypt of [ciphertext] — no CMS EnvelopedData
/// parsing, unlike [decrypt_rsa_oaep]. For artifact proof-of-possession,
/// where the server sends a small directly-RSA-encrypted nonce, not a full
/// CMS message.
pub fn rsa_oaep_decrypt_raw(ciphertext: &[u8], entry: &KeyEntry) -> Result<Vec<u8>> {
    let pkcs8 = entry
        .pkcs8_b64
        .as_ref()
        .ok_or(SmimeError::NoSuitableEncryptionKey)?;
    let sk = rsa_from_pkcs8(pkcs8.as_bytes())?;
    sk.decrypt(Oaep::new::<Sha256>(), ciphertext)
        .map_err(|_| SmimeError::DecryptionFailed)
}

pub fn sign_mldsa(data: &[u8], entry: &KeyEntry) -> Result<Vec<u8>> {
    let sig = pqc::sign_mldsa(data, entry)?;
    let signed = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_oid(&oid(OID_MLDSA_ORI));
            w.next().write_bytes(data);
            w.next().write_bytes(&sig);
        });
    });
    Ok(wrap_content_info(oid(OID_SIGNED), signed))
}

pub fn verify_signature(data: &[u8], signature: &[u8], public: &KeyBundle) -> Result<VerificationResult> {
    let der = maybe_pem_cms(signature)?;
    let (ct, inner) = parse_content_info(&der)?;
    if ct != oid(OID_SIGNED) {
        return Ok(VerificationResult {
            validity: SignatureValidity::MalformedSignature,
        });
    }
    let parsed = yasna::parse_der(&inner, |r| {
        r.read_sequence(|r| {
            let alg = r.next().read_oid()?;
            let inner_data = r.next().read_bytes()?;
            let sig = r.next().read_bytes()?;
            Ok((alg, inner_data, sig))
        })
    });
    let Ok((alg, inner_data, sig)) = parsed else {
        return Ok(VerificationResult {
            validity: SignatureValidity::MalformedSignature,
        });
    };
    let payload = if inner_data.is_empty() { data } else { &inner_data };
    if payload != data && !inner_data.is_empty() && inner_data != data {
        // encapsulated content must match
        if inner_data != data {
            return Ok(VerificationResult {
                validity: SignatureValidity::CryptographicallyInvalid,
            });
        }
    }
    let message = if inner_data.is_empty() { data } else { inner_data.as_slice() };
    if alg == oid(OID_RSA_PSS) {
        for e in public.signing_entries() {
            if e.cert_pem.is_empty() {
                continue;
            }
            if let Ok(pk) = rsa_pub_from_entry(e) {
                let vk = PssVerifyingKey::<RsaSha256>::new(pk);
                if let Ok(sig_t) = PssSignature::try_from(sig.as_slice()) {
                    if vk.verify(message, &sig_t).is_ok() {
                        return Ok(VerificationResult {
                            validity: SignatureValidity::CryptographicallyValid,
                        });
                    }
                }
            }
        }
        return Ok(VerificationResult {
            validity: SignatureValidity::CryptographicallyInvalid,
        });
    }
    if alg == oid(OID_MLDSA_ORI) {
        for e in public.signing_entries().filter(|e| is_pqc_catalog(&e.alg)) {
            if pqc::verify_mldsa(message, &sig, e) {
                return Ok(VerificationResult {
                    validity: SignatureValidity::CryptographicallyValid,
                });
            }
        }
        return Ok(VerificationResult {
            validity: SignatureValidity::CryptographicallyInvalid,
        });
    }
    Ok(VerificationResult {
        validity: SignatureValidity::UnsupportedAlgorithm,
    })
}

pub fn pem_pkcs7(der: &[u8]) -> Vec<u8> {
    ::pem::Pem::new("PKCS7", der.to_vec()).to_string().into_bytes()
}
