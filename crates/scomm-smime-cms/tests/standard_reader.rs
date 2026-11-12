//! Standard CMS encryption read through OpenSSL (`design.md` D2, D4, D6),
//! with messages built in process so no CLI is needed.

use base64::Engine;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::cms::{CMSOptions, CmsContentInfo};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::symm::Cipher;
use openssl::x509::{X509Name, X509};
use scomm_smime_cms::CmsSmime;
use scomm_smime_core::*;
use serde_json::json;

const MSG: &[u8] = b"standard reader plaintext";

struct Identity {
    key: PKey<Private>,
    cert: X509,
}

fn identity(cn: &str, serial: u32) -> Identity {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_text("CN", cn).unwrap();
    let name = name.build();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(&BigNum::from_u32(serial).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(30).unwrap())
        .unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    Identity {
        key,
        cert: b.build(),
    }
}

/// A secret bundle holding `cert` next to `key`, which need not match it.
fn bundle(cert: &X509, key: &PKey<Private>) -> Vec<u8> {
    let p8 = key.private_key_to_pkcs8().unwrap();
    serde_json::to_vec(&json!({"v": 1, "entries": [{
        "alg": ALG_RSA_OAEP,
        "purpose": "encryption",
        "cert_pem": String::from_utf8(cert.to_pem().unwrap()).unwrap(),
        "spki_b64": "",
        "pkcs8_b64": base64::engine::general_purpose::STANDARD.encode(p8),
    }]}))
    .unwrap()
}

/// PKCS#1 v1.5 key transport, OpenSSL's default.
fn encrypt(to: &[&Identity], cipher: Cipher) -> Vec<u8> {
    let mut certs = Stack::new().unwrap();
    for who in to {
        certs.push(who.cert.clone()).unwrap();
    }
    CmsContentInfo::encrypt(&certs, MSG, cipher, CMSOptions::BINARY)
        .unwrap()
        .to_der()
        .unwrap()
}

fn decrypt(cms: &[u8], key: &[u8]) -> Result<DecryptResult> {
    CmsSmime::new().decrypt(cms, key, None)
}

#[test]
fn each_recipient_of_a_shared_message_opens_it() {
    let (a, b) = (identity("a", 1), identity("b", 2));
    for (cipher, format) in [
        (Cipher::aes_256_gcm(), FORMAT_F1),
        (Cipher::aes_128_cbc(), FORMAT_F0_STD),
    ] {
        let cms = encrypt(&[&a, &b], cipher);
        for who in [&a, &b] {
            let out = decrypt(&cms, &bundle(&who.cert, &who.key)).unwrap();
            assert_eq!(out.plaintext, MSG);
            assert_eq!(out.format, format);
        }
    }
}

#[test]
fn a_key_not_named_by_any_recipient_is_wrong_private_key() {
    let (a, outsider) = (identity("a", 1), identity("outsider", 9));
    for cipher in [Cipher::aes_256_gcm(), Cipher::aes_256_cbc()] {
        let cms = encrypt(&[&a], cipher);
        let err = decrypt(&cms, &bundle(&outsider.cert, &outsider.key)).unwrap_err();
        assert!(matches!(err, SmimeError::WrongPrivateKey), "{err:?}");
    }
}

/// The certificate names a recipient but the key does not open it. OpenSSL
/// goes on with a random CEK, so the failure shows only at the content.
#[test]
fn a_matching_certificate_with_the_wrong_key_releases_nothing() {
    let (a, other) = (identity("a", 1), identity("other", 2));
    let cms = encrypt(&[&a], Cipher::aes_256_gcm());
    let err = decrypt(&cms, &bundle(&a.cert, &other.key)).unwrap_err();
    assert!(matches!(err, SmimeError::DecryptionFailed), "{err:?}");
}

/// The engine's own RSA output: F1 (standard KTRI) once the Release 2 switch
/// is on; before, OAEP-SHA256 under absent parameters, read by the legacy
/// reader. Frozen legacy RSA mail is covered by `frozen_corpus.rs`.
#[test]
fn engine_rsa_output_reads_with_its_format() {
    let a = identity("a", 1);
    let public = serde_json::to_vec(&json!({"v": 1, "entries": [{
        "alg": ALG_RSA_OAEP,
        "purpose": "encryption",
        "cert_pem": String::from_utf8(a.cert.to_pem().unwrap()).unwrap(),
        "spki_b64": "",
    }]}))
    .unwrap();
    let engine = CmsSmime::new();
    let cms = engine
        .encrypt(MSG, &[&public], &EncryptOptions { armored: false })
        .unwrap();
    let out = decrypt(&cms, &bundle(&a.cert, &a.key)).unwrap();
    assert_eq!(out.plaintext, MSG);
    let want = if scomm_smime_cms::RELEASE_2_WRITERS {
        FORMAT_F1
    } else {
        FORMAT_F0_SCOMM
    };
    assert_eq!(out.format, want);
}
