//! D5 through the C ABI: a tampered AuthEnvelopedData tag returns an error
//! and hands the caller no plaintext (`design.md` D5, Testing strategy).

use std::ptr;

use base64::Engine;
use openssl::asn1::Asn1Time;
use openssl::cms::{CMSOptions, CmsContentInfo};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::symm::Cipher;
use openssl::x509::{X509Name, X509};
use scomm_smime::{scomm_smime_buffer_free, scomm_smime_decrypt, scomm_smime_last_error};

const MSG: &[u8] = b"d5 plaintext that must never leave on a bad tag";
const DECRYPTION_FAILED: i32 = 9;

fn message_and_bundle() -> (Vec<u8>, Vec<u8>) {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_text("CN", "d5").unwrap();
    let name = name.build();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    let cert = b.build();

    let mut certs = Stack::new().unwrap();
    certs.push(cert.clone()).unwrap();
    let cms = CmsContentInfo::encrypt(&certs, MSG, Cipher::aes_256_gcm(), CMSOptions::BINARY)
        .unwrap()
        .to_der()
        .unwrap();
    let bundle = serde_json::to_vec(&serde_json::json!({"v": 1, "entries": [{
        "alg": scomm_smime_core::ALG_RSA_OAEP,
        "purpose": "encryption",
        "cert_pem": String::from_utf8(cert.to_pem().unwrap()).unwrap(),
        "spki_b64": "",
        "pkcs8_b64": base64::engine::general_purpose::STANDARD
            .encode(key.private_key_to_pkcs8().unwrap()),
    }]}))
    .unwrap();
    (cms, bundle)
}

/// Calls the C ABI with `out` preset to garbage, as a careless caller might.
fn decrypt(cms: &[u8], key: &[u8]) -> (i32, Option<Vec<u8>>, *mut u8, usize) {
    let mut out = ptr::NonNull::<u8>::dangling().as_ptr();
    let mut out_len = usize::MAX;
    let rc = unsafe {
        scomm_smime_decrypt(
            cms.as_ptr(),
            cms.len(),
            key.as_ptr(),
            key.len(),
            ptr::null(),
            0,
            &mut out,
            &mut out_len,
        )
    };
    let bytes = (rc == 0 && !out.is_null()).then(|| unsafe {
        let v = std::slice::from_raw_parts(out, out_len).to_vec();
        scomm_smime_buffer_free(out, out_len);
        v
    });
    (rc, bytes, out, out_len)
}

fn last_error() -> String {
    let mut out = ptr::null_mut();
    let mut len = 0usize;
    unsafe {
        scomm_smime_last_error(&mut out, &mut len);
        if out.is_null() {
            return String::new();
        }
        let s = String::from_utf8_lossy(std::slice::from_raw_parts(out, len)).into_owned();
        scomm_smime_buffer_free(out, len);
        s
    }
}

#[test]
fn a_tampered_tag_releases_no_plaintext() {
    let (cms, bundle) = message_and_bundle();

    let (rc, bytes, ..) = decrypt(&cms, &bundle);
    assert_eq!((rc, bytes.as_deref()), (0, Some(MSG)), "untampered control");

    // AuthEnvelopedData ends with the 16-byte GCM tag (no unauthAttrs).
    let mut tampered = cms.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let (rc, bytes, out, out_len) = decrypt(&tampered, &bundle);
    assert_eq!(rc, DECRYPTION_FAILED);
    assert!(bytes.is_none());
    assert!(out.is_null(), "out must be cleared on failure");
    assert_eq!(out_len, 0);
    assert_eq!(last_error(), "decryption failed");
}
