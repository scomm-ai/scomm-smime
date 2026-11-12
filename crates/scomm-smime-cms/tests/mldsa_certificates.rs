//! Task 3.4 (Q5): existing ML-DSA signing keys gain a self-signed
//! certificate; the old key ID stays as an alias, and nothing else changes.

use std::fs;
use std::path::PathBuf;

use openssl::asn1::Asn1Time;
use openssl::nid::Nid;
use openssl::x509::X509;
use scomm_smime_cms::{add_mldsa_certificates, CmsSmime};
use scomm_smime_core::*;
use serde_json::Value;

const MAILBOX: &str = "alice@example.com";
/// The frozen corpus signs this (see `frozen_corpus.rs`).
const PLAINTEXT: &[u8] = b"Content-Type: text/plain\r\n\r\nfrozen plaintext\r\n";

fn fixture(name: &str) -> Vec<u8> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/scomm");
    fs::read(dir.join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn entries(bundle: &[u8]) -> Vec<Value> {
    let v: Value = serde_json::from_slice(bundle).unwrap();
    v["entries"].as_array().unwrap().clone()
}

fn mldsa(entries: &[Value]) -> Value {
    entries
        .iter()
        .find(|e| e["alg"] == ALG_MLDSA65)
        .cloned()
        .unwrap()
}

fn sha256_upper_hex(bytes: &[u8]) -> String {
    openssl::hash::hash(openssl::hash::MessageDigest::sha256(), bytes)
        .unwrap()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect()
}

fn public_of(secret: &[u8]) -> Vec<u8> {
    CmsSmime::new().export_public_key(secret).unwrap()
}

fn check_profile(cert_pem: &str) {
    let cert = X509::from_pem(cert_pem.as_bytes()).unwrap();
    assert!(
        cert.verify(&cert.public_key().unwrap()).unwrap(),
        "self-signature"
    );
    let cn = cert
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .unwrap();
    assert_eq!(cn.data().to_string().unwrap(), MAILBOX);
    assert_eq!(
        cert.issuer_name().to_der().unwrap(),
        cert.subject_name().to_der().unwrap()
    );
    let san: Vec<String> = cert
        .subject_alt_names()
        .unwrap()
        .iter()
        .filter_map(|n| n.email().map(str::to_string))
        .collect();
    assert_eq!(san, [MAILBOX]);
    assert_eq!(
        cert.not_before(),
        &*Asn1Time::from_str("20240101000000Z").unwrap()
    );
    assert_eq!(
        cert.not_after(),
        &*Asn1Time::from_str("20340101000000Z").unwrap()
    );
    let serial = cert.serial_number().to_bn().unwrap();
    assert_eq!(serial.num_bytes(), 16);
    let text = String::from_utf8(cert.to_text().unwrap()).unwrap();
    assert!(text.contains("X509v3 Key Usage: critical"), "{text}");
    assert!(text.contains("Digital Signature"), "{text}");
    assert!(text.contains("ML-DSA-65"), "{text}");
}

fn migrate_and_check(secret: &[u8]) -> Vec<u8> {
    let before = entries(secret);
    let updated = add_mldsa_certificates(secret, MAILBOX)
        .unwrap()
        .expect("an ML-DSA entry without a certificate gets one");
    let after = entries(&updated);
    assert_eq!(before.len(), after.len());
    let (old, new) = (mldsa(&before), mldsa(&after));
    // Seed and public key are unchanged; only the certificate and alias are new.
    assert_eq!(old["spki_b64"], new["spki_b64"]);
    assert_eq!(old["pkcs8_b64"], new["pkcs8_b64"]);
    let old_id = sha256_upper_hex(old["spki_b64"].as_str().unwrap().as_bytes());
    assert_eq!(new["legacy_key_ids"], serde_json::json!([old_id]));
    check_profile(new["cert_pem"].as_str().unwrap());
    for (b, a) in before.iter().zip(&after) {
        if b["alg"] != ALG_MLDSA65 {
            assert_eq!(b, a, "other entries are left alone");
        }
    }
    // Idempotent: a second run finds nothing to do.
    assert!(add_mldsa_certificates(&updated, MAILBOX).unwrap().is_none());
    // The public bundle carries the certificate and the alias, never the seed.
    let public = mldsa(&entries(&public_of(&updated)));
    assert_eq!(public["cert_pem"], new["cert_pem"]);
    assert_eq!(public["legacy_key_ids"], new["legacy_key_ids"]);
    assert!(public.get("pkcs8_b64").is_none());
    updated
}

fn new_pqc_key(userid: &str) -> Vec<u8> {
    CmsSmime::new()
        .generate_key(&GenerateKeyOptions {
            userid: userid.to_string(),
            profile: KeyProfile::PqcCms,
            ..Default::default()
        })
        .unwrap()
        .secret
}

/// Task 5.9: a new key carries its certificate from the start, so it has
/// no old key ID and the migration has nothing to do.
#[test]
fn a_new_pqc_key_is_born_with_a_certificate() {
    let secret = new_pqc_key(&format!("Alice <{MAILBOX}>"));
    let entry = mldsa(&entries(&secret));
    check_profile(entry["cert_pem"].as_str().unwrap());
    assert!(entry.get("legacy_key_ids").map_or(true, |v| v == &serde_json::json!([])));
    assert!(add_mldsa_certificates(&secret, MAILBOX).unwrap().is_none());
    let public = mldsa(&entries(&public_of(&secret)));
    assert_eq!(public["cert_pem"], entry["cert_pem"]);
}

/// Without an address the key is made bare, and the unlock migration
/// certifies it once the mailbox is known.
#[test]
fn a_new_pqc_key_without_an_address_gains_a_certificate_once() {
    let secret = new_pqc_key("Alice");
    assert_eq!(mldsa(&entries(&secret))["cert_pem"], "");
    migrate_and_check(&secret);
}

/// The frozen key from an older build: its old S0 signature still verifies
/// after the migration, under the same fingerprint.
#[test]
fn the_frozen_pqc_key_migrates_and_old_signatures_still_verify() {
    let secret = fixture("pqc.sec.json");
    let old_sig = fixture("mldsa65.sig");
    let before = CmsSmime::new()
        .verify_detached(PLAINTEXT, &old_sig, Some(&fixture("pqc.pub.json")), None)
        .unwrap();
    assert_eq!(before.validity, SignatureValidity::CryptographicallyValid);

    let updated = migrate_and_check(&secret);
    let after = CmsSmime::new()
        .verify_detached(PLAINTEXT, &old_sig, Some(&public_of(&updated)), None)
        .unwrap();
    assert_eq!(after.validity, SignatureValidity::CryptographicallyValid);
    assert_eq!(after.signer_fingerprint, before.signer_fingerprint);
}

#[test]
fn nothing_to_do_or_bad_input_writes_nothing() {
    // A public bundle has no seed, so it cannot get a certificate.
    assert!(add_mldsa_certificates(&fixture("pqc.pub.json"), MAILBOX)
        .unwrap()
        .is_none());
    // A classical bundle has no ML-DSA entry.
    assert!(
        add_mldsa_certificates(&fixture("classical.sec.json"), MAILBOX)
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        add_mldsa_certificates(&fixture("pqc.sec.json"), "not an address"),
        Err(SmimeError::InvalidArgument(_))
    ));
}
