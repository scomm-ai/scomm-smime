use base64::Engine;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::x509::{X509Req, X509};

use super::*;
use crate::import::import;

fn request(name: Option<&str>, sign: bool, encrypt: bool) -> CsrRequest {
    CsrRequest {
        email: "alice@example.com".into(),
        name: name.map(Into::into),
        key_bits: 2048,
        sign,
        encrypt,
    }
}

fn subject(req: &X509Req, nid: Nid) -> Vec<String> {
    req.subject_name()
        .entries_by_nid(nid)
        .map(|e| e.data().to_string().unwrap())
        .collect()
}

/// What a CA does with the request: copies its key and requested
/// extensions into a certificate it signs with its own key.
fn issue(csr: &X509Req) -> X509 {
    let ca_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(&BigNum::from_u32(9).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    b.set_subject_name(csr.subject_name()).unwrap();
    b.set_issuer_name(csr.subject_name()).unwrap();
    b.set_pubkey(&csr.public_key().unwrap()).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    b.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap();
    for ext in csr.extensions().unwrap() {
        b.append_extension(ext).unwrap();
    }
    b.sign(&ca_key, MessageDigest::sha256()).unwrap();
    b.build()
}

#[test]
fn mailbox_validated_request() {
    let out = create_csr(&request(None, true, true)).unwrap();
    assert!(out.csr_pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
    assert!(!out.csr_pem.contains("PRIVATE"));
    let csr = X509Req::from_pem(out.csr_pem.as_bytes()).unwrap();
    assert!(csr.verify(&csr.public_key().unwrap()).unwrap());
    assert_eq!(subject(&csr, Nid::COMMONNAME), ["alice@example.com"]);
    assert_eq!(subject(&csr, Nid::PKCS9_EMAILADDRESS), ["alice@example.com"]);
    assert!(subject(&csr, Nid::ORGANIZATIONNAME).is_empty());
    let spki = csr.public_key().unwrap().public_key_to_der().unwrap();
    assert_eq!(out.spki_b64, b64_encode(&spki));
    assert_eq!(out.spki_sha256, crate::cert::fingerprint_of(&spki));
    assert_eq!(csr.public_key().unwrap().rsa().unwrap().size(), 256);

    let cert = issue(&csr);
    let sans: Vec<String> = cert
        .subject_alt_names()
        .unwrap()
        .iter()
        .filter_map(|n| n.email().map(str::to_string))
        .collect();
    assert_eq!(sans, ["alice@example.com"]);
    let text = String::from_utf8(cert.to_text().unwrap()).unwrap();
    assert!(text.contains("Digital Signature, Key Encipherment"), "{text}");
    assert!(text.contains("E-mail Protection"), "{text}");
}

#[test]
fn individual_validated_request_names_the_person() {
    let out = create_csr(&request(Some("  Alice Example "), true, false)).unwrap();
    let csr = X509Req::from_pem(out.csr_pem.as_bytes()).unwrap();
    assert_eq!(subject(&csr, Nid::COMMONNAME), ["Alice Example"]);
    assert_eq!(subject(&csr, Nid::PKCS9_EMAILADDRESS), ["alice@example.com"]);
    let text = String::from_utf8(issue(&csr).to_text().unwrap()).unwrap();
    assert!(text.contains("Digital Signature"), "{text}");
    assert!(!text.contains("Key Encipherment"), "{text}");
}

#[test]
fn issued_certificate_matches_the_stored_key_on_import() {
    let out = create_csr(&request(None, false, true)).unwrap();
    let csr = X509Req::from_pem(out.csr_pem.as_bytes()).unwrap();
    let cert = issue(&csr);
    let key = base64::engine::general_purpose::STANDARD
        .decode(&out.pkcs8_b64)
        .unwrap();

    let matched = import(&[cert.to_pem().unwrap(), key], "").unwrap();
    assert_eq!(matched.unmatched_keys, 0);
    assert_eq!(matched.certificates[0].pkcs8_b64.as_deref(), Some(out.pkcs8_b64.as_str()));
    assert_eq!(matched.certificates[0].spki_b64, out.spki_b64);

    // Another request's key does not complete this certificate.
    let other = create_csr(&request(None, false, true)).unwrap();
    let other_key = base64::engine::general_purpose::STANDARD
        .decode(&other.pkcs8_b64)
        .unwrap();
    let unmatched = import(&[cert.to_pem().unwrap(), other_key], "").unwrap();
    assert_eq!(unmatched.unmatched_keys, 1);
    assert!(unmatched.certificates[0].pkcs8_b64.is_none());
}

#[test]
fn every_request_has_a_new_key() {
    let a = create_csr(&request(None, true, true)).unwrap();
    let b = create_csr(&request(None, true, true)).unwrap();
    assert_ne!(a.spki_b64, b.spki_b64);
}

#[test]
fn rsa_3072() {
    let mut req = request(None, true, true);
    req.key_bits = 3072;
    let csr = X509Req::from_pem(create_csr(&req).unwrap().csr_pem.as_bytes()).unwrap();
    assert_eq!(csr.public_key().unwrap().rsa().unwrap().size(), 384);
}

#[test]
fn bad_requests_are_refused() {
    let bits = |b| CsrRequest { key_bits: b, ..request(None, true, true) };
    assert!(matches!(create_csr(&bits(1024)), Err(SmimeError::UnsupportedAlgorithm(_))));
    assert!(matches!(create_csr(&bits(4096)), Err(SmimeError::UnsupportedAlgorithm(_))));
    assert!(matches!(create_csr(&request(None, false, false)), Err(SmimeError::InvalidArgument(_))));
    for email in ["", "alice", "a@b", "a b@example.com", "a@@example.com", "@example.com", "ä@example.com"] {
        let req = CsrRequest { email: email.into(), ..request(None, true, true) };
        assert!(matches!(create_csr(&req), Err(SmimeError::InvalidArgument(_))), "{email}");
    }
    let long = "x".repeat(65);
    assert!(matches!(create_csr(&request(Some(&long), true, true)), Err(SmimeError::InvalidArgument(_))));
    assert!(matches!(create_csr(&request(Some("a\nb"), true, true)), Err(SmimeError::InvalidArgument(_))));
}
