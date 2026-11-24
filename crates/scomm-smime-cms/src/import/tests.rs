use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkcs12::Pkcs12;
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::symm::Cipher;
use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectAlternativeName};
use openssl::x509::{X509Name, X509};

use super::*;

fn rsa() -> PKey<Private> {
    PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap()
}

fn cert(subject: &str, key: &PKey<Private>, issuer: Option<(&X509, &PKey<Private>)>, ca: bool) -> X509 {
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_text("CN", subject).unwrap();
    let name = name.build();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(&BigNum::from_u32(7).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(issuer.map_or(&name, |(c, _)| c.subject_name()))
        .unwrap();
    b.set_pubkey(key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    b.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap();
    if ca {
        b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
    } else {
        b.append_extension(
            KeyUsage::new()
                .digital_signature()
                .key_encipherment()
                .build()
                .unwrap(),
        )
        .unwrap();
        let san = SubjectAlternativeName::new()
            .email(&format!("{subject}@example.com"))
            .build(&b.x509v3_context(issuer.map(|(c, _)| c.as_ref()), None))
            .unwrap();
        b.append_extension(san).unwrap();
    }
    b.sign(issuer.map_or(key, |(_, k)| k), MessageDigest::sha256())
        .unwrap();
    b.build()
}

struct Fixture {
    ca: X509,
    leaf: X509,
    key: PKey<Private>,
}

fn fixture() -> Fixture {
    let ca_key = rsa();
    let ca = cert("Root", &ca_key, None, true);
    let key = rsa();
    let leaf = cert("alice", &key, Some((&ca, &ca_key)), false);
    Fixture { ca, leaf, key }
}

fn p12(f: &Fixture, password: &str) -> Vec<u8> {
    let mut chain = Stack::new().unwrap();
    chain.push(f.ca.clone()).unwrap();
    Pkcs12::builder()
        .name("alice")
        .pkey(&f.key)
        .cert(&f.leaf)
        .ca(chain)
        .build2(password)
        .unwrap()
        .to_der()
        .unwrap()
}

fn p7(f: &Fixture) -> Pkcs7 {
    let mut certs = Stack::new().unwrap();
    certs.push(f.ca.clone()).unwrap();
    Pkcs7::sign(&f.leaf, &f.key, &certs, b"x", Pkcs7Flags::DETACHED).unwrap()
}

fn one_line(pem: &[u8]) -> Vec<u8> {
    String::from_utf8(pem.to_vec())
        .unwrap()
        .replace('\n', "")
        .replace("-----BEGIN PKCS7-----", "-----BEGIN PKCS7----- ")
        .into_bytes()
}

fn pem_of(c: &X509) -> String {
    String::from_utf8(c.to_pem().unwrap()).unwrap()
}

#[test]
fn pkcs12_gives_identity_and_untrusted_ca() {
    let f = fixture();
    let r = import(&[p12(&f, "secret")], "secret").unwrap();
    assert_eq!(r.certificates.len(), 2);
    assert_eq!(r.unmatched_keys, 0);
    let leaf = &r.certificates[0];
    assert_eq!(leaf.cert_pem, pem_of(&f.leaf));
    assert!(leaf.pkcs8_b64.is_some());
    assert!(!leaf.is_ca);
    assert_eq!(leaf.key_algorithm, "rsa");
    assert!(r.certificates[1].is_ca);
    assert!(r.certificates[1].pkcs8_b64.is_none());
    // The key is returned as PKCS#8 the engine reads.
    let der = crate::bundle::b64_decode(leaf.pkcs8_b64.as_ref().unwrap()).unwrap();
    assert!(PKey::private_key_from_pkcs8(&der).unwrap().public_eq(&f.key));
}

#[test]
fn pkcs12_password_errors() {
    let f = fixture();
    let file = p12(&f, "secret");
    assert!(matches!(import(&[file.clone()], ""), Err(SmimeError::PasswordRequired)));
    assert!(matches!(import(&[file], "nope"), Err(SmimeError::WrongPassword)));
}

#[test]
fn pkcs12_with_empty_password_opens() {
    let f = fixture();
    let r = import(&[p12(&f, "")], "").unwrap();
    assert!(r.certificates[0].pkcs8_b64.is_some());
}

#[test]
fn pkcs7_pem_der_and_single_line() {
    let f = fixture();
    let p7 = p7(&f);
    let pem = p7.to_pem().unwrap();
    for file in [pem.clone(), p7.to_der().unwrap(), one_line(&pem), pem.replace_newlines_crlf()] {
        let r = import(&[file], "").unwrap();
        assert_eq!(r.certificates.len(), 2, "both certificates");
        assert!(r.certificates.iter().all(|c| c.pkcs8_b64.is_none()));
    }
}

trait Crlf {
    fn replace_newlines_crlf(&self) -> Vec<u8>;
}

impl Crlf for Vec<u8> {
    fn replace_newlines_crlf(&self) -> Vec<u8> {
        String::from_utf8(self.clone())
            .unwrap()
            .replace('\n', "\r\n")
            .into_bytes()
    }
}

#[test]
fn der_certificate_and_unarmored_base64() {
    let f = fixture();
    let der = f.leaf.to_der().unwrap();
    let b64 = crate::bundle::b64_encode(&der).into_bytes();
    for file in [der, b64] {
        let r = import(&[file], "").unwrap();
        assert_eq!(r.certificates.len(), 1);
        assert!(!r.certificates[0].is_ca);
    }
}

#[test]
fn separate_certificate_and_key_files_including_encrypted() {
    let f = fixture();
    let cert = f.leaf.to_pem().unwrap();
    let keys: Vec<(Vec<u8>, &str)> = vec![
        (f.key.private_key_to_pem_pkcs8().unwrap(), ""),
        (f.key.rsa().unwrap().private_key_to_pem().unwrap(), ""),
        (f.key.private_key_to_der().unwrap(), ""),
        (
            f.key
                .private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), b"pw")
                .unwrap(),
            "pw",
        ),
        (
            f.key
                .rsa()
                .unwrap()
                .private_key_to_pem_passphrase(Cipher::aes_128_cbc(), b"pw")
                .unwrap(),
            "pw",
        ),
    ];
    for (key, pw) in keys {
        let r = import(&[cert.clone(), key], pw).unwrap();
        assert_eq!(r.certificates.len(), 1);
        assert!(r.certificates[0].pkcs8_b64.is_some());
        assert_eq!(r.unmatched_keys, 0);
    }
}

#[test]
fn encrypted_keys_need_the_right_password() {
    let f = fixture();
    let cert = f.leaf.to_pem().unwrap();
    let pkcs8 = f
        .key
        .private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), b"pw")
        .unwrap();
    let legacy = f
        .key
        .rsa()
        .unwrap()
        .private_key_to_pem_passphrase(Cipher::aes_128_cbc(), b"pw")
        .unwrap();
    for key in [pkcs8, legacy] {
        assert!(matches!(
            import(&[cert.clone(), key.clone()], ""),
            Err(SmimeError::PasswordRequired)
        ));
        assert!(matches!(
            import(&[cert.clone(), key], "bad"),
            Err(SmimeError::WrongPassword)
        ));
    }
}

#[test]
fn mismatched_key_is_reported_not_attached() {
    let f = fixture();
    let other = rsa();
    let r = import(
        &[f.leaf.to_pem().unwrap(), other.private_key_to_pem_pkcs8().unwrap()],
        "",
    )
    .unwrap();
    assert!(r.certificates[0].pkcs8_b64.is_none());
    assert_eq!(r.unmatched_keys, 1);
}

#[test]
fn duplicates_are_collapsed() {
    let f = fixture();
    let pem = f.leaf.to_pem().unwrap();
    let r = import(&[pem.clone(), pem, f.leaf.to_der().unwrap()], "").unwrap();
    assert_eq!(r.certificates.len(), 1);
}

#[test]
fn malformed_input_is_refused_not_repaired() {
    let f = fixture();
    let pem = String::from_utf8(f.leaf.to_pem().unwrap()).unwrap();
    // One Base64 character of the DER length changed: still Base64, no
    // longer a certificate, and not fixed up.
    let corrupt = pem.replacen("MII", "MIJ", 1).into_bytes();
    let bad_base64 = pem.replacen("MII", "MI*I", 1).into_bytes();
    let truncated = pem[..pem.len() - 30].as_bytes().to_vec();
    for file in [corrupt, bad_base64, truncated] {
        assert!(
            matches!(import(&[file], ""), Err(SmimeError::InvalidKey(_))),
            "malformed"
        );
    }
    assert!(matches!(
        import(&[b"hello world, not a key".to_vec()], ""),
        Err(SmimeError::InvalidArgument(_)) | Err(SmimeError::InvalidKey(_))
    ));
}
