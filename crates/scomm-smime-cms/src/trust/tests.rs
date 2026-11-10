//! Path B (task 3.3): roots passed at startup, S/MIME sign and encrypt
//! purposes, validity window and e-mail match, through a test CA.

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
};
use openssl::x509::{X509Name, X509};

use super::*;
use crate::bundle::{b64_encode, KeyEntry};
use crate::cms_envelop::verify_detached;
use crate::signed::{sign, SignAlg};

struct Issued {
    cert: X509,
    key: PKey<Private>,
}

enum Leaf {
    Sign,
    Encrypt,
    ServerOnly,
}

fn key() -> PKey<Private> {
    PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap()
}

fn name(cn: &str) -> openssl::x509::X509Name {
    let mut n = X509Name::builder().unwrap();
    n.append_entry_by_text("CN", cn).unwrap();
    n.build()
}

/// A certificate for `cn`, signed by `issuer` (self-signed when `None`).
/// `days` is the validity window relative to now.
fn issue(
    cn: &str,
    issuer: Option<&Issued>,
    ca: bool,
    leaf: Option<Leaf>,
    days: (i64, i64),
) -> Issued {
    let key = key();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    let mut serial = BigNum::new().unwrap();
    serial.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();
    b.set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();
    b.set_subject_name(&name(cn)).unwrap();
    b.set_issuer_name(issuer.map_or(&name(cn), |i| i.cert.subject_name()))
        .unwrap();
    b.set_pubkey(&key).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    b.set_not_before(&Asn1Time::from_unix(now + days.0 * 86_400).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::from_unix(now + days.1 * 86_400).unwrap())
        .unwrap();
    if ca {
        b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        b.append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .unwrap(),
        )
        .unwrap();
    }
    if let Some(kind) = leaf {
        let san = SubjectAlternativeName::new()
            .email(cn)
            .build(&b.x509v3_context(issuer.map(|i| i.cert.as_ref()), None))
            .unwrap();
        b.append_extension(san).unwrap();
        let (ku, eku) = match kind {
            Leaf::Sign => (
                KeyUsage::new().critical().digital_signature().build(),
                ExtendedKeyUsage::new().email_protection().build(),
            ),
            Leaf::Encrypt => (
                KeyUsage::new().critical().key_encipherment().build(),
                ExtendedKeyUsage::new().email_protection().build(),
            ),
            Leaf::ServerOnly => (
                KeyUsage::new().critical().digital_signature().build(),
                ExtendedKeyUsage::new().server_auth().build(),
            ),
        };
        b.append_extension(ku.unwrap()).unwrap();
        b.append_extension(eku.unwrap()).unwrap();
    }
    b.sign(issuer.map_or(&key, |i| &i.key), MessageDigest::sha256())
        .unwrap();
    Issued {
        cert: b.build(),
        key,
    }
}

fn entry(leaf: &Issued) -> KeyEntry {
    KeyEntry {
        alg: ALG_RSA_PKCS1.into(),
        purpose: "signing".into(),
        cert_pem: String::from_utf8(leaf.cert.to_pem().unwrap()).unwrap(),
        spki_b64: String::new(),
        pkcs8_b64: Some(b64_encode(&leaf.key.private_key_to_pkcs8().unwrap())),
        legacy_key_ids: Vec::new(),
    }
}

fn pem(certs: &[&X509]) -> Vec<u8> {
    certs.iter().flat_map(|c| c.to_pem().unwrap()).collect()
}

const DATA: &[u8] = b"path b";

fn chain_of(leaf: &Issued, sender: &str) -> (ChainStatus, Option<bool>) {
    let sig = sign(DATA, &entry(leaf), SignAlg::RsaPkcs1).unwrap();
    let v = verify_detached(DATA, &sig, None, Some(sender)).unwrap();
    assert_eq!(v.validity, SignatureValidity::CryptographicallyValid);
    (v.chain, v.email_match)
}

/// One test, because the roots are process-wide state.
#[test]
fn path_b_judges_chain_purpose_validity_and_e_mail() {
    let root = issue("Test Root", None, true, None, (-10, 3650));
    let inter = issue("Test Intermediate", Some(&root), true, None, (-10, 3650));
    let good = issue(
        "bob@example.com",
        Some(&root),
        false,
        Some(Leaf::Sign),
        (-1, 365),
    );
    let expired = issue(
        "old@example.com",
        Some(&root),
        false,
        Some(Leaf::Sign),
        (-400, -1),
    );
    let future = issue(
        "new@example.com",
        Some(&root),
        false,
        Some(Leaf::Sign),
        (10, 365),
    );
    let server = issue(
        "web@example.com",
        Some(&root),
        false,
        Some(Leaf::ServerOnly),
        (-1, 365),
    );
    let enc = issue(
        "bob@example.com",
        Some(&root),
        false,
        Some(Leaf::Encrypt),
        (-1, 365),
    );
    let via_inter = issue(
        "carol@example.com",
        Some(&inter),
        false,
        Some(Leaf::Sign),
        (-1, 365),
    );
    let stranger_root = issue("Other Root", None, true, None, (-10, 3650));
    let stranger = issue(
        "eve@example.com",
        Some(&stranger_root),
        false,
        Some(Leaf::Sign),
        (-1, 365),
    );

    // Nothing loaded: nothing chains, but the window is still judged.
    clear_trust_roots();
    assert_eq!(
        chain_of(&good, "bob@example.com"),
        (ChainStatus::UntrustedRoot, Some(true))
    );
    assert_eq!(
        chain_of(&expired, "old@example.com").0,
        ChainStatus::Expired
    );

    assert_eq!(set_trust_roots(&pem(&[&root.cert])).unwrap(), 1);
    assert_eq!(
        chain_of(&good, "bob@example.com"),
        (ChainStatus::TrustedRoot, Some(true))
    );
    assert_eq!(
        chain_of(&good, "mallory@example.com"),
        (ChainStatus::TrustedRoot, Some(false))
    );
    assert_eq!(
        chain_of(&expired, "old@example.com").0,
        ChainStatus::Expired
    );
    assert_eq!(
        chain_of(&future, "new@example.com").0,
        ChainStatus::NotYetValid
    );
    assert_eq!(
        chain_of(&server, "web@example.com").0,
        ChainStatus::WrongPurpose
    );
    assert_eq!(
        chain_of(&stranger, "eve@example.com").0,
        ChainStatus::UntrustedRoot
    );
    // The signer certificate alone does not reach the root through an
    // intermediate the message does not carry.
    assert_eq!(
        chain_of(&via_inter, "carol@example.com").0,
        ChainStatus::UntrustedRoot
    );

    // Certificates the app holds: the chain may come with the PEM.
    let check =
        |certs: &[&X509], email, purpose| check_certificate(&pem(certs), email, purpose).unwrap();
    assert_eq!(
        check(
            &[&via_inter.cert, &inter.cert],
            Some("carol@example.com"),
            CertPurpose::SmimeSign
        ),
        CertCheck {
            chain: ChainStatus::TrustedRoot,
            email_match: Some(true)
        }
    );
    assert_eq!(
        check(
            &[&enc.cert],
            Some("bob@example.com"),
            CertPurpose::SmimeEncrypt
        )
        .chain,
        ChainStatus::TrustedRoot
    );
    assert_eq!(
        check(&[&good.cert], None, CertPurpose::SmimeEncrypt),
        CertCheck {
            chain: ChainStatus::WrongPurpose,
            email_match: None
        }
    );
    assert_eq!(
        check(&[&enc.cert], None, CertPurpose::SmimeSign).chain,
        ChainStatus::WrongPurpose
    );

    // Bad input is refused and leaves the loaded roots alone.
    assert!(matches!(
        set_trust_roots(b"-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n"),
        Err(SmimeError::InvalidArgument(_))
    ));
    assert_eq!(
        chain_of(&good, "bob@example.com").0,
        ChainStatus::TrustedRoot
    );
    // Empty input clears them.
    assert_eq!(set_trust_roots(b"").unwrap(), 0);
    assert_eq!(
        chain_of(&good, "bob@example.com").0,
        ChainStatus::UntrustedRoot
    );
    clear_trust_roots();
}
