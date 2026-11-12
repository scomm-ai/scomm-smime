//! cert_info (task 3.5): the fields the Dart `X509CertInfo` exposed, read by
//! OpenSSL, for Scomm's own certificates and an external CA-issued one.

use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::extension::{
    ExtendedKeyUsage, KeyUsage, SubjectAlternativeName, SubjectKeyIdentifier,
};
use openssl::x509::X509Name;

use super::*;
use crate::cert::{ed25519_sign_entry, rsa_sign_entry};

#[test]
fn scomm_ed25519_certificate() {
    let e = ed25519_sign_entry("Alice <alice@example.com>").unwrap();
    let i = cert_info(e.cert_pem.as_bytes()).unwrap();
    assert_eq!(i.version, 3);
    assert_eq!(i.public_key_algorithm, "ed25519");
    assert_eq!(i.key_bits, 256);
    assert_eq!(i.subject_dn, "CN=alice@example.com");
    assert_eq!(i.issuer_dn, i.subject_dn);
    assert!(i.is_self_signed);
    // Scomm's own certificates are valid 2024-01-01 to 2034-01-01.
    assert_eq!((i.not_before, i.not_after), (1_704_067_200, 2_019_686_400));
    assert_eq!(i.key_usages, ["Digital Signature"]);
    assert!(i.extended_key_usages.is_empty());
    assert_eq!(i.email_address.as_deref(), Some("alice@example.com"));
    assert_eq!(i.common_name.as_deref(), Some("alice@example.com"));
    // DER input gives the same answer; the pin fingerprint is the SPKI hash.
    let der = X509::from_pem(e.cert_pem.as_bytes())
        .unwrap()
        .to_der()
        .unwrap();
    assert_eq!(cert_info(&der).unwrap(), i);
    let spki = crate::bundle::b64_decode(&e.spki_b64).unwrap();
    let want: String = openssl::hash::hash(MessageDigest::sha256(), &spki)
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(i.spki_sha256_hex, want);
}

#[test]
fn scomm_rsa_certificate() {
    let e = rsa_sign_entry("bob@example.com").unwrap();
    let i = cert_info(e.cert_pem.as_bytes()).unwrap();
    assert_eq!(
        (i.public_key_algorithm.as_str(), i.key_bits),
        ("rsaEncryption", 2048)
    );
    assert_eq!(i.email_address.as_deref(), Some("bob@example.com"));
    assert_eq!(i.sha256_hex.len(), 64);
    assert_eq!(i.sha1_hex.len(), 40);
    assert!(i
        .sha256_hex
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase()));
}

/// An external certificate with the extensions the Dart parser read.
#[test]
fn external_certificate_with_every_field() {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509Name::builder().unwrap();
    for (k, v) in [("C", "DE"), ("O", "Example GmbH"), ("CN", "Carol Example")] {
        name.append_entry_by_text(k, v).unwrap();
    }
    name.append_entry_by_nid(Nid::PKCS9_EMAILADDRESS, "dn@example.com")
        .unwrap();
    let name = name.build();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(
        &BigNum::from_hex_str("0A1B2C")
            .unwrap()
            .to_asn1_integer()
            .unwrap(),
    )
    .unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::from_unix(1_700_000_000).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::from_unix(1_800_000_000).unwrap())
        .unwrap();
    b.append_extension(
        KeyUsage::new()
            .critical()
            .digital_signature()
            .non_repudiation()
            .key_encipherment()
            .build()
            .unwrap(),
    )
    .unwrap();
    b.append_extension(
        ExtendedKeyUsage::new()
            .email_protection()
            .client_auth()
            .other("1.2.3.4")
            .build()
            .unwrap(),
    )
    .unwrap();
    let ski = SubjectKeyIdentifier::new()
        .build(&b.x509v3_context(None, None))
        .unwrap();
    b.append_extension(ski).unwrap();
    let san = SubjectAlternativeName::new()
        .email("carol@example.com")
        .build(&b.x509v3_context(None, None))
        .unwrap();
    b.append_extension(san).unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    let cert = b.build();

    let i = cert_info(&cert.to_pem().unwrap()).unwrap();
    assert_eq!(i.serial_hex, "A1B2C");
    assert_eq!(
        i.subject_dn,
        "C=DE, O=Example GmbH, CN=Carol Example, emailAddress=dn@example.com"
    );
    assert_eq!((i.not_before, i.not_after), (1_700_000_000, 1_800_000_000));
    assert_eq!(
        i.key_usages,
        ["Digital Signature", "Non Repudiation", "Key Encipherment"]
    );
    assert_eq!(
        i.extended_key_usages,
        ["E-mail Protection", "TLS Client Authentication", "1.2.3.4"]
    );
    let ski = cert.subject_key_id().unwrap().as_slice().to_vec();
    assert_eq!(i.subject_key_identifier, Some(upper_hex(&ski)));
    // SAN wins over the DN e-mail, as in the Dart parser.
    assert_eq!(i.email_address.as_deref(), Some("carol@example.com"));
    assert_eq!(i.common_name.as_deref(), Some("Carol Example"));
}

#[test]
fn garbage_is_an_invalid_key() {
    for input in [
        &b""[..],
        b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        &[0x30, 0x03, 1, 2, 3],
    ] {
        assert!(matches!(cert_info(input), Err(SmimeError::InvalidKey(_))));
    }
}
