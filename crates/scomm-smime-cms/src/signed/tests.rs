//! S1 writer (task 3.1): every algorithm verifies under OpenSSL CMS, the
//! structure matches `design.md` "Signatures", and Release 1 routing holds.

use std::process::Command;

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::cms::CMSOptions;
use openssl::hash::MessageDigest;
use openssl::x509::X509Name;

use super::*;
use crate::cert::{ed25519_sign_entry, rsa_sign_entry};
use crate::classify::{classify, Kind};

const DATA: &[u8] = b"Content-Type: text/plain\r\n\r\nsigned body\r\n";

/// Self-signed certificate for a test ML-DSA entry (task 3.4 makes the real
/// ones); X509_sign takes no digest for ML-DSA.
fn mldsa_entry() -> KeyEntry {
    let mut e = pqc::mldsa_sign_entry(None).unwrap();
    let key = pqc::mldsa_pkey(&b64_decode(e.pkcs8_b64.as_ref().unwrap()).unwrap()).unwrap();
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_text("CN", "mldsa@example.com")
        .unwrap();
    let name = name.build();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    let mut serial = BigNum::new().unwrap();
    serial.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();
    b.set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    b.sign(&key, unsafe { MessageDigest::from_ptr(ptr::null()) })
        .unwrap();
    e.cert_pem = String::from_utf8(b.build().to_pem().unwrap()).unwrap();
    e
}

fn all() -> Vec<(SignAlg, KeyEntry)> {
    let rsa = rsa_sign_entry("rsa@example.com").unwrap();
    vec![
        (SignAlg::RsaPkcs1, rsa.clone()),
        (SignAlg::RsaPss, rsa),
        (
            SignAlg::Ed25519,
            ed25519_sign_entry("ed@example.com").unwrap(),
        ),
        (SignAlg::MlDsa65, mldsa_entry()),
    ]
}

/// "Signature math holds" with the embedded signer certificate and no chain.
fn math_holds(sig: &[u8], data: &[u8]) -> bool {
    let mut cms = CmsContentInfo::from_der(sig).unwrap();
    cms.verify(
        None,
        None,
        Some(data),
        None,
        CMSOptions::NO_SIGNER_CERT_VERIFY | CMSOptions::BINARY | CMSOptions::DETACHED,
    )
    .is_ok()
}

#[test]
fn every_algorithm_verifies_and_binds_the_data() {
    for (alg, entry) in all() {
        let sig = sign(DATA, &entry, alg).unwrap();
        assert!(
            matches!(classify(&sig).unwrap().kind, Kind::Signed),
            "{alg:?}"
        );
        assert!(math_holds(&sig, DATA), "{alg:?}");
        let mut other = DATA.to_vec();
        other[0] ^= 1;
        assert!(!math_holds(&sig, &other), "{alg:?} verified changed data");
    }
}

#[test]
fn a_key_that_does_not_match_the_certificate_is_refused() {
    let rsa = rsa_sign_entry("rsa@example.com").unwrap();
    let mut wrong = rsa_sign_entry("other@example.com").unwrap();
    wrong.cert_pem = rsa.cert_pem.clone();
    assert!(matches!(
        sign(DATA, &wrong, SignAlg::RsaPkcs1),
        Err(SmimeError::InvalidKey(_))
    ));
    let mut no_cert = rsa;
    no_cert.cert_pem.clear();
    assert_eq!(
        sign(DATA, &no_cert, SignAlg::RsaPkcs1).err(),
        Some(SmimeError::NoSuitableSigningKey)
    );
}

/// RSA PKCS#1 v1.5 is always S1; the others are S1 once the Release 2
/// switch is on and S0 before.
#[test]
fn signing_follows_the_release_switch() {
    use crate::bundle::KeyBundle;
    use crate::CmsSmime;
    for (alg, entry) in all() {
        let name = match alg {
            SignAlg::RsaPkcs1 => ALG_RSA_PKCS1,
            SignAlg::RsaPss => ALG_RSA_PSS,
            SignAlg::Ed25519 => ALG_ED25519,
            SignAlg::MlDsa65 => ALG_MLDSA65,
        };
        let bundle = KeyBundle {
            v: 1,
            entries: vec![entry],
        }
        .to_secret_json()
        .unwrap();
        let options = SignOptions {
            detached: true,
            algorithm: name,
        };
        let sig = CmsSmime::new().sign(DATA, &bundle, None, &options).unwrap();
        let s1 = matches!(classify(&sig).unwrap().kind, Kind::Signed);
        assert_eq!(s1, alg == SignAlg::RsaPkcs1 || crate::RELEASE_2_WRITERS, "{name}");
    }
}

/// Structure as `openssl cms -cmsout -print` reports it: one certificate,
/// exactly content type, message digest and signing time as signed
/// attributes, and the digest and signature algorithms from the design.
#[test]
fn structure_matches_the_design_per_openssl_cli() {
    let bin = std::env::var("SCOMM_OPENSSL_CLI").unwrap_or_else(|_| "openssl".into());
    let Ok(v) = Command::new(&bin).arg("version").output() else {
        println!("skipped: {bin} not usable here");
        return;
    };
    // ML-DSA in CMS needs 3.5 or later; CI runs the pinned 4.1.
    let version = String::from_utf8_lossy(&v.stdout).to_string();
    let new_enough = ["OpenSSL 3.5.", "OpenSSL 3.6.", "OpenSSL 4."]
        .iter()
        .any(|p| version.starts_with(p));
    if !new_enough {
        println!("skipped: needs OpenSSL 3.5 or later, have {version}");
        return;
    }
    let dir = std::env::temp_dir().join(format!("scomm-s1-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let data_path = dir.join("data.bin");
    std::fs::write(&data_path, DATA).unwrap();
    for (alg, entry) in all() {
        let sig_path = dir.join("sig.der");
        std::fs::write(&sig_path, sign(DATA, &entry, alg).unwrap()).unwrap();
        let printed = Command::new(&bin)
            .args(["cms", "-cmsout", "-print", "-inform", "DER", "-in"])
            .arg(&sig_path)
            .output()
            .unwrap();
        let printed = String::from_utf8_lossy(&printed.stdout).to_string();
        assert_eq!(
            printed.matches("cert_info:").count(),
            1,
            "{alg:?}\n{printed}"
        );
        for attr in ["contentType", "messageDigest", "signingTime"] {
            assert!(printed.contains(attr), "{alg:?} lacks {attr}\n{printed}");
        }
        assert!(!printed.contains("SMIMECapabilities"), "{alg:?}\n{printed}");
        let (digest, signature) = match alg {
            SignAlg::RsaPkcs1 => ("sha256", "rsaEncryption"),
            SignAlg::RsaPss => ("sha256", "rsassaPss"),
            SignAlg::Ed25519 => ("sha512", "ED25519"),
            SignAlg::MlDsa65 => ("sha512", "ML-DSA-65"),
        };
        assert!(printed.contains(digest), "{alg:?}\n{printed}");
        assert!(printed.contains(signature), "{alg:?}\n{printed}");
        if alg == SignAlg::RsaPss {
            assert!(printed.contains("mgf1"), "{printed}");
            // RSASSA-PSS-params [2] saltLength, printed as an ASN.1 dump.
            let salt = printed.split("cont [ 2 ]").nth(1).unwrap_or("");
            assert!(
                salt.lines()
                    .nth(1)
                    .unwrap_or("")
                    .ends_with("INTEGER           :20"),
                "{printed}"
            );
        }
        let verified = Command::new(&bin)
            .args([
                "cms",
                "-verify",
                "-binary",
                "-noverify",
                "-inform",
                "DER",
                "-in",
            ])
            .arg(&sig_path)
            .arg("-content")
            .arg(&data_path)
            .arg("-out")
            .arg(dir.join("out.bin"))
            .output()
            .unwrap();
        assert!(
            verified.status.success(),
            "{alg:?}: {}",
            String::from_utf8_lossy(&verified.stderr)
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// Task 3.2: S1 verifier and SignatureVerdict.

use crate::bundle::KeyBundle;
use crate::cms_envelop::verify_detached;

fn public_bundle(entry: &KeyEntry) -> KeyBundle {
    let mut e = entry.clone();
    e.pkcs8_b64 = None;
    KeyBundle {
        v: 1,
        entries: vec![e],
    }
}

fn fingerprint_of_cert(pem: &str) -> String {
    let key = X509::from_pem(pem.as_bytes())
        .unwrap()
        .public_key()
        .unwrap();
    crate::trust::spki_fingerprint(&key).unwrap()
}

#[test]
fn a_valid_s1_signature_reports_validity_apart_from_trust() {
    for (alg, entry) in all() {
        let sig = sign(DATA, &entry, alg).unwrap();
        let v = verify_detached(DATA, &sig, None, Some("someone@example.com")).unwrap();
        assert_eq!(
            v.validity,
            SignatureValidity::CryptographicallyValid,
            "{alg:?}"
        );
        assert_eq!(v.format, Some(SignatureFormat::S1));
        // Self-signed: valid but never chained to a bundled root.
        assert_eq!(v.chain, ChainStatus::UntrustedRoot, "{alg:?}");
        assert_eq!(v.email_match, Some(false), "{alg:?}");
        assert!(!v.weak_algorithm && !v.revocation_checked, "{alg:?}");
        assert_eq!(
            v.signer_fingerprint.as_deref(),
            Some(fingerprint_of_cert(&entry.cert_pem).as_str()),
            "{alg:?}"
        );
        assert!(v.signer_cert_pem.unwrap().contains("BEGIN CERTIFICATE"));

        let mut other = DATA.to_vec();
        other[5] ^= 1;
        let bad = verify_detached(&other, &sig, None, None).unwrap();
        assert_eq!(
            bad.validity,
            SignatureValidity::CryptographicallyInvalid,
            "{alg:?}"
        );
        assert_eq!(bad.signer_fingerprint, v.signer_fingerprint);
    }
}

#[test]
fn the_e_mail_match_uses_the_certificate_address() {
    let entry = ed25519_sign_entry("Alice <alice@example.com>").unwrap();
    let sig = sign(DATA, &entry, SignAlg::Ed25519).unwrap();
    let check = |sender| {
        verify_detached(DATA, &sig, None, sender)
            .unwrap()
            .email_match
    };
    assert_eq!(check(Some("alice@example.com")), Some(true));
    // OpenSSL compares the domain without case and the local part exactly
    // (RFC 5321 lets the local part be case-sensitive).
    assert_eq!(check(Some("alice@EXAMPLE.COM")), Some(true));
    assert_eq!(check(Some("ALICE@example.com")), Some(false));
    assert_eq!(check(Some("mallory@example.com")), Some(false));
    assert_eq!(check(None), None);
}

/// Without a certificate in the message the signer is unknown, unless the
/// app already holds the sender's certificate.
#[test]
fn a_signature_without_certificate_needs_a_known_key() {
    let entry = rsa_sign_entry("rsa@example.com").unwrap();
    let cert = X509::from_pem(entry.cert_pem.as_bytes()).unwrap();
    let key = rsa_from_pkcs8(entry.pkcs8_b64.as_ref().unwrap().as_bytes()).unwrap();
    let sig = CmsContentInfo::sign(
        Some(&cert),
        Some(&key),
        None,
        Some(DATA),
        CMSOptions::CMS_NOCERTS | CMSOptions::DETACHED | CMSOptions::BINARY,
    )
    .unwrap()
    .to_der()
    .unwrap();
    let unknown = verify_detached(DATA, &sig, None, None).unwrap();
    assert_eq!(unknown.validity, SignatureValidity::UnknownSigner);
    assert_eq!(unknown.chain, ChainStatus::NoChain);
    let known = verify_detached(DATA, &sig, Some(&public_bundle(&entry)), None).unwrap();
    assert_eq!(known.validity, SignatureValidity::CryptographicallyValid);
}

#[test]
fn more_than_one_signer_is_malformed() {
    let a = rsa_sign_entry("a@example.com").unwrap();
    let b = rsa_sign_entry("b@example.com").unwrap();
    let sig = unsafe {
        let flags = CMS_DETACHED | CMS_BINARY | CMS_NOSMIMECAP;
        let cms = CmsContentInfo::from_ptr(CMS_sign_ex(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            flags | CMS_PARTIAL,
            ptr::null_mut(),
            ptr::null(),
        ));
        for e in [&a, &b] {
            let cert = X509::from_pem(e.cert_pem.as_bytes()).unwrap();
            let key = rsa_from_pkcs8(e.pkcs8_b64.as_ref().unwrap().as_bytes()).unwrap();
            assert!(!CMS_add1_signer(
                cms.as_ptr(),
                cert.as_ptr(),
                key.as_ptr(),
                ffi::EVP_sha256(),
                flags
            )
            .is_null());
        }
        let input = ffi::BIO_new_mem_buf(DATA.as_ptr().cast(), DATA.len() as c_int);
        assert_eq!(CMS_final(cms.as_ptr(), input, ptr::null_mut(), flags), 1);
        BIO_free(input);
        cms.to_der().unwrap()
    };
    let v = verify_detached(DATA, &sig, None, None).unwrap();
    assert_eq!(v.validity, SignatureValidity::MalformedSignature);
    assert_eq!(v.format, Some(SignatureFormat::S1));
}

#[test]
fn sha1_digests_and_short_rsa_keys_are_weak() {
    let rsa = rsa_sign_entry("rsa@example.com").unwrap();
    let sha1 = sign_with_digest(DATA, &rsa, SignAlg::RsaPkcs1, unsafe { ffi::EVP_sha1() }).unwrap();
    let v = verify_detached(DATA, &sha1, None, None).unwrap();
    assert_eq!(v.validity, SignatureValidity::CryptographicallyValid);
    assert!(v.weak_algorithm);

    let pkcs8 = crate::cert::rsa_pkcs8(1024).unwrap();
    let short = KeyEntry {
        cert_pem: crate::cert::self_signed_rsa("short@example.com", &pkcs8, false, true).unwrap(),
        pkcs8_b64: Some(crate::bundle::b64_encode(&pkcs8)),
        ..rsa
    };
    let v = verify_detached(
        DATA,
        &sign(DATA, &short, SignAlg::RsaPkcs1).unwrap(),
        None,
        None,
    )
    .unwrap();
    assert!(v.weak_algorithm);
}

/// The same key gives the same fingerprint in S0 (Release 1 writers) and
/// S1 (Release 2 writers), so the upgrade does not look like a key change.
#[test]
fn s0_and_s1_report_the_same_fingerprint_for_one_key() {
    use crate::legacy_writer::{sign_ed25519, sign_mldsa, sign_pss};
    type Writer = fn(&[u8], &KeyEntry) -> Result<Vec<u8>>;
    let legacy: [(SignAlg, Writer); 3] = [
        (SignAlg::Ed25519, sign_ed25519),
        (SignAlg::MlDsa65, sign_mldsa),
        (SignAlg::RsaPss, sign_pss),
    ];
    let entries = all();
    for (alg, s0_writer) in legacy {
        let entry = &entries.iter().find(|(a, _)| *a == alg).unwrap().1;
        let public = public_bundle(entry);
        let s0 =
            verify_detached(DATA, &s0_writer(DATA, entry).unwrap(), Some(&public), None).unwrap();
        let s1 = verify_detached(DATA, &sign(DATA, entry, alg).unwrap(), None, None).unwrap();
        assert_eq!(
            s0.validity,
            SignatureValidity::CryptographicallyValid,
            "{alg:?}"
        );
        assert_eq!(
            (s0.format, s0.chain),
            (Some(SignatureFormat::S0), ChainStatus::NoChain)
        );
        assert!(s0.signer_fingerprint.is_some(), "{alg:?}");
        assert_eq!(s0.signer_fingerprint, s1.signer_fingerprint, "{alg:?}");

        let unknown = verify_detached(DATA, &s0_writer(DATA, entry).unwrap(), None, None).unwrap();
        assert_eq!(
            unknown.validity,
            SignatureValidity::UnknownSigner,
            "{alg:?}"
        );
    }
}

/// The boolean API answers "was this signed by one of these keys?": a
/// standard signature verifies against its own certificate, so a key the
/// caller supplied that did not sign it must not report valid.
#[test]
fn boolean_verify_requires_the_supplied_key_to_be_the_signer() {
    use crate::cms_envelop::verify_signature;
    let entries = all();
    for (i, (alg, entry)) in entries.iter().enumerate() {
        let sig = sign(DATA, entry, *alg).unwrap();
        let own = verify_signature(DATA, &sig, &public_bundle(entry)).unwrap();
        assert_eq!(
            own.validity,
            SignatureValidity::CryptographicallyValid,
            "{alg:?}"
        );
        let (_, other) = &entries[(i + 2) % entries.len()];
        let stranger = verify_signature(DATA, &sig, &public_bundle(other)).unwrap();
        assert_eq!(
            stranger.validity,
            SignatureValidity::CryptographicallyInvalid,
            "{alg:?} verified with another signer's key"
        );
    }
}
