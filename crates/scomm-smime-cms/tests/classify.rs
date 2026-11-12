//! Message routing is structural (R8): checks on the frozen legacy corpus,
//! on ciphertext that happens to hold a Scomm OID's bytes, and on damaged input.

use std::fs;
use std::path::PathBuf;

use scomm_smime_cms::CmsSmime;
use scomm_smime_core::*;

fn file(name: &str) -> Vec<u8> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/scomm");
    fs::read(dir.join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn inspect(message: &[u8]) -> MessageInfo {
    CmsSmime::new().inspect_message(message).expect("inspect")
}

#[test]
fn legacy_corpus_is_labeled_by_structure() {
    for (name, algorithm, pqc, classical) in [
        ("rsa.cms", ALG_RSA_OAEP, false, false),
        ("x25519.single.cms", ALG_X25519, false, true),
        ("x25519.multi.cms", ALG_X25519, false, true),
        ("x25519.armored.pem", ALG_X25519, false, true),
        ("hybrid.single.cms", ALG_MLKEM_HYBRID, true, false),
        ("hybrid.multi.cms", ALG_MLKEM_HYBRID, true, false),
        ("mixed.cms", ALG_MLKEM_HYBRID, true, true),
    ] {
        let info = inspect(&file(name));
        assert!(info.encrypted && !info.signed, "{name}");
        assert_eq!(info.algorithm, algorithm, "{name}");
        assert_eq!(info.pqc, pqc, "{name}");
        assert_eq!(info.classical_recipient, classical, "{name}");
    }
    for (name, algorithm, pqc) in [
        ("ed25519.sig", ALG_ED25519, false),
        ("rsa-pss.sig", ALG_RSA_PSS, false),
        ("mldsa65.sig", ALG_MLDSA65, true),
    ] {
        let info = inspect(&file(name));
        assert!(info.signed && !info.encrypted, "{name}");
        assert_eq!(info.algorithm, algorithm, "{name}");
        assert_eq!(info.pqc, pqc, "{name}");
    }
}

/// The old router searched the whole message for these bytes, so an RSA
/// message whose ciphertext contained them was sent down the hybrid path.
#[test]
fn oid_bytes_inside_ciphertext_do_not_change_routing() {
    // DER of 1.3.6.1.4.1.54392.1.1 (legacy hybrid ORI) and 1.3.101.110 (X25519 ORI).
    let hybrid_oid = [
        0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xa6, 0x78, 0x01, 0x01,
    ];
    let x25519_oid = [0x06, 0x03, 0x2b, 0x65, 0x6e];
    let mut message = file("rsa.cms");
    let end = message.len();
    // The encrypted content is the last field, so this only changes ciphertext bytes.
    message[end - 40..end - 28].copy_from_slice(&hybrid_oid);
    message[end - 20..end - 15].copy_from_slice(&x25519_oid);
    let info = inspect(&message);
    assert_eq!(info.algorithm, ALG_RSA_OAEP);
    assert!(!info.pqc);
    assert!(!info.classical_recipient);
    // Still decrypted as an RSA message: the key unwraps and only CBC
    // padding or content is wrong, never a hybrid or X25519 key error.
    let err = CmsSmime::new()
        .decrypt(&message, &file("rsa.sec.json"), None)
        .map(|r| r.plaintext)
        .err();
    assert!(
        !matches!(err, Some(SmimeError::WrongPrivateKey)),
        "routed away from RSA: {err:?}"
    );
}

#[test]
fn oversize_input_is_refused_before_parsing() {
    let big = vec![0x30u8; scomm_smime_cms::MAX_MESSAGE_LEN + 1];
    assert!(matches!(
        CmsSmime::new().inspect_message(&big),
        Err(SmimeError::InvalidArgument(_))
    ));
    assert!(matches!(
        CmsSmime::new().decrypt(&big, &file("classical.sec.json"), None),
        Err(SmimeError::InvalidArgument(_))
    ));
}

#[test]
fn damaged_input_never_panics() {
    let engine = CmsSmime::new();
    for (message, key) in [
        ("rsa.cms", "rsa"),
        ("x25519.multi.cms", "classical"),
        ("x25519.armored.pem", "classical"),
        ("hybrid.single.cms", "pqc"),
        ("mixed.cms", "pqc"),
        ("ed25519.sig", "classical"),
        ("mldsa65.sig", "pqc"),
    ] {
        let original = file(message);
        let secret = file(&format!("{key}.sec.json"));
        let public = file(&format!("{key}.pub.json"));
        for cut in 0..original.len() {
            let _ = engine.inspect_message(&original[..cut]);
            if cut % 61 == 0 {
                let _ = engine.decrypt(&original[..cut], &secret, None);
                let _ = engine.verify(b"x", &original[..cut], &public);
            }
        }
        for i in 0..original.len() {
            let mut flipped = original.clone();
            flipped[i] ^= 0x80;
            let _ = engine.inspect_message(&flipped);
            if i % 61 == 0 {
                let _ = engine.decrypt(&flipped, &secret, None);
            }
        }
    }
}
