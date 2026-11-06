use scomm_smime_core::*;
use scomm_smime_cms::CmsSmime;

fn engine() -> CmsSmime {
    CmsSmime::new()
}

fn gen(profile: KeyProfile) -> GeneratedKey {
    engine()
        .generate_key(&GenerateKeyOptions {
            userid: "Alice <alice@example.com>".into(),
            passphrase: None,
            profile,
        })
        .expect("generate")
}

#[test]
fn classical_generate_inspect() {
    let key = gen(KeyProfile::Classical);
    let info = engine().inspect_key(&key.secret).unwrap();
    assert!(info.identities.iter().any(|c| c.algorithm == ALG_X25519));
    assert!(info.identities.iter().any(|c| c.algorithm == ALG_ED25519));
    assert!(!info.identities.iter().any(|c| c.algorithm == ALG_RSA_OAEP));
    assert!(!info.identities.iter().any(|c| c.algorithm == ALG_RSA_PSS));
    assert!(!info.is_pqc());
}

#[test]
fn ed25519_sign_verify() {
    let alice = gen(KeyProfile::Classical);
    let p = engine();
    let sig = p
        .sign(
            b"signed-ed25519",
            &alice.secret,
            None,
            &SignOptions {
                detached: false,
                algorithm: ALG_ED25519,
            },
        )
        .unwrap();
    let v = p.verify(b"signed-ed25519", &sig, &alice.public).unwrap();
    assert_eq!(v.validity, SignatureValidity::CryptographicallyValid);
    let bad = p.verify(b"other", &sig, &alice.public).unwrap();
    assert_ne!(bad.validity, SignatureValidity::CryptographicallyValid);
}

#[test]
fn rsa_encrypt_decrypt_roundtrip() {
    let alice = gen(KeyProfile::Classical);
    let p = engine();
    let ct = p
        .encrypt(
            b"hello smime",
            &[&alice.public],
            &EncryptOptions { armored: true },
        )
        .unwrap();
    let info = p.inspect_message(&ct).unwrap();
    assert!(info.encrypted);
    assert!(!info.pqc);
    let pt = p.decrypt(&ct, &alice.secret, None).unwrap();
    assert_eq!(pt.plaintext, b"hello smime");
}

#[test]
fn pqc_encrypt_decrypt_roundtrip() {
    let alice = gen(KeyProfile::PqcCms);
    assert!(alice.info.is_pqc());
    let p = engine();
    let ct = p
        .encrypt(
            b"pqc cms",
            &[&alice.public],
            &EncryptOptions { armored: false },
        )
        .unwrap();
    let info = p.inspect_message(&ct).unwrap();
    assert!(info.pqc);
    let pt = p.decrypt(&ct, &alice.secret, None).unwrap();
    assert_eq!(pt.plaintext, b"pqc cms");
}

/// A classical key row and a PQC key row share one bundle. Each must sign with
/// its own key: a classical row that signed with ML-DSA would skip the add-on
/// check and fail against the Ed25519 key the sender published.
#[test]
fn pqc_bundle_signs_with_the_named_algorithm() {
    let alice = gen(KeyProfile::PqcCms);
    let p = engine();
    for (algorithm, pqc) in [(ALG_ED25519, false), (ALG_MLDSA65, true)] {
        let options = SignOptions { detached: false, algorithm };
        let sig = p.sign(b"signed", &alice.secret, None, &options).unwrap();
        assert_eq!(p.inspect_message(&sig).unwrap().pqc, pqc, "{algorithm}");
        let v = p.verify(b"signed", &sig, &alice.public).unwrap();
        assert_eq!(v.validity, SignatureValidity::CryptographicallyValid);
    }
}

#[test]
fn sign_refuses_an_algorithm_the_bundle_does_not_hold() {
    let alice = gen(KeyProfile::Classical);
    let options = SignOptions { detached: false, algorithm: ALG_MLDSA65 };
    assert!(matches!(
        engine().sign(b"signed", &alice.secret, None, &options),
        Err(SmimeError::NoSuitableSigningKey)
    ));
}

#[test]
fn classical_decrypt_without_pqc_bundle() {
    let alice = gen(KeyProfile::Classical);
    let p = engine();
    let ct = p
        .encrypt(b"free", &[&alice.public], &EncryptOptions::default())
        .unwrap();
    let pt = p.decrypt(&ct, &alice.secret, None).unwrap();
    assert_eq!(pt.plaintext, b"free");
}

#[test]
fn x25519_multi_recipient_each_can_decrypt() {
    let alice = gen(KeyProfile::Classical);
    let bob = gen(KeyProfile::Classical);
    let carol = gen(KeyProfile::Classical);
    let p = engine();
    let ct = p
        .encrypt(
            b"to all",
            &[&alice.public, &bob.public, &carol.public],
            &EncryptOptions { armored: false },
        )
        .unwrap();
    for k in [&alice, &bob, &carol] {
        assert_eq!(p.decrypt(&ct, &k.secret, None).unwrap().plaintext, b"to all");
    }
    let mallory = gen(KeyProfile::Classical);
    assert!(p.decrypt(&ct, &mallory.secret, None).is_err());
}

#[test]
fn pqc_and_classical_recipients_each_can_decrypt() {
    let alice = gen(KeyProfile::PqcCms);
    let bob = gen(KeyProfile::Classical);
    let p = engine();
    let ct = p
        .encrypt(b"mixed", &[&alice.public, &bob.public], &EncryptOptions { armored: false })
        .unwrap();
    assert_eq!(p.decrypt(&ct, &alice.secret, None).unwrap().plaintext, b"mixed");
    assert_eq!(p.decrypt(&ct, &bob.secret, None).unwrap().plaintext, b"mixed");
}

#[test]
fn several_pqc_recipients_stay_post_quantum() {
    let alice = gen(KeyProfile::PqcCms);
    let bob = gen(KeyProfile::PqcCms);
    let p = engine();
    let ct = p
        .encrypt(b"pq only", &[&alice.public, &bob.public], &EncryptOptions { armored: false })
        .unwrap();
    let info = p.inspect_message(&ct).unwrap();
    assert!(info.pqc);
    assert!(!info.classical_recipient);
    for k in [&alice, &bob] {
        assert_eq!(p.decrypt(&ct, &k.secret, None).unwrap().plaintext, b"pq only");
    }
}

#[test]
fn inspect_reports_a_classical_recipient_beside_a_pqc_one() {
    let alice = gen(KeyProfile::PqcCms);
    let bob = gen(KeyProfile::Classical);
    let p = engine();
    let ct = p
        .encrypt(b"mixed", &[&alice.public, &bob.public], &EncryptOptions { armored: false })
        .unwrap();
    let info = p.inspect_message(&ct).unwrap();
    assert!(info.pqc);
    assert!(info.classical_recipient);
}
