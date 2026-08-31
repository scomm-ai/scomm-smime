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
    assert!(info.identities.iter().any(|c| c.algorithm == ALG_RSA_OAEP));
    assert!(info.identities.iter().any(|c| c.algorithm == ALG_X25519));
    assert!(info.identities.iter().any(|c| c.algorithm == ALG_RSA_PSS));
    assert!(!info.is_pqc());
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

#[test]
fn rsa_pss_sign_verify() {
    let alice = gen(KeyProfile::Classical);
    let p = engine();
    let sig = p
        .sign(b"signed", &alice.secret, None, &SignOptions::default())
        .unwrap();
    let v = p.verify(b"signed", &sig, &alice.public).unwrap();
    assert_eq!(v.validity, SignatureValidity::CryptographicallyValid);
    let bad = p.verify(b"other", &sig, &alice.public).unwrap();
    assert_ne!(bad.validity, SignatureValidity::CryptographicallyValid);
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
