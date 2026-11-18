//! CMS-01: a supplied recipient bundle that yields no encryption entry must
//! refuse the whole envelope, naming that recipient, instead of being dropped
//! while the other recipients (often the sender's own copy) are still wrapped.
use scomm_smime_cms::CmsSmime;
use scomm_smime_core::*;

fn gen(profile: KeyProfile, uid: &str) -> GeneratedKey {
    CmsSmime::new()
        .generate_key(&GenerateKeyOptions {
            userid: uid.into(),
            passphrase: None,
            profile,
            ..Default::default()
        })
        .unwrap()
}

// Parses (v=1, non-empty entries) but no supported encryption algorithm.
const UNSUPPORTED: &[u8] =
    br#"{"v":1,"entries":[{"alg":"smime-p256-ecdh","purpose":"encryption","spki_b64":"AAAA"}]}"#;
// Signing-only bundle: no encryption entry at all.
const SIGN_ONLY: &[u8] =
    br#"{"v":1,"entries":[{"alg":"smime-ed25519","purpose":"signing","spki_b64":"AAAA"}]}"#;

#[test]
fn unusable_bundle_refuses_and_names_its_index() {
    let p = CmsSmime::new();
    let alice = gen(KeyProfile::Classical, "Alice <alice@example.com>");
    let pat = gen(KeyProfile::PqcCms, "Pat <pat@example.com>");
    for bad in [UNSUPPORTED, SIGN_ONLY] {
        for (keys, index) in [
            (vec![&alice.public[..], bad], 1),
            (vec![bad, &alice.public[..]], 0),
            (vec![&alice.public[..], &pat.public[..], bad], 2),
            (vec![bad], 0),
        ] {
            let err = p
                .encrypt(b"hi", &keys, &EncryptOptions { armored: false })
                .unwrap_err();
            assert_eq!(err, SmimeError::RecipientWithoutEncryptionKey { index });
            assert_eq!(err.code(), SmimeError::NoSuitableEncryptionKey.code());
            assert_eq!(
                err.to_string(),
                format!("no suitable encryption key for recipient {index}")
            );
        }
    }
}

#[test]
fn usable_classical_and_pqc_recipients_still_encrypt() {
    let p = CmsSmime::new();
    let alice = gen(KeyProfile::Classical, "Alice <alice@example.com>");
    let pat = gen(KeyProfile::PqcCms, "Pat <pat@example.com>");
    let der = p
        .encrypt(
            b"hi",
            &[&alice.public, &pat.public],
            &EncryptOptions::default(),
        )
        .unwrap();
    assert_eq!(
        p.decrypt(&der, &alice.secret, None).unwrap().plaintext,
        b"hi"
    );
    assert_eq!(p.decrypt(&der, &pat.secret, None).unwrap().plaintext, b"hi");
}

#[test]
fn no_recipients_is_still_no_suitable_key() {
    let err = CmsSmime::new()
        .encrypt(b"hi", &[], &EncryptOptions::default())
        .unwrap_err();
    assert_eq!(err, SmimeError::NoSuitableEncryptionKey);
}
