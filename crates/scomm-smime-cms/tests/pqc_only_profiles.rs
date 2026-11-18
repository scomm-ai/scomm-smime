//! ABI 4: post-quantum-only key profiles and bundle entry removal
//! (secMail10 OpenSpec `simplify-smime-pqc-key-generation`).

use scomm_smime_cms::{remove_entries, CmsSmime};
use scomm_smime_core::*;
use serde_json::Value;

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

fn entries(bundle: &[u8]) -> Vec<Value> {
    let json: Value = serde_json::from_slice(bundle).unwrap();
    json["entries"].as_array().unwrap().clone()
}

fn algs(bundle: &[u8]) -> Vec<String> {
    entries(bundle)
        .iter()
        .map(|e| e["alg"].as_str().unwrap().to_string())
        .collect()
}

fn spki_of(bundle: &[u8], alg: &str) -> String {
    entries(bundle).iter().find(|e| e["alg"] == alg).unwrap()["spki_b64"]
        .as_str()
        .unwrap()
        .to_string()
}

#[test]
fn pqc_encryption_profile_holds_only_the_hybrid_entry() {
    let key = gen(KeyProfile::PqcEncryption);
    assert_eq!(algs(&key.secret), vec![ALG_MLKEM_HYBRID]);
    assert_eq!(algs(&key.public), vec![ALG_MLKEM_HYBRID]);
    assert!(key.info.is_pqc());

    let p = engine();
    let ct = p
        .encrypt(
            b"pq only",
            &[&key.public],
            &EncryptOptions { armored: false },
        )
        .unwrap();
    assert!(p.inspect_message(&ct).unwrap().pqc);
    assert_eq!(
        p.decrypt(&ct, &key.secret, None).unwrap().plaintext,
        b"pq only"
    );
}

#[test]
fn pqc_signing_profile_holds_only_the_mldsa_entry_with_a_certificate() {
    let key = gen(KeyProfile::PqcSigning);
    assert_eq!(algs(&key.secret), vec![ALG_MLDSA65]);
    let entry = &entries(&key.public)[0];
    assert_eq!(entry["purpose"], "signing");
    assert!(entry["cert_pem"]
        .as_str()
        .unwrap()
        .contains("BEGIN CERTIFICATE"));

    let p = engine();
    let options = SignOptions {
        detached: false,
        algorithm: ALG_MLDSA65,
    };
    let sig = p.sign(b"signed", &key.secret, None, &options).unwrap();
    assert!(p.inspect_message(&sig).unwrap().pqc);
    let v = p.verify(b"signed", &sig, &key.public).unwrap();
    assert_eq!(v.validity, SignatureValidity::CryptographicallyValid);
}

#[test]
fn pqc_only_bundles_cannot_be_used_for_the_other_purpose() {
    let enc = gen(KeyProfile::PqcEncryption);
    let options = SignOptions {
        detached: false,
        algorithm: ALG_MLDSA65,
    };
    assert!(matches!(
        engine().sign(b"x", &enc.secret, None, &options),
        Err(SmimeError::NoSuitableSigningKey)
    ));
    let sign = gen(KeyProfile::PqcSigning);
    assert!(engine()
        .encrypt(b"x", &[&sign.public], &EncryptOptions::default())
        .is_err());
}

#[test]
fn two_pqc_only_runs_share_no_secret() {
    let enc = gen(KeyProfile::PqcEncryption);
    let sign = gen(KeyProfile::PqcSigning);
    let secrets = |b: &[u8]| -> Vec<String> {
        entries(b)
            .iter()
            .filter_map(|e| e["pkcs8_b64"].as_str().map(str::to_string))
            .collect()
    };
    for s in secrets(&enc.secret) {
        assert!(!secrets(&sign.secret).contains(&s));
    }
}

#[test]
fn remove_entries_drops_only_the_named_entries() {
    let legacy = gen(KeyProfile::PqcCms);
    let hybrid = spki_of(&legacy.secret, ALG_MLKEM_HYBRID);
    let trimmed = remove_entries(&legacy.secret, &[hybrid]).unwrap();
    assert_eq!(
        algs(&trimmed),
        vec![ALG_X25519, ALG_ED25519, ALG_MLDSA65],
        "only the hybrid entry is removed"
    );
    let before: Vec<Value> = entries(&legacy.secret)
        .into_iter()
        .filter(|e| e["alg"] != ALG_MLKEM_HYBRID)
        .collect();
    assert_eq!(
        entries(&trimmed),
        before,
        "other entries are byte-identical"
    );

    // The classical entry left behind still decrypts its own mail.
    let p = engine();
    let classical_public =
        remove_entries(&legacy.public, &[spki_of(&legacy.public, ALG_MLKEM_HYBRID)]).unwrap();
    let ct = p
        .encrypt(b"classic", &[&classical_public], &EncryptOptions::default())
        .unwrap();
    assert_eq!(
        p.decrypt(&ct, &trimmed, None).unwrap().plaintext,
        b"classic"
    );
}

#[test]
fn remove_entries_refuses_to_empty_a_bundle() {
    let key = gen(KeyProfile::PqcEncryption);
    let spki = spki_of(&key.secret, ALG_MLKEM_HYBRID);
    assert!(remove_entries(&key.secret, &[spki]).is_err());
}

#[test]
fn remove_entries_ignores_unknown_spkis() {
    let key = gen(KeyProfile::PqcCms);
    let same = remove_entries(&key.secret, &["not-there".to_string()]).unwrap();
    assert_eq!(entries(&same), entries(&key.secret));
}
