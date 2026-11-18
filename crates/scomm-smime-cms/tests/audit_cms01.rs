//! Audit reproductions (CMS-02, INT-02). Test-only. CMS-01 is now the
//! regression test in `recipient_without_encryption_key.rs`.
use openssl::x509::X509;
use scomm_smime_cms::CmsSmime;
use scomm_smime_core::*;

fn gen(profile: KeyProfile, uid: &str) -> GeneratedKey {
    CmsSmime::new()
        .generate_key(&GenerateKeyOptions { userid: uid.into(), passphrase: None, profile, ..Default::default() })
        .unwrap()
}

fn out_dir() -> std::path::PathBuf {
    let d = std::env::var("AUDIT_OUT").map(Into::into).unwrap_or_else(|_| std::env::temp_dir());
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn cms02_pqc_signature_shape() {
    let k = gen(KeyProfile::PqcCms, "Pat <pat@example.com>");
    let sig = CmsSmime::new()
        .sign(b"m", &k.secret, None, &SignOptions { detached: true, algorithm: ALG_MLDSA65 })
        .unwrap();
    std::fs::write(out_dir().join("audit_mldsa_sig.der"), &sig).unwrap();
}

#[test]
fn int02_fixed_serial_and_validity() {
    let certs = |k: &GeneratedKey, alg: &str| -> X509 {
        let v: serde_json::Value = serde_json::from_slice(&k.public).unwrap();
        let pem = v["entries"].as_array().unwrap().iter()
            .find(|e| e["alg"] == alg).unwrap()["cert_pem"].as_str().unwrap().to_owned();
        X509::from_pem(pem.as_bytes()).unwrap()
    };
    let a = gen(KeyProfile::PqcCms, "A <same@example.com>");
    let b = gen(KeyProfile::PqcCms, "A <same@example.com>");
    let (ea, eb) = (certs(&a, ALG_ED25519), certs(&b, ALG_ED25519));
    let sn = |c: &X509| c.serial_number().to_bn().unwrap().to_dec_str().unwrap().to_string();
    println!("ed25519 serials {} {}; validity {} - {}", sn(&ea), sn(&eb), ea.not_before(), ea.not_after());
    assert_eq!(sn(&ea), "1");
    assert_eq!(sn(&ea), sn(&eb));
    assert_eq!(ea.issuer_name().to_der().unwrap(), eb.issuer_name().to_der().unwrap());
    assert_eq!(ea.not_after().to_string(), eb.not_after().to_string());
    let (ma, mb) = (certs(&a, ALG_MLDSA65), certs(&b, ALG_MLDSA65));
    println!("mldsa serials {} {}; validity {} - {}", sn(&ma), sn(&mb), ma.not_before(), ma.not_after());
    assert_ne!(sn(&ma), sn(&mb));
    assert_eq!(ma.not_after().to_string(), mb.not_after().to_string());
    std::fs::write(out_dir().join("audit_ed25519_cert.pem"), ea.to_pem().unwrap()).unwrap();
}
