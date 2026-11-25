use base64::Engine;
use openssl::pkey::PKey;
use openssl::x509::X509;
use scomm_smime_cms::{cert_info, import, CmsSmime};
use scomm_smime_core::*;
use serde_json::{json, Value};
use std::fs;
use std::process::Command;

const DATA: &[u8] = b"Content-Type: text/plain\r\n\r\nNIST curves\r\n";
const PROFILES: [(KeyProfile, &str, &str, u32); 3] = [
    (
        KeyProfile::ClassicalP256,
        ALG_ECDSA_P256,
        ALG_ECDH_P256,
        256,
    ),
    (
        KeyProfile::ClassicalP384,
        ALG_ECDSA_P384,
        ALG_ECDH_P384,
        384,
    ),
    (
        KeyProfile::ClassicalP521,
        ALG_ECDSA_P521,
        ALG_ECDH_P521,
        521,
    ),
];

fn generate(profile: KeyProfile) -> GeneratedKey {
    CmsSmime::new()
        .generate_key(&GenerateKeyOptions {
            userid: "Alice <alice@example.com>".into(),
            profile,
            validity_years: Some(3),
            ..Default::default()
        })
        .unwrap()
}

fn bytes(entry: &Value, field: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(entry[field].as_str().unwrap())
        .unwrap()
}

#[test]
fn nist_curves_roundtrip_and_mixed_recipients() {
    let engine = CmsSmime::new();
    for (profile, sign, encrypt, bits) in PROFILES {
        let key = generate(profile);
        let public = engine.export_public_key(&key.secret).unwrap();
        assert_eq!(public, key.public);
        let bundle: Value = serde_json::from_slice(&key.secret).unwrap();
        let entries = bundle["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        assert_ne!(entries[0]["spki_b64"], entries[1]["spki_b64"]);
        assert_eq!(entries[0]["alg"], sign);
        assert_eq!(entries[1]["alg"], encrypt);
        for entry in entries {
            let pem = entry["cert_pem"].as_str().unwrap().as_bytes();
            let cert = X509::from_pem(pem).unwrap();
            let private = PKey::private_key_from_der(&bytes(entry, "pkcs8_b64")).unwrap();
            assert!(cert.public_key().unwrap().public_eq(&private));
            assert!(cert.verify(&private).unwrap());
            let info = cert_info(pem).unwrap();
            assert_eq!(cert.public_key().unwrap().bits(), bits);
            assert!(info.is_self_signed);
            assert_eq!(info.key_bits, bits);
            let usage = if entry["purpose"] == "signing" {
                "Digital Signature"
            } else {
                "Key Agreement"
            };
            assert_eq!(info.key_usages, vec![usage.to_string()]);
            assert!(info
                .extended_key_usages
                .iter()
                .any(|u| u == "E-mail Protection"));
            let imported = import(&[pem.to_vec(), bytes(entry, "pkcs8_b64")], "").unwrap();
            assert_eq!(imported.certificates.len(), 1);
            assert!(imported.certificates[0].pkcs8_b64.is_some());
            assert_eq!(imported.unmatched_keys, 0);
        }
        let sig = engine
            .sign(
                DATA,
                &key.secret,
                None,
                &SignOptions {
                    detached: true,
                    algorithm: sign,
                },
            )
            .unwrap();
        assert_eq!(engine.inspect_message(&sig).unwrap().algorithm, sign);
        assert_eq!(
            engine.verify(DATA, &sig, &public).unwrap().validity,
            SignatureValidity::CryptographicallyValid
        );
        assert_ne!(
            engine.verify(b"altered", &sig, &public).unwrap().validity,
            SignatureValidity::CryptographicallyValid
        );
        assert!(engine
            .sign(
                DATA,
                &key.secret,
                None,
                &SignOptions {
                    detached: true,
                    algorithm: ALG_ED25519
                }
            )
            .is_err());
        let encrypted = engine
            .encrypt(DATA, &[&public], &EncryptOptions { armored: false })
            .unwrap();
        let opened = engine.decrypt(&encrypted, &key.secret, None).unwrap();
        assert_eq!(opened.plaintext, DATA);
        assert_eq!(opened.algorithm, encrypt);
        assert_eq!(opened.format, FORMAT_F1);
        assert_eq!(
            engine.inspect_message(&encrypted).unwrap().algorithm,
            "smime-ecdh"
        );
        let mut tampered = encrypted.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(engine.decrypt(&tampered, &key.secret, None).is_err());
        assert!(engine
            .decrypt(&encrypted[..encrypted.len() / 2], &key.secret, None)
            .is_err());
        assert!(engine
            .decrypt(&encrypted, &generate(profile).secret, None)
            .is_err());

        // A recipient of each existing family and a different NIST curve can all open it.
        let classical = generate(KeyProfile::Classical);
        let hybrid = generate(KeyProfile::PqcEncryption);
        let other = generate(KeyProfile::ClassicalP384);
        let mixed = engine
            .encrypt(
                DATA,
                &[&public, &classical.public, &hybrid.public, &other.public],
                &EncryptOptions { armored: true },
            )
            .unwrap();
        for recipient in [&key, &classical, &hybrid, &other] {
            assert_eq!(
                engine
                    .decrypt(&mixed, &recipient.secret, None)
                    .unwrap()
                    .plaintext,
                DATA
            );
        }
        // Rename a P-256 private entry to another curve: never silently sign with it.
        let mut wrong = bundle.clone();
        wrong["entries"][0]["alg"] = json!(if bits == 256 {
            ALG_ECDSA_P384
        } else {
            ALG_ECDSA_P256
        });
        let algorithm = if bits == 256 {
            ALG_ECDSA_P384
        } else {
            ALG_ECDSA_P256
        };
        assert!(engine
            .sign(
                DATA,
                &serde_json::to_vec(&wrong).unwrap(),
                None,
                &SignOptions {
                    detached: true,
                    algorithm
                }
            )
            .is_err());
    }
}

#[test]
fn nist_curves_openssl_interop() {
    let cli = std::env::var("SCOMM_OPENSSL_CLI").unwrap_or_else(|_| "openssl".into());
    if Command::new(&cli).arg("version").output().is_err() {
        assert!(
            std::env::var_os("SCOMM_INTEROP_REQUIRE_TOOLS").is_none(),
            "OpenSSL CLI required"
        );
        eprintln!("skipped: OpenSSL CLI unavailable");
        return;
    }
    let dir = std::env::temp_dir().join(format!("scomm-nist-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let run = |args: &[&str]| {
        let out = Command::new(&cli)
            .args(args)
            .current_dir(&dir)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    };
    let engine = CmsSmime::new();
    fs::write(dir.join("msg"), DATA).unwrap();
    for (profile, sign, _, _) in PROFILES {
        let key = generate(profile);
        let bundle: Value = serde_json::from_slice(&key.secret).unwrap();
        for (i, name) in [(0, "sign"), (1, "encrypt")] {
            fs::write(
                dir.join(format!("{name}.crt")),
                bundle["entries"][i]["cert_pem"].as_str().unwrap(),
            )
            .unwrap();
            let private =
                PKey::private_key_from_der(&bytes(&bundle["entries"][i], "pkcs8_b64")).unwrap();
            fs::write(
                dir.join(format!("{name}.key")),
                private.private_key_to_pem_pkcs8().unwrap(),
            )
            .unwrap();
        }
        let sig = engine
            .sign(
                DATA,
                &key.secret,
                None,
                &SignOptions {
                    detached: true,
                    algorithm: sign,
                },
            )
            .unwrap();
        fs::write(dir.join("sig.der"), &sig).unwrap();
        assert_eq!(
            run(&[
                "cms",
                "-verify",
                "-binary",
                "-inform",
                "DER",
                "-in",
                "sig.der",
                "-content",
                "msg",
                "-noverify"
            ]),
            DATA
        );
        let printed = String::from_utf8(run(&[
            "cms", "-cmsout", "-print", "-inform", "DER", "-in", "sig.der",
        ]))
        .unwrap();
        assert!(printed.contains("ecdsa-with-SHA"));
        run(&[
            "cms", "-sign", "-binary", "-in", "msg", "-signer", "sign.crt", "-inkey", "sign.key",
            "-md", "sha256", "-outform", "DER", "-out", "cli-sig",
        ]);
        let sig = fs::read(dir.join("cli-sig")).unwrap();
        // SHA-256 on a P-384/P-521 key must not be labeled as P-256.
        assert_eq!(
            engine.inspect_message(&sig).unwrap().algorithm,
            if profile == KeyProfile::ClassicalP256 {
                ALG_ECDSA_P256
            } else {
                "smime-ecdsa"
            }
        );
        assert_eq!(
            engine.verify(DATA, &sig, &key.public).unwrap().validity,
            SignatureValidity::CryptographicallyValid
        );

        let encrypted = engine
            .encrypt(DATA, &[&key.public], &EncryptOptions { armored: false })
            .unwrap();
        fs::write(dir.join("encrypted.der"), &encrypted).unwrap();
        let printed = String::from_utf8(run(&[
            "cms",
            "-cmsout",
            "-print",
            "-inform",
            "DER",
            "-in",
            "encrypted.der",
        ]))
        .unwrap();
        assert!(printed.contains("d.kari"));
        assert!(printed.contains("id-aes256-wrap"));
        assert!(printed.contains("aes-256-gcm"));
        assert_eq!(
            run(&[
                "cms",
                "-decrypt",
                "-binary",
                "-inform",
                "DER",
                "-in",
                "encrypted.der",
                "-recip",
                "encrypt.crt",
                "-inkey",
                "encrypt.key"
            ]),
            DATA
        );
        // External EnvelopedData also uses KARI, and must route to OpenSSL's reader.
        run(&[
            "cms",
            "-encrypt",
            "-binary",
            "-in",
            "msg",
            "-aes-256-cbc",
            "-outform",
            "DER",
            "-out",
            "cli-encrypted",
            "encrypt.crt",
        ]);
        assert_eq!(
            engine
                .decrypt(
                    &fs::read(dir.join("cli-encrypted")).unwrap(),
                    &key.secret,
                    None
                )
                .unwrap()
                .plaintext,
            DATA
        );
    }
    // Check the paths before removing this test's temporary directory.
    let parent = std::env::temp_dir().canonicalize().unwrap();
    let resolved = dir.canonicalize().unwrap();
    assert!(
        resolved.starts_with(parent)
            && resolved
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("scomm-nist-")
    );
    fs::remove_dir_all(resolved).unwrap();
}
