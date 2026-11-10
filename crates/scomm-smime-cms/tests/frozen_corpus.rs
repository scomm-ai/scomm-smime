//! Keys and messages in today's private Scomm format, written by an earlier build.
//!
//! The rebuild on OpenSSL CMS keeps a decrypt-only reader for existing mail, and
//! this is what it has to keep opening. Throwaway test material.
//!
//! Add new files with `cargo test --test frozen_corpus -- --ignored`. Existing
//! files are never rewritten: replacing one would hide the failure it guards.
//! RSA bundles are no longer generated, so that one needs `rsa.pub.json` and
//! `rsa.sec.json` to already exist.

use std::fs;
use std::path::PathBuf;

use scomm_smime_cms::CmsSmime;
use scomm_smime_core::*;

const PLAINTEXT: &[u8] = b"Content-Type: text/plain\r\n\r\nfrozen plaintext\r\n";

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/scomm")
}

fn file(name: &str) -> Vec<u8> {
    fs::read(dir().join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn engine() -> CmsSmime {
    CmsSmime::new()
}

fn opens(message: &str, key: &str) {
    let out = engine()
        .decrypt(&file(message), &file(&format!("{key}.sec.json")), None)
        .unwrap_or_else(|e| panic!("{message} with {key}: {e}"));
    assert_eq!(out.plaintext, PLAINTEXT, "{message} with {key}");
    assert_eq!(out.format, FORMAT_F0_SCOMM, "{message} with {key}");
}

fn verifies(signature: &str, key: &str) {
    let result = engine()
        .verify(PLAINTEXT, &file(signature), &file(&format!("{key}.pub.json")))
        .unwrap_or_else(|e| panic!("{signature}: {e}"));
    assert_eq!(result.validity, SignatureValidity::CryptographicallyValid, "{signature}");
}

#[test]
fn frozen_messages_still_open() {
    opens("x25519.single.cms", "classical");
    opens("x25519.multi.cms", "classical");
    opens("x25519.multi.cms", "classical2");
    opens("hybrid.single.cms", "pqc");
    opens("hybrid.multi.cms", "pqc");
    opens("hybrid.multi.cms", "pqc2");
    opens("mixed.cms", "pqc");
    opens("mixed.cms", "classical");
    opens("x25519.armored.pem", "classical");
    opens("rsa.cms", "rsa");
    verifies("ed25519.sig", "classical");
    verifies("mldsa65.sig", "pqc");
    verifies("rsa-pss.sig", "rsa");
}

fn write_new(name: &str, data: &[u8]) {
    let path = dir().join(name);
    if !path.exists() {
        fs::write(path, data).unwrap();
    }
}

#[test]
#[ignore = "writes fixtures"]
fn add_missing_fixtures() {
    fs::create_dir_all(dir()).unwrap();
    for (name, profile) in [
        ("classical", KeyProfile::Classical),
        ("classical2", KeyProfile::Classical),
        ("pqc", KeyProfile::PqcCms),
        ("pqc2", KeyProfile::PqcCms),
    ] {
        if dir().join(format!("{name}.sec.json")).exists() {
            continue;
        }
        let key = engine()
            .generate_key(&GenerateKeyOptions {
                userid: format!("Frozen {name} <frozen-{name}@example.com>"),
                passphrase: None,
                profile,
            })
            .unwrap();
        write_new(&format!("{name}.pub.json"), &key.public);
        write_new(&format!("{name}.sec.json"), &key.secret);
    }
    let public = |name: &str| file(&format!("{name}.pub.json"));
    let secret = |name: &str| file(&format!("{name}.sec.json"));
    let encrypt = |keys: &[&[u8]], armored: bool| {
        engine()
            .encrypt(PLAINTEXT, keys, &EncryptOptions { armored })
            .unwrap()
    };
    let (c1, c2, q1, q2) = (public("classical"), public("classical2"), public("pqc"), public("pqc2"));
    write_new("x25519.single.cms", &encrypt(&[&c1], false));
    write_new("x25519.multi.cms", &encrypt(&[&c1, &c2], false));
    write_new("x25519.armored.pem", &encrypt(&[&c1], true));
    write_new("hybrid.single.cms", &encrypt(&[&q1], false));
    write_new("hybrid.multi.cms", &encrypt(&[&q1, &q2], false));
    write_new("mixed.cms", &encrypt(&[&q1, &c1], false));

    let sign = |key: &[u8], algorithm| {
        engine()
            .sign(PLAINTEXT, key, None, &SignOptions { detached: false, algorithm })
            .unwrap()
    };
    write_new("ed25519.sig", &sign(&secret("classical"), ALG_ED25519));
    write_new("mldsa65.sig", &sign(&secret("pqc"), ALG_MLDSA65));

    write_new("rsa.cms", &encrypt(&[&public("rsa")], false));
    write_new("rsa-pss.sig", &sign(&secret("rsa"), ALG_RSA_PSS));
}
