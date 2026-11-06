//! Messages captured from real mail clients. See `interop/samples/README.md`.

mod common;

use std::fs;
use std::path::PathBuf;

use base64::Engine;
use common::{Expect, Matrix};
use scomm_smime_cms::CmsSmime;
use scomm_smime_core::*;
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
struct Case {
    client: String,
    name: String,
    kind: String,
    message: String,
    #[serde(default)]
    content: Option<String>,
    identity: String,
    alg: String,
    expect: String,
}

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/client-samples")
}

fn file(name: &str) -> Vec<u8> {
    fs::read(dir().join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn identity(case: &Case, with_secret: bool) -> Vec<u8> {
    let cert = String::from_utf8(file(&format!("identities/{}.crt", case.identity))).unwrap();
    let purpose = if case.kind == "verify" { "signing" } else { "encryption" };
    let secret = with_secret.then(|| {
        base64::engine::general_purpose::STANDARD.encode(file(&format!("identities/{}.p8", case.identity)))
    });
    serde_json::to_vec(&json!({"v": 1, "entries": [{
        "alg": case.alg,
        "purpose": purpose,
        "cert_pem": cert,
        "spki_b64": "",
        "pkcs8_b64": secret,
    }]}))
    .unwrap()
}

fn run(case: &Case) -> std::result::Result<(), String> {
    let engine = CmsSmime::new();
    let message = file(&case.message);
    match case.kind.as_str() {
        "decrypt" => engine
            .decrypt(&message, &identity(case, true), None)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        "verify" => {
            let content = file(case.content.as_deref().expect("verify needs content"));
            let result = engine
                .verify(&content, &message, &identity(case, false))
                .map_err(|e| e.to_string())?;
            match result.validity {
                SignatureValidity::CryptographicallyValid => Ok(()),
                other => Err(format!("{other:?}")),
            }
        }
        other => panic!("unknown kind: {other}"),
    }
}

#[test]
fn client_samples() {
    let path = dir().join("cases.json");
    let cases: Vec<Case> = serde_json::from_slice(&fs::read(&path).expect("cases.json")).expect("cases.json");
    let mut m = Matrix::default();
    for case in &cases {
        let expect = match case.expect.strip_prefix("gap:") {
            Some(id) => Expect::Gap(Box::leak(id.to_string().into_boxed_str())),
            None => {
                assert_eq!(case.expect, "works", "{}", case.name);
                Expect::Works
            }
        };
        m.case(&format!("{}: {}", case.client, case.name), expect, run(case));
    }
    m.finish(&format!("Client samples ({})", cases.len()));
}
