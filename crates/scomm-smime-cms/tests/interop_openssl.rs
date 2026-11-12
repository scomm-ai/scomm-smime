//! Interop with the OpenSSL CLI, as a matrix of expected outcomes.
//!
//! Skips when no CLI is found unless SCOMM_INTEROP_REQUIRE_TOOLS is set, as it is
//! in CI, which also requires OpenSSL 4.1. SCOMM_OPENSSL_CLI names the binary.
//!
//! This covers the native engine only. The app also has a Dart signer and
//! verifier for RSA SignedData (`smime_cms_signed_data.dart` in secMail0).

mod common;

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use base64::Engine;
use common::{Expect::*, Matrix};
use scomm_smime_cms::CmsSmime;
use scomm_smime_core::*;
use serde_json::{json, Value};

const MSG: &[u8] = b"Content-Type: text/plain\r\n\r\ninterop plaintext\r\n";

struct Cli {
    bin: String,
    work: PathBuf,
}

impl Cli {
    fn start(test: &str) -> Option<Self> {
        let required = std::env::var_os("SCOMM_INTEROP_REQUIRE_TOOLS").is_some();
        let bin = std::env::var("SCOMM_OPENSSL_CLI").unwrap_or_else(|_| "openssl".into());
        let version = match Command::new(&bin).arg("version").output() {
            Ok(out) => String::from_utf8_lossy(&out.stdout).trim().to_string(),
            Err(_) => {
                assert!(!required, "{bin} is required but not usable");
                println!("skipped: {bin} not usable here");
                return None;
            }
        };
        println!("{version}");
        if required {
            assert!(version.starts_with("OpenSSL 4.1."), "need OpenSSL 4.1, have {version}");
        }
        let work = std::env::temp_dir().join(format!("scomm-smime-{test}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&work);
        fs::create_dir_all(&work).unwrap();
        fs::write(work.join("msg.bin"), MSG).unwrap();
        Some(Self { bin, work })
    }

    fn try_run(&self, args: &[&str]) -> std::result::Result<Vec<u8>, String> {
        let out = Command::new(&self.bin)
            .current_dir(&self.work)
            .args(args)
            .output()
            .map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok(out.stdout)
        } else {
            let err = String::from_utf8_lossy(&out.stderr);
            Err(err.lines().next().unwrap_or("openssl failed").trim().to_string())
        }
    }

    /// For setup steps: failure means the harness is broken, not the engine.
    fn run(&self, args: &[&str]) {
        if let Err(e) = self.try_run(args) {
            panic!("openssl {args:?}: {e}");
        }
    }

    fn read(&self, name: &str) -> Vec<u8> {
        fs::read(self.work.join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
    }

    fn text(&self, name: &str) -> String {
        String::from_utf8(self.read(name)).unwrap()
    }

    fn write(&self, name: &str, data: &[u8]) {
        fs::write(self.work.join(name), data).unwrap();
    }

    fn make_identities(&self) {
        self.run(&["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", "rsa.key"]);
        self.run(&["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", "p256.key"]);
        self.run(&["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384", "-out", "p384.key"]);
        self.run(&["genpkey", "-algorithm", "ED25519", "-out", "ed25519.key"]);
        self.run(&["genpkey", "-algorithm", "ML-DSA-65", "-out", "mldsa.key"]);
        for name in ["rsa", "p256", "p384", "ed25519", "mldsa"] {
            let subj = format!("/CN={name}@example.com");
            self.run(&["req", "-x509", "-new", "-key", &format!("{name}.key"), "-subj", &subj, "-days", "30", "-out", &format!("{name}.crt")]);
        }
        self.run(&["pkcs8", "-topk8", "-nocrypt", "-in", "rsa.key", "-outform", "DER", "-out", "rsa.p8"]);
        // X25519 cannot self-sign, so the Ed25519 identity issues its certificate.
        self.run(&["genpkey", "-algorithm", "X25519", "-out", "x25519.key"]);
        self.run(&["pkey", "-in", "x25519.key", "-pubout", "-out", "x25519.pub"]);
        self.run(&["x509", "-new", "-subj", "/CN=x25519@example.com", "-force_pubkey", "x25519.pub", "-CA", "ed25519.crt", "-CAkey", "ed25519.key", "-days", "30", "-out", "x25519.crt"]);
    }

    fn entry(&self, alg: &str, purpose: &str, cert: &str, pkcs8: Option<&[u8]>) -> Value {
        json!({
            "alg": alg,
            "purpose": purpose,
            "cert_pem": self.text(cert),
            "spki_b64": "",
            "pkcs8_b64": pkcs8.map(b64),
        })
    }
}

impl Drop for Cli {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.work);
    }
}

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn bundle(entries: Vec<Value>) -> Vec<u8> {
    serde_json::to_vec(&json!({"v": 1, "entries": entries})).unwrap()
}

fn engine() -> CmsSmime {
    CmsSmime::new()
}

fn scomm_decrypts(cms: &[u8], key: &[u8], format: &str) -> std::result::Result<(), String> {
    let out = engine().decrypt(cms, key, None).map_err(|e| e.to_string())?;
    if out.plaintext != MSG {
        return Err("wrong plaintext".into());
    }
    if out.format != format {
        return Err(format!("format {} instead of {format}", out.format));
    }
    Ok(())
}

fn scomm_verifies(sig: &[u8], key: &[u8]) -> std::result::Result<(), String> {
    let result = engine().verify(MSG, sig, key).map_err(|e| e.to_string())?;
    match result.validity {
        SignatureValidity::CryptographicallyValid => Ok(()),
        other => Err(format!("{other:?}")),
    }
}

const OAEP: [&str; 2] = ["-keyopt", "rsa_padding_mode:oaep"];
const OAEP256: [&str; 4] = ["-keyopt", "rsa_padding_mode:oaep", "-keyopt", "rsa_oaep_md:sha256"];

#[test]
fn openssl_to_scomm() {
    let Some(cli) = Cli::start("inbound") else { return };
    cli.make_identities();
    let rsa_p8 = cli.read("rsa.p8");
    let rsa = bundle(vec![cli.entry("smime-rsa-oaep-sha256", "encryption", "rsa.crt", Some(&rsa_p8))]);
    let mut m = Matrix::default();

    // Each message is first opened by OpenSSL, so a bad recipe fails loudly here
    // instead of reading as an engine gap.
    let mut encrypted = |name: &str, recip: &str, inkey: &str, opts: &[&str], key: &[u8], format: &str, expect: common::Expect| {
        let mut args = vec!["cms", "-encrypt", "-binary", "-outform", "DER", "-in", "msg.bin", "-out", "m.cms"];
        args.extend_from_slice(opts);
        cli.run(&args);
        let plain = cli
            .try_run(&["cms", "-decrypt", "-binary", "-inform", "DER", "-in", "m.cms", "-recip", recip, "-inkey", inkey])
            .unwrap_or_else(|e| panic!("{name}: OpenSSL cannot read its own message: {e}"));
        assert_eq!(plain, MSG, "{name}");
        m.case(name, expect, scomm_decrypts(&cli.read("m.cms"), key, format));
    };
    let with = |cipher: &'static str, recip: &'static str, keyopts: &'static [&'static str]| -> Vec<&'static str> {
        let mut v = vec![cipher, "-recip", recip];
        v.extend_from_slice(keyopts);
        v
    };

    for (padding, keyopts) in [("PKCS#1 v1.5", &[][..]), ("OAEP-SHA1", &OAEP[..]), ("OAEP-SHA256", &OAEP256[..])] {
        for (cipher, opt, format) in [
            ("AES-128-CBC", "-aes128", FORMAT_F0_STD),
            ("AES-192-CBC", "-aes192", FORMAT_F0_STD),
            ("AES-256-CBC", "-aes256", FORMAT_F0_STD),
            ("AES-128-GCM AuthEnvelopedData", "-aes-128-gcm", FORMAT_F1),
            ("AES-192-GCM AuthEnvelopedData", "-aes-192-gcm", FORMAT_F1),
            ("AES-256-GCM AuthEnvelopedData", "-aes-256-gcm", FORMAT_F1),
        ] {
            let name = format!("RSA {padding}, {cipher}");
            encrypted(&name, "rsa.crt", "rsa.key", &with(opt, "rsa.crt", keyopts), &rsa, format, Works);
        }
    }
    encrypted("RSA OAEP-SHA256, BER indefinite length", "rsa.crt", "rsa.key", &[&["-stream"][..], &with("-aes256", "rsa.crt", &OAEP256)[..]].concat(), &rsa, FORMAT_F0_STD, Works);
    encrypted("RSA OAEP-SHA256, AES-256-GCM, BER indefinite length", "rsa.crt", "rsa.key", &[&["-stream"][..], &with("-aes-256-gcm", "rsa.crt", &OAEP256)[..]].concat(), &rsa, FORMAT_F1, Works);

    for (name, id, alg) in [
        ("ECDH P-256 KeyAgreeRecipientInfo", "p256", "smime-ecdh-p256"),
        ("ECDH P-384 KeyAgreeRecipientInfo", "p384", "smime-ecdh-p384"),
    ] {
        let (crt, key) = (format!("{id}.crt"), format!("{id}.key"));
        cli.run(&["pkcs8", "-topk8", "-nocrypt", "-in", &key, "-outform", "DER", "-out", "ec.p8"]);
        let p8 = cli.read("ec.p8");
        let key_bundle = bundle(vec![cli.entry(alg, "encryption", &crt, Some(&p8))]);
        let opts = vec!["-aes256".to_string(), "-recip".to_string(), crt.clone()];
        let refs: Vec<&str> = opts.iter().map(String::as_str).collect();
        encrypted(name, &crt, &key, &refs, &key_bundle, FORMAT_F0_STD, Gap("H1"));
    }

    // OpenSSL's CMS only does key agreement for "EC", "DH" and "DHX" keys, so it
    // cannot write RFC 8418 X25519. A Curve25519 S/MIME default has to build this
    // on OpenSSL's X25519. If this starts working, that work may be unnecessary.
    m.case(
        "OpenSSL itself writes X25519 KeyAgreeRecipientInfo (RFC 8418)",
        Gap("OpenSSL CMS"),
        cli.try_run(&["cms", "-encrypt", "-binary", "-outform", "DER", "-in", "msg.bin", "-out", "x.cms", "-aes256", "-recip", "x25519.crt"])
            .map(|_| ()),
    );

    for (name, id, alg, md) in [
        ("RSA SHA-256 SignedData", "rsa", "smime-rsa-pss-sha256", "sha256"),
        ("ECDSA P-256 SHA-256 SignedData", "p256", "smime-ecdsa-sha256", "sha256"),
        ("ECDSA P-384 SHA-384 SignedData", "p384", "smime-ecdsa-sha384", "sha384"),
        ("Ed25519 SHA-512 SignedData (RFC 8419)", "ed25519", "smime-ed25519", "sha512"),
    ] {
        let (crt, key) = (format!("{id}.crt"), format!("{id}.key"));
        cli.run(&["cms", "-sign", "-binary", "-md", md, "-signer", &crt, "-inkey", &key, "-outform", "DER", "-in", "msg.bin", "-out", "s.p7s"]);
        let public = bundle(vec![cli.entry(alg, "signing", &crt, None)]);
        m.case(&format!("detached {name}"), Works, scomm_verifies(&cli.read("s.p7s"), &public));
    }
    cli.run(&["cms", "-sign", "-binary", "-md", "sha512", "-signer", "mldsa.crt", "-inkey", "mldsa.key", "-outform", "DER", "-in", "msg.bin", "-out", "s.p7s"]);
    let mldsa = bundle(vec![cli.entry("pqc-mldsa65", "signing", "mldsa.crt", None)]);
    m.case("detached ML-DSA-65 SHA-512 SignedData (RFC 9882)", Works, scomm_verifies(&cli.read("s.p7s"), &mldsa));

    m.finish("OpenSSL to Scomm");
}

#[test]
fn scomm_to_openssl() {
    let Some(cli) = Cli::start("outbound") else { return };
    cli.make_identities();
    let mut m = Matrix::default();
    let generate = |profile, who: &str| {
        engine()
            .generate_key(&GenerateKeyOptions {
                userid: format!("{who} <{who}@example.com>"),
                passphrase: None,
                profile,
            })
            .expect("generate")
    };
    // Gaps the Release 2 writers close: open while the switch is off.
    let release_2 = |id| if scomm_smime_cms::RELEASE_2_WRITERS { Works } else { Gap(id) };
    let classical = generate(KeyProfile::Classical, "classical");
    let other = generate(KeyProfile::Classical, "other");
    let pqc = generate(KeyProfile::PqcCms, "pqc");

    let parses = |name: &str, data: &[u8]| {
        cli.write(name, data);
        cli.try_run(&["cms", "-cmsout", "-noout", "-inform", "DER", "-in", name]).map(|_| ())
    };
    let encrypt = |keys: &[&[u8]]| {
        engine()
            .encrypt(MSG, keys, &EncryptOptions { armored: false })
            .expect("encrypt")
    };
    m.case("X25519 message parses as CMS", release_2("C1"), parses("x.cms", &encrypt(&[&classical.public])));
    m.case("two X25519 recipients parse as CMS", release_2("C1"), parses("xx.cms", &encrypt(&[&classical.public, &other.public])));
    m.case("hybrid message parses as CMS", release_2("C1"), parses("h.cms", &encrypt(&[&pqc.public])));

    let rsa_public = bundle(vec![cli.entry("smime-rsa-oaep-sha256", "encryption", "rsa.crt", None)]);
    cli.write("r.cms", &encrypt(&[&rsa_public]));
    m.case(
        "RSA envelope opens in OpenSSL",
        release_2("H1"),
        cli.try_run(&["cms", "-decrypt", "-binary", "-inform", "DER", "-in", "r.cms", "-recip", "rsa.crt", "-inkey", "rsa.key"])
            .map(|_| ()),
    );

    let sign = |secret: &[u8], algorithm| {
        engine()
            .sign(MSG, secret, None, &SignOptions { detached: false, algorithm })
            .expect("sign")
    };
    let cert = |key: &GeneratedKey, alg: &str| {
        let v: Value = serde_json::from_slice(&key.public).unwrap();
        v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["alg"] == alg)
            .and_then(|e| e["cert_pem"].as_str())
            .unwrap()
            .to_string()
    };
    cli.write("alice.crt", cert(&classical, ALG_ED25519).as_bytes());
    cli.write("e.p7s", &sign(&classical.secret, ALG_ED25519));
    m.case(
        "Ed25519 signature verifies in OpenSSL",
        release_2("C1"),
        cli.try_run(&["cms", "-verify", "-binary", "-inform", "DER", "-in", "e.p7s", "-content", "msg.bin", "-noverify", "-certfile", "alice.crt"])
            .map(|_| ()),
    );
    m.case("ML-DSA-65 signature parses as CMS", release_2("H7"), parses("m.p7s", &sign(&pqc.secret, ALG_MLDSA65)));

    m.case(
        "self-issued Ed25519 certificate parses",
        Works,
        cli.try_run(&["x509", "-in", "alice.crt", "-noout", "-subject"]).map(|_| ()),
    );
    m.case(
        "self-issued certificate passes the S/MIME signing purpose",
        Works,
        cli.try_run(&["verify", "-x509_strict", "-purpose", "smimesign", "-CAfile", "alice.crt", "alice.crt"]).map(|_| ()),
    );

    m.finish("Scomm to OpenSSL");
}
