//! Q3 gate (task 2.1): known answers, round trip, OpenSSL CLI interop with the
//! exported KEK, and rejection of every bound field when tampered with.

use std::path::PathBuf;
use std::process::Command;

use super::*;
use crate::bundle::b64_decode;
use crate::cert::x25519_encrypt_entry;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

struct Key {
    scheme: Scheme,
    public: Vec<u8>,
    secret: Vec<u8>,
}

fn key(scheme: Scheme) -> Key {
    let entry = match scheme {
        Scheme::X25519 => x25519_encrypt_entry().unwrap(),
        Scheme::MlKem768X25519 => pqc::hybrid_encrypt_entry().unwrap(),
    };
    Key {
        scheme,
        public: b64_decode(&entry.spki_b64).unwrap(),
        secret: b64_decode(entry.pkcs8_b64.as_ref().unwrap()).unwrap(),
    }
}

fn plaintext() -> Vec<u8> {
    let mut p = vec![0u8; 4096];
    rand_bytes(&mut p).unwrap();
    p
}

fn seal(pt: &[u8], keys: &[&Key]) -> (Vec<u8>, Vec<Written>) {
    let recipients: Vec<Recipient> = keys
        .iter()
        .map(|k| Recipient {
            scheme: k.scheme,
            public: &k.public,
        })
        .collect();
    encrypt(pt, &recipients, &[]).unwrap()
}

fn open(der: &[u8], k: &Key) -> Result<Vec<u8>> {
    decrypt(der, k.scheme, &k.public, &k.secret)
}

/// Flips the low bit of the last byte of the only occurrence of `needle`.
fn flip(der: &[u8], needle: &[u8]) -> Vec<u8> {
    let hits: Vec<usize> = (0..=der.len() - needle.len())
        .filter(|&i| der[i..i + needle.len()] == *needle)
        .collect();
    assert_eq!(hits.len(), 1, "field {} must occur once", hex(needle));
    let mut out = der.to_vec();
    out[hits[0] + needle.len() - 1] ^= 0x01;
    out
}

#[test]
fn hkdf_matches_rfc5869_case_3() {
    let mut okm = [0u8; 42];
    hkdf_sha256(&[0x0b; 22], &[], &mut okm).unwrap();
    assert_eq!(
        hex(&okm),
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    );
}

#[test]
fn dhkem_matches_rfc9180_a_1_1() {
    let sk_r = unhex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");
    let enc = unhex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
    assert_eq!(
        hex(&x25519_public(&sk_r).unwrap()),
        "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d"
    );
    assert_eq!(
        hex(&x25519_decaps(&sk_r, &enc).unwrap().0),
        "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc"
    );
}

/// Task 2.5: RFC 9180 A.1.1 Encap with the vector's `ikmE`, and the matching
/// Decap, so both directions are pinned to the published values.
#[test]
fn dhkem_encap_matches_rfc9180_a_1_1() {
    let ikm_e = unhex("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234");
    let pk_r = unhex("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
    let enc = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431";
    let ss = "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc";
    let mut spki = X25519_SPKI_PREFIX.to_vec();
    spki.extend_from_slice(&pk_r);
    for public in [&pk_r, &spki] {
        let (got_ss, got_enc) = x25519_encaps_with(public, Some(&ikm_e)).unwrap();
        assert_eq!((hex(&got_enc).as_str(), hex(&got_ss.0).as_str()), (enc, ss));
    }
}

#[test]
fn x25519_recipient_key_must_be_raw_or_rfc8410_spki() {
    let pk = [9u8; 32];
    let mut spki = X25519_SPKI_PREFIX.to_vec();
    spki.extend_from_slice(&pk);
    assert_eq!(x25519_recipient_raw(&pk).unwrap(), pk);
    assert_eq!(x25519_recipient_raw(&spki).unwrap(), pk);
    let mut wrong_oid = spki.clone();
    wrong_oid[8] = 0x70; // Ed25519 (1.3.101.112), not X25519
    let mut longer = spki.clone();
    longer.push(0);
    for bad in [
        &pk[..31],
        &spki[..43],
        &longer[..],
        &wrong_oid[..],
        &[0u8; 44][..],
    ] {
        assert!(
            matches!(x25519_recipient_raw(bad), Err(SmimeError::InvalidKey(_))),
            "{}",
            hex(bad)
        );
    }
}

/// Low-order `enc` values give an all-zero DH result, which OpenSSL refuses
/// (RFC 9180 §7.1.4); the error is forwarded, never a predictable secret.
#[test]
fn dhkem_decap_refuses_low_order_points() {
    let sk_r = unhex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");
    let mut one = [0u8; 32];
    one[0] = 1;
    for enc in [[0u8; 32], one] {
        assert_eq!(
            x25519_decaps(&sk_r, &enc).err(),
            Some(SmimeError::DecryptionFailed),
            "{}",
            hex(&enc)
        );
    }
}

/// Task 2.6: the known answers below assume the pinned OpenSSL 4.1.
#[test]
fn linked_openssl_is_the_pinned_4_1() {
    let v = openssl::version::version();
    assert!(
        v.starts_with("OpenSSL 4.1."),
        "need OpenSSL 4.1, linked {v}"
    );
}

/// draft-ietf-lamps-pq-composite-kem-23, Appendix F, combiner example for
/// `id-MLKEM768-X25519-SHA3-256`.
#[test]
fn composite_combiner_matches_draft_23_appendix_f() {
    let ss = composite_combiner(
        &unhex("461b74b074818906edcd2fd976008caca5247f496670ae86e34abe35e62a7ae1"),
        &unhex("4c62bd6d6f76294f3c14d7e79dbf56e4bf82cb1fb803accfaf2a59c1663a8843"),
        &unhex("0ec7210a4aa22bb75af9243f95a6ccf857e872efbe5e77e8e917b56178fa473f"),
        &unhex("1e9d4f72d56cef589864e102c6d6fa86cd3ac5163839556f7555ad083f37b03b"),
    )
    .unwrap();
    assert_eq!(
        hex(&ss.0),
        "21ee673fdeac21dd78ef13bc8432a50c0ac31893cbe97d14c0e82f5fe4a28d98"
    );
}

/// draft -23 §3.5: an error in either component is returned, never a secret.
#[test]
fn hybrid_forwards_component_errors() {
    let k = key(Scheme::MlKem768X25519);
    let (_, good_ct) = hybrid_encaps(&k.public).unwrap();
    let x_at = pqc::MLKEM_EK_LEN;

    // X25519 half: a low-order tradPK (encaps) or tradCT (decaps).
    let mut low_pk = k.public.clone();
    low_pk[x_at..].fill(0);
    assert!(hybrid_encaps(&low_pk).is_err());
    let mut low_ct = good_ct.clone();
    low_ct[pqc::MLKEM_CT_LEN..].fill(0);
    assert_eq!(
        hybrid_decaps(&k.secret, &k.public, &low_ct).err(),
        Some(SmimeError::DecryptionFailed)
    );

    // ML-KEM half: an encapsulation key with coefficients >= q (FIPS 203 §7.2).
    let mut bad_ek = k.public.clone();
    bad_ek[..x_at].fill(0xff);
    assert!(matches!(
        hybrid_encaps(&bad_ek),
        Err(SmimeError::InvalidKey(_))
    ));

    // Sizes are checked before anything is split or decapsulated.
    for n in [0, pqc::MLKEM_CT_LEN, good_ct.len() - 1, good_ct.len() + 1] {
        let mut ct = good_ct.clone();
        ct.resize(n, 0);
        assert_eq!(
            hybrid_decaps(&k.secret, &k.public, &ct).err(),
            Some(SmimeError::MalformedMessage),
            "ciphertext length {n}"
        );
    }
    assert!(hybrid_encaps(&k.public[..k.public.len() - 1]).is_err());
}

#[test]
fn composite_kem_matches_draft_23_appendix_g() {
    use base64::Engine;
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/composite-kem/mlkem768-x25519-sha3-256.json");
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let b = |k: &str| {
        base64::engine::general_purpose::STANDARD
            .decode(v[k].as_str().unwrap())
            .unwrap()
    };
    let ss = hybrid_decaps(&b("dk"), &b("ek"), &b("c")).unwrap();
    assert_eq!(ss.0.to_vec(), b("k"));
}

/// Task 2.4: `evidence/kat_kek.py` builds the DER by hand from `design.md`
/// and runs RFC 5869 with hmac/hashlib; OpenSSL `asn1parse` reads its UKM.
#[test]
fn kek_derivation_matches_independent_vectors() {
    let ss = Secret(std::array::from_fn(|i| i as u8));
    let kek_id: Vec<u8> = (0xa0..0xb0).collect();
    let rkid = sha256(b"scomm kek kat recipient").unwrap();
    assert_eq!(
        hex(&rkid),
        "4d25c7ca32f94e9ee1161e0bf25479b29d84092251e4f7cec000a883ecb96a4c"
    );
    let cases = [
        (
            Scheme::X25519,
            "3073300b060960864801650304012d020120a061045f305d0c0f53636f6d6d2d434d532d4b454b5249\
             061369bbd5a881cd92aaa885b0bacd95ffc4dbdc250201010410a0a1a2a3a4a5a6a7a8a9aaabacadaeaf\
             04204d25c7ca32f94e9ee1161e0bf25479b29d84092251e4f7cec000a883ecb96a4c",
            "9efb0962d2e7853f66742f8055d97d353d0cf9c8759ebd6793b98846e00234c3",
        ),
        (
            Scheme::MlKem768X25519,
            "3074300b060960864801650304012d020120a0620460305e0c0f53636f6d6d2d434d532d4b454b5249\
             06146981888790f19bae8a94cf90a3cc989fd3d4d46e0201010410a0a1a2a3a4a5a6a7a8a9aaabacadaeaf\
             04204d25c7ca32f94e9ee1161e0bf25479b29d84092251e4f7cec000a883ecb96a4c",
            "13c2da9281aad70a71a8d87d2f44a37a504134b8b97c6581e7792cd0fd90855a",
        ),
    ];
    for (scheme, info, kek) in cases {
        assert_eq!(
            hex(&kdf_info(scheme, &kek_id, &rkid).unwrap()),
            info,
            "{scheme:?} info"
        );
        assert_eq!(
            hex(&derive_kek(&ss, scheme, &kek_id, &rkid).unwrap().0),
            kek,
            "{scheme:?} kek"
        );
    }
}

#[test]
fn kdf_refuses_identifiers_of_the_wrong_size() {
    let ss = Secret([7u8; 32]);
    for (kek_id, rkid) in [(15, 32), (17, 32), (16, 31), (16, 33), (0, 0)] {
        assert_eq!(
            derive_kek(&ss, Scheme::X25519, &vec![1u8; kek_id], &vec![2u8; rkid]).err(),
            Some(SmimeError::MalformedMessage),
            "kekId {kek_id}, recipientKeyId {rkid}"
        );
    }
}

#[test]
fn kek_binds_every_kdf_input() {
    let ss = Secret([7u8; 32]);
    let base = derive_kek(&ss, Scheme::X25519, &[1u8; 16], &[2u8; 32])
        .unwrap()
        .0;
    let variants = [
        derive_kek(&Secret([8u8; 32]), Scheme::X25519, &[1u8; 16], &[2u8; 32]),
        derive_kek(&ss, Scheme::MlKem768X25519, &[1u8; 16], &[2u8; 32]),
        derive_kek(&ss, Scheme::X25519, &[9u8; 16], &[2u8; 32]),
        derive_kek(&ss, Scheme::X25519, &[1u8; 16], &[9u8; 32]),
    ];
    for v in variants {
        assert_ne!(v.unwrap().0, base);
    }
}

#[test]
fn both_schemes_round_trip_in_one_message() {
    let (a, b, outsider) = (
        key(Scheme::X25519),
        key(Scheme::MlKem768X25519),
        key(Scheme::X25519),
    );
    let pt = plaintext();
    let (der, _) = seal(&pt, &[&a, &b]);
    assert_eq!(open(&der, &a).unwrap(), pt);
    assert_eq!(open(&der, &b).unwrap(), pt);
    assert_eq!(open(&der, &outsider), Err(SmimeError::WrongPrivateKey));
    // A hybrid key never opens the X25519 recipient and the reverse.
    let b_as_x25519 = Key {
        scheme: Scheme::X25519,
        public: b.public.clone(),
        secret: b.secret.clone(),
    };
    assert!(open(&der, &b_as_x25519).is_err());
}

/// The scheme attribute comes back from OpenSSL exactly as written.
#[test]
fn other_key_attribute_survives_round_trip() {
    let (a, b) = (key(Scheme::X25519), key(Scheme::MlKem768X25519));
    let (der, written) = seal(b"x", &[&a, &b]);
    let cms = CmsContentInfo::from_der(&der).unwrap();
    let mut seen = Vec::new();
    unsafe {
        assert_eq!(oid_text(CMS_get0_type(cms.as_ptr())), OID_AUTH_ENVELOPED);
        let stack = CMS_get0_RecipientInfos(cms.as_ptr());
        for i in 0..ffi::OPENSSL_sk_num(stack) {
            let ri = ffi::OPENSSL_sk_value(stack, i);
            assert_eq!(CMS_RecipientInfo_type(ri), CMS_RECIPINFO_KEK);
            let (mut alg, mut id, mut date, mut oid, mut other) = (
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            );
            assert_eq!(
                CMS_RecipientInfo_kekri_get0_id(
                    ri, &mut alg, &mut id, &mut date, &mut oid, &mut other
                ),
                1
            );
            let mut attr = vec![0u8; ffi::i2d_ASN1_TYPE(other, ptr::null_mut()) as usize];
            ffi::i2d_ASN1_TYPE(other, &mut attr.as_mut_ptr());
            let kek_id = std::slice::from_raw_parts(ffi::ASN1_STRING_get0_data(id), 16).to_vec();
            seen.push((oid_text(oid), kek_id, parse_recipient_attr(&attr).unwrap()));
        }
    }
    for (k, w) in [(&a, &written[0]), (&b, &written[1])] {
        let expected = (
            k.scheme.oid().to_str().unwrap().to_string(),
            w.kek_id.to_vec(),
            (
                sha256(&k.public).unwrap().to_vec(),
                w.kem_ciphertext.clone(),
            ),
        );
        assert!(
            seen.contains(&expected),
            "{:?} recipient not found",
            k.scheme
        );
    }
    assert_eq!(written[0].kem_ciphertext.len(), 32);
    assert_eq!(written[1].kem_ciphertext.len(), 1120);
}

#[test]
fn every_bound_field_rejects_tampering() {
    let wrap_alg_then_key = unhex("300b060960864801650304012d0428");
    for scheme in [Scheme::X25519, Scheme::MlKem768X25519] {
        let k = key(scheme);
        let pt = plaintext();
        let (der, written) = seal(&pt, &[&k]);
        let w = &written[0];
        let ct = &w.kem_ciphertext;
        let wrapped_at = der
            .windows(wrap_alg_then_key.len())
            .position(|x| x == wrap_alg_then_key)
            .unwrap()
            + wrap_alg_then_key.len();
        let mut cases: Vec<(&str, Vec<u8>, SmimeError)> = vec![
            ("kekid", flip(&der, &w.kek_id), SmimeError::WrongPrivateKey),
            (
                "scheme OID",
                flip(&der, &scheme.der().unwrap()),
                SmimeError::WrongPrivateKey,
            ),
            (
                "recipientKeyId",
                flip(&der, &sha256(&k.public).unwrap()),
                SmimeError::WrongPrivateKey,
            ),
            (
                "wrapped key",
                flip(&der, &der[wrapped_at..wrapped_at + 40]),
                SmimeError::WrongPrivateKey,
            ),
            (
                "GCM tag",
                flip(&der, &der[der.len() - 16..]),
                SmimeError::DecryptionFailed,
            ),
            (
                "ciphertext",
                flip(&der, &der[der.len() - 80..der.len() - 60]),
                SmimeError::DecryptionFailed,
            ),
        ];
        match scheme {
            Scheme::X25519 => cases.push(("enc", flip(&der, ct), SmimeError::WrongPrivateKey)),
            Scheme::MlKem768X25519 => {
                cases.push((
                    "ML-KEM ct",
                    flip(&der, &ct[..64]),
                    SmimeError::WrongPrivateKey,
                ));
                cases.push((
                    "X25519 ct",
                    flip(&der, &ct[1088..]),
                    SmimeError::WrongPrivateKey,
                ));
            }
        }
        assert_eq!(open(&der, &k).unwrap(), pt);
        for (field, tampered, expected) in cases {
            assert_eq!(open(&tampered, &k), Err(expected), "{scheme:?}: {field}");
        }
    }
}

/// D5. OpenSSL 3.x streamed AuthEnvelopedData plaintext to the output before
/// checking the GCM tag (the 3.5.6 CLI wrote all 270,177 bytes of a forged
/// message). The pinned 4.1.0 holds it in memory until the tag verifies
/// (`cms_copy_content`). This pins that behavior, and the engine refuses on
/// its own as well.
#[test]
fn bad_tag_releases_no_plaintext() {
    let k = key(Scheme::X25519);
    let mut pt = vec![0u8; 300_000];
    rand_bytes(&mut pt).unwrap();
    let (der, _) = seal(&pt, &[&k]);
    let tampered = flip(&der, &der[der.len() - 16..]);

    let cms = CmsContentInfo::from_der(&tampered).unwrap();
    let my_key_id = sha256(&k.public).unwrap();
    let (ok, leaked) = unsafe {
        let ri = ffi::OPENSSL_sk_value(CMS_get0_RecipientInfos(cms.as_ptr()), 0);
        open_recipient(&cms, ri, k.scheme, &my_key_id, &k.public, &k.secret).unwrap();
        let out = ffi::BIO_new(ffi::BIO_s_mem());
        let ok = ffi::CMS_decrypt(
            cms.as_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            out,
            ffi::CMS_BINARY,
        );
        let mut data: *mut c_char = ptr::null_mut();
        let n = ffi::BIO_get_mem_data(out, &mut data);
        let leaked = if n > 0 {
            std::slice::from_raw_parts(data as *const u8, n as usize).to_vec()
        } else {
            Vec::new()
        };
        BIO_free(out);
        let _ = ErrorStack::get();
        (ok, leaked)
    };
    println!(
        "OpenSSL CMS_decrypt returned {ok} after writing {} of {} bytes",
        leaked.len(),
        pt.len()
    );
    assert_eq!(ok, 0, "OpenSSL reports the bad tag");
    assert!(
        leaked.is_empty(),
        "OpenSSL released {} unverified bytes",
        leaked.len()
    );
    assert_eq!(open(&tampered, &k), Err(SmimeError::DecryptionFailed));
}

fn cli() -> Option<String> {
    let required = std::env::var_os("SCOMM_INTEROP_REQUIRE_TOOLS").is_some();
    let bin = std::env::var("SCOMM_OPENSSL_CLI").unwrap_or_else(|_| "openssl".into());
    match Command::new(&bin).arg("version").output() {
        Ok(out) if out.status.success() => {
            println!("{}", String::from_utf8_lossy(&out.stdout).trim());
            Some(bin)
        }
        _ => {
            assert!(!required, "{bin} is required but not usable");
            println!("skipped: {bin} not usable here");
            None
        }
    }
}

/// The CMS layer is standard: the OpenSSL CLI opens engine output when given
/// only the derived KEK and its key identifier, and shows the attribute.
#[test]
fn openssl_cli_opens_engine_output_with_exported_kek() {
    let Some(bin) = cli() else { return };
    let dir = std::env::temp_dir().join(format!("scomm-kekri-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (a, b) = (key(Scheme::X25519), key(Scheme::MlKem768X25519));
    let pt = plaintext();
    let (der, written) = seal(&pt, &[&a, &b]);
    let msg = dir.join("msg.der");
    std::fs::write(&msg, &der).unwrap();
    let run = |args: &[&str]| Command::new(&bin).args(args).output().unwrap();

    let printed = run(&[
        "cms",
        "-cmsout",
        "-print",
        "-inform",
        "DER",
        "-in",
        msg.to_str().unwrap(),
    ]);
    let printed = String::from_utf8_lossy(&printed.stdout);
    assert!(printed.contains("authEnvelopedData"), "{printed}");
    for k in [&a, &b] {
        assert!(
            printed.contains(k.scheme.oid().to_str().unwrap()),
            "{printed}"
        );
    }

    for w in &written {
        let out = dir.join("pt.bin");
        let _ = std::fs::remove_file(&out);
        let r = run(&[
            "cms",
            "-decrypt",
            "-binary",
            "-inform",
            "DER",
            "-in",
            msg.to_str().unwrap(),
            "-secretkey",
            &hex(&w.kek),
            "-secretkeyid",
            &hex(&w.kek_id),
            "-out",
            out.to_str().unwrap(),
        ]);
        assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stderr));
        assert_eq!(std::fs::read(&out).unwrap(), pt);
    }

    let mut wrong = written[0].kek;
    wrong[0] ^= 1;
    let r = run(&[
        "cms",
        "-decrypt",
        "-binary",
        "-inform",
        "DER",
        "-in",
        msg.to_str().unwrap(),
        "-secretkey",
        &hex(&wrong),
        "-secretkeyid",
        &hex(&written[0].kek_id),
        "-out",
        dir.join("wrong.bin").to_str().unwrap(),
    ]);
    assert!(!r.status.success(), "a wrong KEK must not open the message");
    let _ = std::fs::remove_dir_all(&dir);
}

// Task 2.7: KEKRI reader routed through the engine, and the F1 writer.

use crate::bundle::{b64_encode, KeyBundle, KeyEntry};
use crate::classify::{classify, Kind, Recipient as Ri};
use crate::CmsSmime;

/// RSA encryption entry with a self-signed certificate, as other clients'
/// and imported RSA keys are stored.
fn rsa_entry() -> (KeyEntry, openssl::pkey::PKey<openssl::pkey::Private>) {
    use openssl::{asn1::Asn1Time, bn::BigNum, pkey::PKey, rsa::Rsa, x509::X509Name};
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_text("CN", "f1 rsa").unwrap();
    let name = name.build();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    // KTRI names its recipient by issuer and serial, so every identity needs
    // its own serial or OpenSSL takes one for the other (design.md D2).
    let mut serial = BigNum::new().unwrap();
    serial
        .rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)
        .unwrap();
    b.set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    let entry = KeyEntry {
        alg: ALG_RSA_OAEP.into(),
        purpose: "encryption".into(),
        cert_pem: String::from_utf8(b.build().to_pem().unwrap()).unwrap(),
        spki_b64: String::new(),
        pkcs8_b64: Some(b64_encode(&key.private_key_to_pkcs8().unwrap())),
        legacy_key_ids: Vec::new(),
    };
    (entry, key)
}

fn bundle_json(entries: &[&KeyEntry], secret: bool) -> Vec<u8> {
    let b = KeyBundle {
        v: 1,
        entries: entries.iter().map(|e| (*e).clone()).collect(),
    };
    if secret {
        b.to_secret_json().unwrap()
    } else {
        b.to_public_json().unwrap()
    }
}

fn engine_decrypt(der: &[u8], secret: &[&KeyEntry]) -> Result<DecryptResult> {
    CmsSmime::new().decrypt(der, &bundle_json(secret, true), None)
}

#[test]
#[allow(clippy::assertions_on_constants)] // fails on purpose when Release 2 flips it
fn release_1_still_writes_f0_scomm() {
    assert!(
        !crate::RELEASE_2_WRITERS,
        "the F1 writer is switched on only in Release 2"
    );
    let x = x25519_encrypt_entry().unwrap();
    let der = CmsSmime::new()
        .encrypt(
            b"release 1",
            &[&bundle_json(&[&x], false)],
            &EncryptOptions { armored: false },
        )
        .unwrap();
    assert!(matches!(
        classify(&der).unwrap().kind,
        Kind::Enveloped {
            authenticated: false,
            ..
        }
    ));
    assert_eq!(engine_decrypt(&der, &[&x]).unwrap().format, FORMAT_F0_SCOMM);
}

#[test]
fn f1_writer_mixes_rsa_and_kem_recipients_and_each_opens_it() {
    let x = x25519_encrypt_entry().unwrap();
    let h = pqc::hybrid_encrypt_entry().unwrap();
    let (r, _) = rsa_entry();
    let pt = plaintext();
    let der = encrypt_entries(&pt, &[&x, &h, &r]).unwrap();

    // DER sorts the RecipientInfos SET OF, so KTRI comes first.
    assert_eq!(
        classify(&der).unwrap().kind,
        Kind::Enveloped {
            authenticated: true,
            recipients: vec![
                Ri::KeyTransport,
                Ri::ScommKem(Scheme::X25519),
                Ri::ScommKem(Scheme::MlKem768X25519),
            ],
        }
    );
    for (entry, alg) in [(&x, ALG_X25519), (&h, ALG_MLKEM_HYBRID), (&r, ALG_RSA_OAEP)] {
        let out = engine_decrypt(&der, &[entry]).unwrap();
        assert_eq!(out.plaintext, pt, "{alg}");
        assert_eq!(
            (out.format.as_str(), out.algorithm.as_str()),
            (FORMAT_F1, alg)
        );
    }
    // A bundle holding a non-recipient key next to the right one still opens.
    let outsider = x25519_encrypt_entry().unwrap();
    assert_eq!(
        engine_decrypt(&der, &[&outsider, &h]).unwrap().plaintext,
        pt
    );

    let info = CmsSmime::new().inspect_message(&der).unwrap();
    assert!(info.encrypted && info.pqc && info.classical_recipient);
}

#[test]
fn f1_reader_reports_no_key_and_bad_content_apart() {
    let x = x25519_encrypt_entry().unwrap();
    let (r, _) = rsa_entry();
    let (other_rsa, _) = rsa_entry();
    let der = encrypt_entries(b"apart", &[&x, &r]).unwrap();

    let outsider = x25519_encrypt_entry().unwrap();
    assert_eq!(
        engine_decrypt(&der, &[&outsider, &other_rsa]).err(),
        Some(SmimeError::WrongPrivateKey)
    );
    // The right keys, but the GCM tag (last 16 bytes) is broken.
    let mut bad = der.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    for entry in [&x, &r] {
        assert_eq!(
            engine_decrypt(&bad, &[entry]).err(),
            Some(SmimeError::DecryptionFailed)
        );
    }
}

#[test]
fn f1_writer_refuses_a_recipient_it_cannot_serve() {
    let mut no_cert = rsa_entry().0;
    no_cert.cert_pem.clear();
    let ed = crate::cert::ed25519_sign_entry("a@example.com").unwrap();
    for e in [&no_cert, &ed] {
        assert_eq!(
            encrypt_entries(b"x", &[e]).err(),
            Some(SmimeError::NoSuitableEncryptionKey)
        );
    }
}

/// The RSA recipient is RSAES-OAEP with SHA-256 for both hash and MGF1, and
/// a stock OpenSSL opens it with nothing but the certificate and key.
#[test]
fn f1_rsa_recipient_is_oaep_sha256_and_openssl_cli_opens_it() {
    let Some(bin) = cli() else { return };
    let dir = std::env::temp_dir().join(format!("scomm-f1-rsa-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (r, key) = rsa_entry();
    let pt = plaintext();
    let msg = dir.join("msg.der");
    std::fs::write(&msg, encrypt_entries(&pt, &[&r]).unwrap()).unwrap();
    let cert = dir.join("cert.pem");
    std::fs::write(&cert, &r.cert_pem).unwrap();
    let key_path = dir.join("key.pem");
    std::fs::write(&key_path, key.private_key_to_pem_pkcs8().unwrap()).unwrap();
    let run = |args: &[&str]| Command::new(&bin).args(args).output().unwrap();

    let printed = run(&[
        "cms",
        "-cmsout",
        "-print",
        "-inform",
        "DER",
        "-in",
        msg.to_str().unwrap(),
    ]);
    let printed = String::from_utf8_lossy(&printed.stdout).to_string();
    assert!(printed.contains("authEnvelopedData"), "{printed}");
    assert!(printed.contains("rsaesOaep"), "{printed}");
    assert!(printed.contains("mgf1"), "{printed}");
    assert!(printed.matches("sha256").count() >= 2, "{printed}");
    assert!(!printed.contains("sha1"), "{printed}");

    let out = dir.join("pt.bin");
    let r = run(&[
        "cms",
        "-decrypt",
        "-binary",
        "-inform",
        "DER",
        "-in",
        msg.to_str().unwrap(),
        "-recip",
        cert.to_str().unwrap(),
        "-inkey",
        key_path.to_str().unwrap(),
        "-out",
        out.to_str().unwrap(),
    ]);
    assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stderr));
    assert_eq!(std::fs::read(&out).unwrap(), pt);
    let _ = std::fs::remove_dir_all(&dir);
}

// Task 2.8: tamper, wrong-key, wrong-recipient, malformed and downgrade tests
// on F1 through the engine (design.md "Testing strategy", P2, P5).

/// aes-256-gcm, aes-256-wrap: `06 09 2.16.840.1.101.3.4.1.{46,45}`.
const GCM256_OID: [u8; 11] = [6, 9, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 1, 0x2e];
const WRAP256_OID: [u8; 11] = [6, 9, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 1, 0x2d];
/// id-ct-authEnvelopedData and id-envelopedData as DER OIDs.
const AUTH_ENVELOPED_OID: [u8; 13] = [6, 11, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 16, 1, 23];
const ENVELOPED_OID: [u8; 11] = [6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 3];

/// Offset of the only occurrence of `needle`.
fn find_once(der: &[u8], needle: &[u8]) -> usize {
    let hits: Vec<usize> = (0..=der.len() - needle.len())
        .filter(|&i| der[i..i + needle.len()] == *needle)
        .collect();
    assert_eq!(hits.len(), 1, "{} must occur once", hex(needle));
    hits[0]
}

fn with_byte(der: &[u8], at: usize, value: u8) -> Vec<u8> {
    let mut out = der.to_vec();
    out[at] = value;
    out
}

/// One F1 message to an X25519, a hybrid and an RSA recipient, small enough
/// to sweep byte by byte.
fn mixed_message() -> (Vec<u8>, Vec<u8>, [KeyEntry; 3]) {
    let x = x25519_encrypt_entry().unwrap();
    let h = pqc::hybrid_encrypt_entry().unwrap();
    let (r, _) = rsa_entry();
    let pt = b"f1 sweep plaintext, 64 bytes long ........................ end".to_vec();
    let der = encrypt_entries(&pt, &[&x, &h, &r]).unwrap();
    (der, pt, [x, h, r])
}

/// Every prefix is refused, and no single-bit change anywhere yields
/// plaintext other than the original. Changes from the content-encryption
/// algorithm on (OID, nonce, content, tag) are refused, with one exception
/// pinned here: OpenSSL 4.1 checks the tag with the length of `mac` and does
/// not enforce RFC 5084's ICVlen range, so ICVlen 16 -> 17 still opens the
/// authentic content. If that ever changes, this test says so.
#[test]
fn f1_truncation_and_bit_flips_never_release_other_plaintext() {
    let (der, pt, entries) = mixed_message();
    let content_from = find_once(&der, &GCM256_OID);
    let icv_len_at = find_once(&der, &[0x30, 0x11, 0x04, 0x0c]) + 4 + 12 + 2;
    assert_eq!(der[icv_len_at], 0x10);
    for entry in &entries {
        for cut in 0..der.len() {
            assert!(
                engine_decrypt(&der[..cut], &[entry]).is_err(),
                "{} opened a {cut}-byte prefix",
                entry.alg
            );
        }
        for i in 0..der.len() {
            let flipped = with_byte(&der, i, der[i] ^ 0x01);
            if let Ok(out) = engine_decrypt(&flipped, &[entry]) {
                assert_eq!(out.plaintext, pt, "{}: byte {i}", entry.alg);
                assert!(
                    i < content_from || i == icv_len_at,
                    "{}: byte {i} is authenticated",
                    entry.alg
                );
            }
        }
    }
}

/// P5: an F1 message cannot be turned into an unauthenticated one.
#[test]
fn f1_downgrade_attempts_are_refused() {
    let (der, _, entries) = mixed_message();
    let gcm = find_once(&der, &GCM256_OID) + GCM256_OID.len() - 1;

    // Same content-encryption key, weaker or different algorithm.
    let to_cbc = with_byte(&der, gcm, 0x2a); // aes-256-cbc
    let to_gcm128 = with_byte(&der, gcm, 0x06); // aes-128-gcm

    // AuthEnvelopedData relabelled as EnvelopedData: swap the content type
    // OID (2 bytes shorter) and shrink the outer SEQUENCE length to match.
    let at = find_once(&der, &AUTH_ENVELOPED_OID);
    assert_eq!(&der[..2], &[0x30, 0x82], "outer length is two bytes");
    let mut relabelled = der[..at].to_vec();
    relabelled.extend_from_slice(&ENVELOPED_OID);
    relabelled.extend_from_slice(&der[at + AUTH_ENVELOPED_OID.len()..]);
    let outer = u16::from_be_bytes([der[2], der[3]]) - 2;
    relabelled[2..4].copy_from_slice(&outer.to_be_bytes());

    for (name, tampered) in [
        ("aes-256-cbc", &to_cbc),
        ("aes-128-gcm", &to_gcm128),
        ("EnvelopedData", &relabelled),
    ] {
        for entry in &entries {
            let got = engine_decrypt(tampered, &[entry]);
            assert!(got.is_err(), "{name} opened for {}", entry.alg);
        }
    }
}

/// Algorithm identifiers and parameters the reader does not accept.
#[test]
fn f1_wrong_oids_and_parameters_are_refused() {
    for entry in [
        x25519_encrypt_entry().unwrap(),
        pqc::hybrid_encrypt_entry().unwrap(),
    ] {
        let der = encrypt_entries(b"parameters", &[&entry]).unwrap();
        assert!(engine_decrypt(&der, &[&entry]).is_ok());

        let wrap = find_once(&der, &WRAP256_OID) + WRAP256_OID.len() - 1;
        let aes192_wrap = with_byte(&der, wrap, 0x19);
        // GCMParameters ::= SEQUENCE { nonce OCTET STRING (12), ICVlen INTEGER 16 }
        let params = find_once(&der, &[0x30, 0x11, 0x04, 0x0c]) + 4 + 12;
        assert_eq!(&der[params..params + 3], &[0x02, 0x01, 0x10]);
        // OpenSSL 4.1 checks the tag with the length of `mac` and ignores
        // ICVlen; the engine bounds `mac` itself (f1_short_gcm_tag_is_refused),
        // so a wrong ICVlen alone still yields only the authentic content.
        let icv_12 = with_byte(&der, params + 2, 0x0c);
        assert_eq!(
            engine_decrypt(&icv_12, &[&entry]).unwrap().plaintext,
            b"parameters"
        );
        // ScommKemRecipient version 2.
        let rkid = sha256(&b64_decode(&entry.spki_b64).unwrap()).unwrap();
        let mut version_rkid = vec![0x02, 0x01, 0x01, 0x04, 0x20];
        version_rkid.extend_from_slice(&rkid);
        let version = find_once(&der, &version_rkid) + 2;
        let version_2 = with_byte(&der, version, 0x02);

        // Our own recipient with a bad field counts as "no recipient opened"
        // (D4), so these report WrongPrivateKey, before any key is used.
        for (name, tampered) in [("aes192-wrap", aes192_wrap), ("version 2", version_2)] {
            assert_eq!(
                engine_decrypt(&tampered, &[&entry]).err(),
                Some(SmimeError::WrongPrivateKey),
                "{}: {name}",
                entry.alg
            );
        }
    }
}

/// A recipient opens only its own RecipientInfo: another key of the same
/// scheme, a key of the other scheme, or a recipientKeyId pointed at a
/// different key all fail with WrongPrivateKey.
#[test]
fn f1_wrong_recipient_is_wrong_private_key() {
    let a_x = x25519_encrypt_entry().unwrap();
    let a_h = pqc::hybrid_encrypt_entry().unwrap();
    let (a_r, _) = rsa_entry();
    let der = encrypt_entries(b"for a only", &[&a_x, &a_h, &a_r]).unwrap();

    let b_x = x25519_encrypt_entry().unwrap();
    let b_h = pqc::hybrid_encrypt_entry().unwrap();
    let (b_r, _) = rsa_entry();
    for b in [&b_x, &b_h, &b_r] {
        assert_eq!(
            engine_decrypt(&der, &[b]).err(),
            Some(SmimeError::WrongPrivateKey),
            "{}",
            b.alg
        );
    }

    // A's X25519 recipient relabelled with B's recipientKeyId: B derives a
    // different KEK, so the AES key unwrap fails; A no longer finds its id.
    let single = encrypt_entries(b"relabelled", &[&a_x]).unwrap();
    let id = |e: &KeyEntry| sha256(&b64_decode(&e.spki_b64).unwrap()).unwrap();
    let at = find_once(&single, &id(&a_x));
    let mut relabelled = single.clone();
    relabelled[at..at + 32].copy_from_slice(&id(&b_x));
    for who in [&a_x, &b_x] {
        assert_eq!(
            engine_decrypt(&relabelled, &[who]).err(),
            Some(SmimeError::WrongPrivateKey)
        );
    }
}

/// Re-encodes `der` with the trailing `mac` cut to `n` bytes (a truncated
/// GCM tag is the leftmost bytes of the full one, SP 800-38D 5.2.1.2).
fn with_short_mac(der: &[u8], n: usize) -> Vec<u8> {
    let mac_at = der.len() - 18;
    assert_eq!(&der[mac_at..mac_at + 2], &[0x04, 0x10]);
    let cut = 16 - n;
    let mut out = der[..mac_at].to_vec();
    out.extend_from_slice(&[0x04, n as u8]);
    out.extend_from_slice(&der[mac_at + 2..mac_at + 2 + n]);
    // ContentInfo, [0] EXPLICIT, AuthEnvelopedData: all 2-byte lengths.
    // Offsets: SEQUENCE header (4) + content type OID (13), then [0] (4).
    for at in [0usize, 17, 21] {
        assert_eq!(der[at + 1], 0x82, "two-byte length at {at}");
        let len = u16::from_be_bytes([out[at + 2], out[at + 3]]) - cut as u16;
        out[at + 2..at + 4].copy_from_slice(&len.to_be_bytes());
    }
    out
}

/// A GCM tag cut below RFC 5084's 12 bytes is refused on every path (RSA
/// KTRI and both KEKRI schemes) even though OpenSSL 4.1 would accept it
/// down to 4 bytes; 12 to 16 bytes still open (SP 800-38D truncation).
#[test]
fn f1_short_gcm_tag_is_refused() {
    let (der, pt, entries) = mixed_message();
    for entry in &entries {
        for n in [16usize, 15, 12] {
            let out = engine_decrypt(&with_short_mac(&der, n), &[entry]).unwrap();
            assert_eq!(out.plaintext, pt, "{}: {n}-byte tag", entry.alg);
        }
        for n in [11usize, 8, 4, 1] {
            assert_eq!(
                engine_decrypt(&with_short_mac(&der, n), &[entry]).err(),
                Some(SmimeError::DecryptionFailed),
                "{}: {n}-byte tag",
                entry.alg
            );
        }
    }
}
