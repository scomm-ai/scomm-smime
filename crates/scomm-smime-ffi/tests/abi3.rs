//! ABI 3 symbols (task 3.6) through the C ABI: verdict JSON, detached
//! signing, certificate info, trust roots, certificate check, ML-DSA
//! migration and decrypt with format.

use std::ptr;

use scomm_smime::*;
use serde_json::Value;

/// Calls `f(out, out_len)` and returns (code, bytes) with the buffer freed.
fn take(f: impl FnOnce(*mut *mut u8, *mut usize) -> i32) -> (i32, Vec<u8>) {
    let mut out = ptr::null_mut();
    let mut len = 0usize;
    let code = f(&mut out, &mut len);
    let bytes = if out.is_null() {
        Vec::new()
    } else {
        let v = unsafe { std::slice::from_raw_parts(out, len) }.to_vec();
        unsafe { scomm_smime_buffer_free(out, len) };
        v
    };
    (code, bytes)
}

fn json(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}

/// A generated post-quantum key: Ed25519 and ML-DSA signing entries.
fn pqc_key() -> (Vec<u8>, Vec<u8>) {
    pqc_key_for(b"Dana <dana@example.com>")
}

/// [pqc_key] for [userid]; without an address the ML-DSA entry is made
/// bare, as keys from older builds are, so the migration has work to do.
fn pqc_key_for(userid: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (mut p, mut pl, mut s, mut sl, mut j, mut jl) =
        (ptr::null_mut(), 0, ptr::null_mut(), 0, ptr::null_mut(), 0);
    let code = unsafe {
        scomm_smime_generate(
            userid.as_ptr(),
            userid.len(),
            ptr::null(),
            0,
            1,
            &mut p,
            &mut pl,
            &mut s,
            &mut sl,
            &mut j,
            &mut jl,
        )
    };
    assert_eq!(code, 0);
    let copy = |ptr: *mut u8, len| {
        let v = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
        unsafe { scomm_smime_buffer_free(ptr, len) };
        v
    };
    let out = (copy(p, pl), copy(s, sl));
    copy(j, jl);
    out
}

const DATA: &[u8] = b"abi 3 data";

#[test]
fn abi_is_6_and_every_symbol_is_linked() {
    assert_eq!(scomm_smime_abi_version(), 6);
    assert_ne!(link_anchor(), 0);
}

/// ABI 5: the lifetime reaches the certificate; out-of-range years fail.
#[test]
fn generate_with_validity_sets_the_certificate_lifetime() {
    let generate = |years: u32| {
        let userid = b"Dana <dana@example.com>";
        let (mut p, mut pl, mut s, mut sl, mut j, mut jl) =
            (ptr::null_mut(), 0, ptr::null_mut(), 0, ptr::null_mut(), 0);
        let code = unsafe {
            scomm_smime_generate_with_validity(
                userid.as_ptr(),
                userid.len(),
                ptr::null(),
                0,
                0,
                years,
                &mut p,
                &mut pl,
                &mut s,
                &mut sl,
                &mut j,
                &mut jl,
            )
        };
        for (ptr, len) in [(p, pl), (s, sl), (j, jl)] {
            if !ptr.is_null() {
                unsafe { scomm_smime_buffer_free(ptr, len) };
            }
        }
        code
    };
    assert_eq!(generate(3), 0);
    assert_ne!(generate(11), 0);
}

/// ABI 4: profiles 2 and 3 give single-entry bundles, and
/// `scomm_smime_remove_entries` drops a named entry through the C ABI.
#[test]
fn pqc_only_profiles_and_remove_entries() {
    let generate = |profile: i32| {
        let userid = b"Dana <dana@example.com>";
        let (mut p, mut pl, mut s, mut sl, mut j, mut jl) =
            (ptr::null_mut(), 0, ptr::null_mut(), 0, ptr::null_mut(), 0);
        let code = unsafe {
            scomm_smime_generate(
                userid.as_ptr(), userid.len(), ptr::null(), 0, profile,
                &mut p, &mut pl, &mut s, &mut sl, &mut j, &mut jl,
            )
        };
        assert_eq!(code, 0, "profile {profile}");
        let secret = unsafe { std::slice::from_raw_parts(s, sl) }.to_vec();
        unsafe {
            scomm_smime_buffer_free(p, pl);
            scomm_smime_buffer_free(s, sl);
            scomm_smime_buffer_free(j, jl);
        }
        secret
    };
    let algs = |bundle: &[u8]| -> Vec<String> {
        json(bundle)["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["alg"].as_str().unwrap().to_string())
            .collect()
    };
    assert_eq!(algs(&generate(2)), vec!["smime-mlkem768-x25519"]);
    assert_eq!(algs(&generate(3)), vec!["pqc-mldsa65"]);

    let (_, legacy) = pqc_key();
    let spki = json(&legacy)["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["alg"] == "smime-mlkem768-x25519")
        .unwrap()["spki_b64"]
        .clone();
    let spkis = serde_json::to_vec(&vec![spki]).unwrap();
    let (code, trimmed) = take(|o, l| unsafe {
        scomm_smime_remove_entries(
            legacy.as_ptr(), legacy.len(), spkis.as_ptr(), spkis.len(), o, l,
        )
    });
    assert_eq!(code, 0);
    assert_eq!(
        algs(&trimmed),
        vec!["smime-x25519", "smime-ed25519", "pqc-mldsa65"]
    );

    let (code, _) = take(|o, l| unsafe {
        scomm_smime_remove_entries(legacy.as_ptr(), legacy.len(), b"not json".as_ptr(), 8, o, l)
    });
    assert_ne!(code, 0, "a bad spki list is refused");
}

#[test]
fn sign_detached_then_verify_detached() {
    let (public, secret) = pqc_key();
    let alg = b"smime-ed25519";
    let (code, sig) = take(|o, l| unsafe {
        scomm_smime_sign_detached(
            DATA.as_ptr(),
            DATA.len(),
            secret.as_ptr(),
            secret.len(),
            ptr::null(),
            0,
            alg.as_ptr(),
            alg.len(),
            o,
            l,
        )
    });
    assert_eq!(code, 0);
    let sender = b"dana@example.com";
    let (code, verdict) = take(|o, l| unsafe {
        scomm_smime_verify_detached(
            DATA.as_ptr(),
            DATA.len(),
            sig.as_ptr(),
            sig.len(),
            public.as_ptr(),
            public.len(),
            sender.as_ptr(),
            sender.len(),
            o,
            l,
        )
    });
    assert_eq!(code, 0);
    let v = json(&verdict);
    assert_eq!(v["validity"], "valid");
    // Ed25519 is S1 once the Release 2 switch is on, S0 before.
    let s1 = scomm_smime_cms::RELEASE_2_WRITERS;
    assert_eq!(v["format"], if s1 { "s1" } else { "s0" });
    // S1 carries its self-signed certificate; S0 carries none.
    assert_eq!(v["chain"], if s1 { "untrusted-root" } else { "no-chain" });
    assert_eq!(v["revocation"], "not-checked");
    assert_eq!(v["signer_fingerprint"].as_str().unwrap().len(), 64);

    let (mut details_ptr, mut details_len) = (ptr::null_mut(), 0);
    let (code, new_verdict) = take(|o, l| unsafe {
        scomm_smime_verify_detached_with_details_v1(
            DATA.as_ptr(),
            DATA.len(),
            sig.as_ptr(),
            sig.len(),
            public.as_ptr(),
            public.len(),
            sender.as_ptr(),
            sender.len(),
            o,
            l,
            &mut details_ptr,
            &mut details_len,
        )
    });
    assert_eq!(code, 0);
    assert_eq!(json(&new_verdict), v);
    assert!(!details_ptr.is_null());
    let details = unsafe {
        let result = json(std::slice::from_raw_parts(details_ptr, details_len));
        scomm_smime_buffer_free(details_ptr, details_len);
        result
    };
    assert_eq!(details["source"], "native_operation");
    assert_eq!(
        details["evidence"]["signatureValidity"]["state"],
        "verified"
    );
    assert!(details["evidence"].get("signer_cert_pem").is_none());
    if s1 {
        assert_eq!(
            details["evidence"]["signatureAlgorithm"]["value"]["id"],
            "1.3.101.112"
        );
    }

    // Without a key and sender: S1 is checked against the certificate it
    // carries; S0 cannot be checked, and nothing fails.
    let (code, verdict) = take(|o, l| unsafe {
        scomm_smime_verify_detached(
            DATA.as_ptr(),
            DATA.len(),
            sig.as_ptr(),
            sig.len(),
            ptr::null(),
            0,
            ptr::null(),
            0,
            o,
            l,
        )
    });
    assert_eq!(code, 0);
    let want = if s1 { "valid" } else { "unknown-signer" };
    assert_eq!(json(&verdict)["validity"], want);

    let bad = b"nonsense";
    let (code, verdict) = take(|o, l| unsafe {
        scomm_smime_verify_detached(
            DATA.as_ptr(),
            DATA.len(),
            bad.as_ptr(),
            bad.len(),
            ptr::null(),
            0,
            ptr::null(),
            0,
            o,
            l,
        )
    });
    assert_eq!(code, 0);
    assert_eq!(json(&verdict)["validity"], "malformed");
}

#[test]
fn cert_info_roots_check_and_migration() {
    let (public, secret) = pqc_key();
    let pub_json = json(&public);
    let cert = pub_json["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|e| e["cert_pem"].as_str().filter(|s| !s.is_empty()))
        .unwrap()
        .to_string();

    let (code, info) =
        take(|o, l| unsafe { scomm_smime_cert_info(cert.as_ptr(), cert.len(), o, l) });
    assert_eq!(code, 0);
    let info = json(&info);
    assert_eq!(info["email_address"], "dana@example.com");
    assert_eq!(info["is_self_signed"], true);

    let email = b"dana@example.com";
    let (code, check) = take(|o, l| unsafe {
        scomm_smime_check_certificate(
            cert.as_ptr(),
            cert.len(),
            email.as_ptr(),
            email.len(),
            0,
            o,
            l,
        )
    });
    assert_eq!(code, 0);
    assert_eq!(
        json(&check),
        serde_json::json!({"chain": "untrusted-root", "email_match": true})
    );
    let (code, _) = take(|o, l| unsafe {
        scomm_smime_check_certificate(cert.as_ptr(), cert.len(), ptr::null(), 0, 7, o, l)
    });
    assert_ne!(code, 0, "unknown purpose");

    // Its own certificate as a root: loading reports one.
    let mut count = 0usize;
    assert_eq!(
        unsafe { scomm_smime_set_trust_roots(cert.as_ptr(), cert.len(), &mut count) },
        0
    );
    assert_eq!(count, 1);
    assert_eq!(
        unsafe { scomm_smime_set_trust_roots(ptr::null(), 0, &mut count) },
        0
    );
    assert_eq!(count, 0);

    // A new key is born with its ML-DSA certificate (task 5.9).
    let (code, none) = take(|o, l| unsafe {
        scomm_smime_add_mldsa_certificates(
            secret.as_ptr(),
            secret.len(),
            email.as_ptr(),
            email.len(),
            o,
            l,
        )
    });
    assert_eq!((code, none.len()), (0, 0), "new key: nothing to do");
    let (_, bare) = pqc_key_for(b"Dana");
    let (code, updated) = take(|o, l| unsafe {
        scomm_smime_add_mldsa_certificates(
            bare.as_ptr(),
            bare.len(),
            email.as_ptr(),
            email.len(),
            o,
            l,
        )
    });
    assert_eq!(code, 0);
    assert!(!updated.is_empty(), "the ML-DSA entry gains a certificate");
    let (code, again) = take(|o, l| unsafe {
        scomm_smime_add_mldsa_certificates(
            updated.as_ptr(),
            updated.len(),
            email.as_ptr(),
            email.len(),
            o,
            l,
        )
    });
    assert_eq!((code, again.len()), (0, 0), "second run: nothing to do");
}

#[test]
fn decrypt_ex_reports_the_format() {
    let (public, secret) = pqc_key();
    let mut recipients = (1u32).to_be_bytes().to_vec();
    recipients.extend_from_slice(&(public.len() as u32).to_be_bytes());
    recipients.extend_from_slice(&public);
    let (code, cms) = take(|o, l| unsafe {
        scomm_smime_encrypt(
            DATA.as_ptr(),
            DATA.len(),
            recipients.as_ptr(),
            recipients.len(),
            0,
            o,
            l,
        )
    });
    assert_eq!(code, 0);
    let (inspected, report) = take(|out, len| unsafe {
        scomm_smime_inspect_public_envelope_v1(cms.as_ptr(), cms.len(), 1, 1, out, len)
    });
    assert_eq!(inspected, 0);
    let report = json(&report);
    let f1 = scomm_smime_cms::RELEASE_2_WRITERS;
    assert_eq!(report["source"], "public_inspection");
    assert_eq!(report["state"], "complete");
    assert_eq!(report["evidence"]["contentCipher"]["state"], "declared");
    assert!(report["evidence"].get("integrity").is_none());
    if f1 {
        assert_eq!(
            report["evidence"]["contentCipher"]["value"]["id"],
            "2.16.840.1.101.3.4.1.46"
        );
    }
    let large = vec![0u8; 16 * 1024 + 1];
    let (_, limited) = take(|out, len| unsafe {
        scomm_smime_inspect_public_envelope_v1(large.as_ptr(), large.len(), 1, 1, out, len)
    });
    assert_eq!(json(&limited)["limit"], "input_bytes");
    let (_, truncated) = take(|out, len| unsafe {
        scomm_smime_inspect_public_envelope_v1(cms.as_ptr(), cms.len() - 1, 1, 1, out, len)
    });
    assert_eq!(json(&truncated)["state"], "malformed");

    let mut meta = (ptr::null_mut(), 0usize);
    let (code, plaintext) = take(|o, l| unsafe {
        scomm_smime_decrypt_ex(
            cms.as_ptr(),
            cms.len(),
            secret.as_ptr(),
            secret.len(),
            ptr::null(),
            0,
            o,
            l,
            &mut meta.0,
            &mut meta.1,
        )
    });
    assert_eq!(code, 0);
    assert_eq!(plaintext, DATA);
    let m = unsafe { std::slice::from_raw_parts(meta.0, meta.1) }.to_vec();
    unsafe { scomm_smime_buffer_free(meta.0, meta.1) };
    let f1 = scomm_smime_cms::RELEASE_2_WRITERS;
    assert_eq!(json(&m)["format"], if f1 { "f1" } else { "f0-scomm" });

    let mut format = (ptr::null_mut(), 0usize);
    let mut details = (ptr::null_mut(), 0usize);
    let (code, plaintext) = take(|o, l| unsafe {
        scomm_smime_decrypt_with_details_v1(
            cms.as_ptr(),
            cms.len(),
            secret.as_ptr(),
            secret.len(),
            ptr::null(),
            0,
            o,
            l,
            &mut format.0,
            &mut format.1,
            &mut details.0,
            &mut details.1,
        )
    });
    assert_eq!(code, 0);
    assert_eq!(plaintext, DATA);
    let read_json = |(ptr, len): (*mut u8, usize)| unsafe {
        assert!(!ptr.is_null());
        let decoded = json(std::slice::from_raw_parts(ptr, len));
        scomm_smime_buffer_free(ptr, len);
        decoded
    };
    assert_eq!(read_json(format), json(&m));
    let integrity = &read_json(details)["evidence"]["integrity"];
    assert_eq!(integrity["state"], if f1 { "verified" } else { "observed" });
    assert_eq!(
        integrity["value"],
        if f1 {
            "aead_passed"
        } else {
            "no_authenticated_integrity"
        }
    );

    let (_, other_secret) = pqc_key_for(b"Other <other@example.com>");
    format = (ptr::null_mut(), 0);
    details = (ptr::null_mut(), 0);
    let (code, plaintext) = take(|o, l| unsafe {
        scomm_smime_decrypt_with_details_v1(
            cms.as_ptr(),
            cms.len(),
            other_secret.as_ptr(),
            other_secret.len(),
            ptr::null(),
            0,
            o,
            l,
            &mut format.0,
            &mut format.1,
            &mut details.0,
            &mut details.1,
        )
    });
    assert_ne!(code, 0);
    assert!(plaintext.is_empty());
    assert!(format.0.is_null() && format.1 == 0);
    let failure = read_json(details);
    assert_eq!(failure["evidence"]["container"]["state"], "declared");
    assert_eq!(failure["evidence"]["failure"]["state"], "observed");
    assert!(failure["evidence"].get("integrity").is_none());

    // A failure leaves both buffers empty.
    let mut broken = cms.clone();
    let last = broken.len() - 1;
    broken[last] ^= 0xff;
    let mut meta = (std::ptr::dangling_mut::<u8>(), 99usize);
    let (code, plaintext) = take(|o, l| unsafe {
        scomm_smime_decrypt_ex(
            broken.as_ptr(),
            broken.len(),
            b"{}".as_ptr(),
            2,
            ptr::null(),
            0,
            o,
            l,
            &mut meta.0,
            &mut meta.1,
        )
    });
    assert_ne!(code, 0);
    assert!(plaintext.is_empty());
    assert!(meta.0.is_null() && meta.1 == 0);
}

#[test]
fn the_plaintext_limit_is_the_engine_limit() {
    assert_eq!(
        scomm_smime_max_plaintext_len(),
        scomm_smime_cms::MAX_PLAINTEXT_LEN
    );
}

fn files_buffer(files: &[&[u8]]) -> Vec<u8> {
    let mut out = (files.len() as u32).to_be_bytes().to_vec();
    for f in files {
        out.extend((f.len() as u32).to_be_bytes());
        out.extend(*f);
    }
    out
}

/// ABI 6: `scomm_smime_import` returns the certificates as JSON and the
/// password errors as their own codes.
#[test]
fn import_reads_files_and_reports_password_errors() {
    let (public, _) = pqc_key();
    let bundle = json(&public);
    let pem = bundle["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|e| e["cert_pem"].as_str().filter(|p| !p.is_empty()))
        .unwrap()
        .to_string();
    let files = files_buffer(&[pem.as_bytes()]);
    let (code, out) = take(|o, l| unsafe {
        scomm_smime_import(files.as_ptr(), files.len(), ptr::null(), 0, o, l)
    });
    assert_eq!(code, 0);
    let v = json(&out);
    assert_eq!(v["certificates"].as_array().unwrap().len(), 1);
    assert_eq!(v["unmatched_keys"], 0);
    assert!(v["certificates"][0].get("pkcs8_b64").is_none());

    // An encrypted PKCS#8 key with no password: code 12; wrong one: 13.
    let key = openssl::pkey::PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
    let enc = key
        .private_key_to_pem_pkcs8_passphrase(openssl::symm::Cipher::aes_128_cbc(), b"pw")
        .unwrap();
    let files = files_buffer(&[pem.as_bytes(), &enc]);
    let (code, _) = take(|o, l| unsafe {
        scomm_smime_import(files.as_ptr(), files.len(), ptr::null(), 0, o, l)
    });
    assert_eq!(code, 12);
    let (code, _) = take(|o, l| unsafe {
        scomm_smime_import(files.as_ptr(), files.len(), b"no".as_ptr(), 2, o, l)
    });
    assert_eq!(code, 13);
}
