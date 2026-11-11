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
    let userid = b"Dana <dana@example.com>";
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
fn abi_is_3_and_every_symbol_is_linked() {
    assert_eq!(scomm_smime_abi_version(), 3);
    assert_ne!(link_anchor(), 0);
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
    // Release 1 writes Ed25519 as S0.
    assert_eq!(v["format"], "s0");
    assert_eq!(v["chain"], "no-chain");
    assert_eq!(v["revocation"], "not-checked");
    assert_eq!(v["signer_fingerprint"].as_str().unwrap().len(), 64);

    // Without a key and sender: S0 cannot be checked, and nothing fails.
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
    assert_eq!(json(&verdict)["validity"], "unknown-signer");

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

    let (code, updated) = take(|o, l| unsafe {
        scomm_smime_add_mldsa_certificates(
            secret.as_ptr(),
            secret.len(),
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
    // Release 1 still writes F0-scomm.
    assert_eq!(json(&m)["format"], "f0-scomm");

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
