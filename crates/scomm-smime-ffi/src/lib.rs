//! C ABI. CMS engine types do not cross this boundary.

use std::cell::RefCell;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;

use scomm_smime_cms::{
    add_mldsa_certificates, cert_info, check_certificate, create_csr, import, remove_entries,
    set_trust_roots, CmsSmime, DecryptEnvelope, MAX_PLAINTEXT_LEN,
};
use scomm_smime_core::*;
use serde_json::json;

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
}

fn engine() -> CmsSmime {
    CmsSmime::new()
}

fn set_error(msg: String) {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = Some(msg));
}

fn clear_error() {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = None);
}

unsafe fn write_buf(bytes: &[u8], out: *mut *mut u8, out_len: *mut usize) {
    if bytes.is_empty() {
        *out = ptr::null_mut();
        *out_len = 0;
        return;
    }
    let boxed = bytes.to_vec().into_boxed_slice();
    let len = boxed.len();
    *out = Box::into_raw(boxed) as *mut u8;
    *out_len = len;
}

unsafe fn read_slice<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        slice::from_raw_parts(ptr, len)
    }
}

fn key_info_json(info: &SmimeKeyInfo) -> String {
    let identities: Vec<serde_json::Value> = info
        .identities
        .iter()
        .map(|c| {
            json!({
                "fingerprint": c.fingerprint,
                "serial": c.serial,
                "algorithm": c.algorithm,
                "email": c.email,
                "subject": c.subject,
                "usage": if c.usage == KeyUsage::Signing { "signing" } else { "encryption" },
                "has_secret": c.has_secret,
                "pqc": c.is_pqc(),
                "legacy_key_ids": c.legacy_key_ids,
            })
        })
        .collect();
    json!({
        "algorithm": info.primary_algorithm(),
        "is_pqc": info.is_pqc(),
        "is_pqc_signing": info.is_pqc_signing(),
        "identities": identities,
    })
    .to_string()
}

fn map_err(e: SmimeError) -> i32 {
    set_error(e.to_string());
    e.code()
}

fn run(f: impl FnOnce() -> Result<i32>) -> i32 {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(code)) => code,
        Ok(Err(e)) => map_err(e),
        Err(_) => {
            set_error("panic in scomm-smime".into());
            SmimeError::Internal("panic".into()).code()
        }
    }
}

fn sign_algorithm(name: &[u8]) -> Result<&'static str> {
    [
        ALG_ED25519, ALG_MLDSA65, ALG_RSA_PSS, ALG_RSA_PKCS1,
        ALG_ECDSA_P256, ALG_ECDSA_P384, ALG_ECDSA_P521,
    ]
        .into_iter()
        .find(|alg| alg.as_bytes() == name)
        .ok_or_else(|| SmimeError::UnsupportedAlgorithm(String::from_utf8_lossy(name).into_owned()))
}

fn parse_recipients(buf: &[u8]) -> Result<Vec<Vec<u8>>> {
    if buf.len() < 4 {
        return Err(SmimeError::InvalidArgument("recipients buffer".into()));
    }
    let n = u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize;
    let mut i = 4;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        if i + 4 > buf.len() {
            return Err(SmimeError::InvalidArgument("truncated recipient".into()));
        }
        let len = u32::from_be_bytes(buf[i..i + 4].try_into().unwrap()) as usize;
        i += 4;
        if i + len > buf.len() {
            return Err(SmimeError::InvalidArgument(
                "truncated recipient key".into(),
            ));
        }
        out.push(buf[i..i + len].to_vec());
        i += len;
    }
    Ok(out)
}

unsafe fn read_opt_str(ptr: *const u8, len: usize) -> Option<String> {
    if ptr.is_null() || len == 0 {
        None
    } else {
        Some(String::from_utf8_lossy(read_slice(ptr, len)).into_owned())
    }
}

fn validity_name(v: SignatureValidity) -> &'static str {
    match v {
        SignatureValidity::CryptographicallyValid => "valid",
        SignatureValidity::CryptographicallyInvalid => "invalid",
        SignatureValidity::UnknownSigner => "unknown-signer",
        SignatureValidity::MalformedSignature => "malformed",
        SignatureValidity::UnsupportedAlgorithm => "unsupported",
    }
}

fn chain_name(c: ChainStatus) -> &'static str {
    match c {
        ChainStatus::TrustedRoot => "trusted-root",
        ChainStatus::UntrustedRoot => "untrusted-root",
        ChainStatus::NoChain => "no-chain",
        ChainStatus::Expired => "expired",
        ChainStatus::NotYetValid => "not-yet-valid",
        ChainStatus::WrongPurpose => "wrong-purpose",
    }
}

/// Verdict JSON (`design.md` "Trust model", "Verdict").
fn verdict_json(v: &SignatureVerdict) -> String {
    json!({
        "validity": validity_name(v.validity),
        "format": v.format.map(|f| match f {
            SignatureFormat::S1 => "s1",
            SignatureFormat::S0 => "s0",
        }),
        "signer_fingerprint": v.signer_fingerprint,
        "signer_cert_pem": v.signer_cert_pem,
        "chain": chain_name(v.chain),
        "email_match": v.email_match,
        "weak_algorithm": v.weak_algorithm,
        "revocation": "not-checked",
    })
    .to_string()
}

#[no_mangle]
pub extern "C" fn scomm_smime_abi_version() -> u32 {
    ABI_VERSION
}

#[no_mangle]
pub unsafe extern "C" fn scomm_smime_buffer_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    drop(Box::from_raw(ptr::slice_from_raw_parts_mut(ptr, len)));
}

#[no_mangle]
pub unsafe extern "C" fn scomm_smime_last_error(out: *mut *mut u8, out_len: *mut usize) -> i32 {
    let msg = LAST_ERROR.with(|slot| slot.borrow().clone().unwrap_or_default());
    write_buf(msg.as_bytes(), out, out_len);
    0
}

#[no_mangle]
pub unsafe extern "C" fn scomm_smime_inspect(
    key: *const u8,
    key_len: usize,
    json_out: *mut *mut u8,
    json_len: *mut usize,
) -> i32 {
    let key = read_slice(key, key_len).to_vec();
    run(|| {
        clear_error();
        let info = engine().inspect_key(&key)?;
        unsafe { write_buf(key_info_json(&info).as_bytes(), json_out, json_len) };
        Ok(0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn scomm_smime_generate(
    userid: *const u8,
    userid_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    profile: i32,
    public_out: *mut *mut u8,
    public_len: *mut usize,
    secret_out: *mut *mut u8,
    secret_len: *mut usize,
    json_out: *mut *mut u8,
    json_len: *mut usize,
) -> i32 {
    scomm_smime_generate_with_validity(
        userid,
        userid_len,
        passphrase,
        passphrase_len,
        profile,
        0,
        public_out,
        public_len,
        secret_out,
        secret_len,
        json_out,
        json_len,
    )
}

/// ABI 5. As `scomm_smime_generate`, valid for `validity_years` from now
/// (1 to 10). 0 keeps the engine's previous default lifetime.
#[no_mangle]
pub unsafe extern "C" fn scomm_smime_generate_with_validity(
    userid: *const u8,
    userid_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    profile: i32,
    validity_years: u32,
    public_out: *mut *mut u8,
    public_len: *mut usize,
    secret_out: *mut *mut u8,
    secret_len: *mut usize,
    json_out: *mut *mut u8,
    json_len: *mut usize,
) -> i32 {
    let userid = String::from_utf8_lossy(read_slice(userid, userid_len)).into_owned();
    let pass = if passphrase.is_null() || passphrase_len == 0 {
        None
    } else {
        Some(String::from_utf8_lossy(read_slice(passphrase, passphrase_len)).into_owned())
    };
    let profile = match profile {
        0 => KeyProfile::Classical,
        1 => KeyProfile::PqcCms,
        2 => KeyProfile::PqcEncryption,
        3 => KeyProfile::PqcSigning,
        4 => KeyProfile::ClassicalP256,
        5 => KeyProfile::ClassicalP384,
        6 => KeyProfile::ClassicalP521,
        _ => {
            set_error("unknown key profile".into());
            return SmimeError::InvalidArgument("profile".into()).code();
        }
    };
    run(|| {
        clear_error();
        let generated = engine().generate_key(&GenerateKeyOptions {
            userid,
            passphrase: pass,
            profile,
            validity_years: (validity_years != 0).then_some(validity_years),
        })?;
        unsafe {
            write_buf(&generated.public, public_out, public_len);
            write_buf(&generated.secret, secret_out, secret_len);
            write_buf(
                key_info_json(&generated.info).as_bytes(),
                json_out,
                json_len,
            );
        }
        Ok(0)
    })
}

#[no_mangle]
pub extern "C" fn scomm_smime_pqc_ready() -> i32 {
    1
}

#[no_mangle]
pub unsafe extern "C" fn scomm_smime_export_public(
    key: *const u8,
    key_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let key = read_slice(key, key_len).to_vec();
    run(|| {
        clear_error();
        let public = engine().export_public_key(&key)?;
        unsafe { write_buf(&public, out, out_len) };
        Ok(0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn scomm_smime_encrypt(
    plaintext: *const u8,
    plaintext_len: usize,
    recipients: *const u8,
    recipients_len: usize,
    armored: i32,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let plaintext = read_slice(plaintext, plaintext_len).to_vec();
    let recipients = read_slice(recipients, recipients_len).to_vec();
    run(|| {
        clear_error();
        let recips = parse_recipients(&recipients)?;
        let refs: Vec<&[u8]> = recips.iter().map(|v| v.as_slice()).collect();
        let ct = engine().encrypt(
            &plaintext,
            &refs,
            &EncryptOptions {
                armored: armored != 0,
            },
        )?;
        unsafe { write_buf(&ct, out, out_len) };
        Ok(0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn scomm_smime_decrypt(
    ciphertext: *const u8,
    ciphertext_len: usize,
    private_key: *const u8,
    private_key_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let ciphertext = read_slice(ciphertext, ciphertext_len).to_vec();
    let private_key = read_slice(private_key, private_key_len).to_vec();
    let pass = if passphrase.is_null() || passphrase_len == 0 {
        None
    } else {
        Some(String::from_utf8_lossy(read_slice(passphrase, passphrase_len)).into_owned())
    };
    // D5: a failure leaves the caller with no buffer at all.
    *out = ptr::null_mut();
    *out_len = 0;
    run(|| {
        clear_error();
        let pt = engine().decrypt(&ciphertext, &private_key, pass.as_deref())?;
        unsafe { write_buf(&pt.plaintext, out, out_len) };
        Ok(0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn scomm_smime_sign(
    data: *const u8,
    data_len: usize,
    private_key: *const u8,
    private_key_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    algorithm: *const u8,
    algorithm_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let data = read_slice(data, data_len).to_vec();
    let private_key = read_slice(private_key, private_key_len).to_vec();
    let pass = if passphrase.is_null() || passphrase_len == 0 {
        None
    } else {
        Some(String::from_utf8_lossy(read_slice(passphrase, passphrase_len)).into_owned())
    };
    let algorithm = read_slice(algorithm, algorithm_len).to_vec();
    run(|| {
        clear_error();
        let options = SignOptions {
            detached: false,
            algorithm: sign_algorithm(&algorithm)?,
        };
        let sig = engine().sign(&data, &private_key, pass.as_deref(), &options)?;
        unsafe { write_buf(&sig, out, out_len) };
        Ok(0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn scomm_smime_verify(
    data: *const u8,
    data_len: usize,
    signature: *const u8,
    signature_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    valid_out: *mut i32,
) -> i32 {
    let data = read_slice(data, data_len).to_vec();
    let signature = read_slice(signature, signature_len).to_vec();
    let public_key = read_slice(public_key, public_key_len).to_vec();
    run(|| {
        clear_error();
        let v = engine().verify(&data, &signature, &public_key)?;
        let ok = v.validity == SignatureValidity::CryptographicallyValid;
        unsafe { *valid_out = if ok { 1 } else { 0 } };
        Ok(0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn scomm_smime_inspect_message(
    message: *const u8,
    message_len: usize,
    json_out: *mut *mut u8,
    json_len: *mut usize,
) -> i32 {
    let message = read_slice(message, message_len).to_vec();
    run(|| {
        clear_error();
        let info = engine().inspect_message(&message)?;
        let json = json!({
            "encrypted": info.encrypted,
            "signed": info.signed,
            "pqc": info.pqc,
            "classical_recipient": info.classical_recipient,
            "algorithm": info.algorithm,
        })
        .to_string();
        unsafe { write_buf(json.as_bytes(), json_out, json_len) };
        Ok(0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn scomm_smime_test_passphrase(
    private_key: *const u8,
    private_key_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
) -> i32 {
    let private_key = read_slice(private_key, private_key_len).to_vec();
    let pass = if passphrase.is_null() || passphrase_len == 0 {
        None
    } else {
        Some(String::from_utf8_lossy(read_slice(passphrase, passphrase_len)).into_owned())
    };
    run(|| {
        clear_error();
        engine().test_passphrase(&private_key, pass.as_deref())?;
        Ok(0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn scomm_smime_pop_sign_mldsa(
    data: *const u8,
    data_len: usize,
    private_key: *const u8,
    private_key_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let data = read_slice(data, data_len).to_vec();
    let private_key = read_slice(private_key, private_key_len).to_vec();
    let pass = if passphrase.is_null() || passphrase_len == 0 {
        None
    } else {
        Some(String::from_utf8_lossy(read_slice(passphrase, passphrase_len)).into_owned())
    };
    run(|| {
        clear_error();
        let sig = engine().pop_sign_mldsa(&data, &private_key, pass.as_deref())?;
        unsafe { write_buf(&sig, out, out_len) };
        Ok(0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn scomm_smime_pop_hybrid_shared(
    private_key: *const u8,
    private_key_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    kem_ciphertext: *const u8,
    kem_ciphertext_len: usize,
    ephemeral_x25519: *const u8,
    ephemeral_x25519_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let private_key = read_slice(private_key, private_key_len).to_vec();
    let kem = read_slice(kem_ciphertext, kem_ciphertext_len).to_vec();
    let eph = read_slice(ephemeral_x25519, ephemeral_x25519_len).to_vec();
    let pass = if passphrase.is_null() || passphrase_len == 0 {
        None
    } else {
        Some(String::from_utf8_lossy(read_slice(passphrase, passphrase_len)).into_owned())
    };
    run(|| {
        clear_error();
        let shared = engine().pop_hybrid_shared(&private_key, pass.as_deref(), &kem, &eph)?;
        unsafe { write_buf(&shared, out, out_len) };
        Ok(0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn scomm_smime_pop_sign_classical(
    data: *const u8,
    data_len: usize,
    private_key: *const u8,
    private_key_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let data = read_slice(data, data_len).to_vec();
    let private_key = read_slice(private_key, private_key_len).to_vec();
    let pass = if passphrase.is_null() || passphrase_len == 0 {
        None
    } else {
        Some(String::from_utf8_lossy(read_slice(passphrase, passphrase_len)).into_owned())
    };
    run(|| {
        clear_error();
        let sig = engine().pop_sign_classical(&data, &private_key, pass.as_deref())?;
        unsafe { write_buf(&sig, out, out_len) };
        Ok(0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn scomm_smime_pop_rsa_decrypt(
    ciphertext: *const u8,
    ciphertext_len: usize,
    private_key: *const u8,
    private_key_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let ciphertext = read_slice(ciphertext, ciphertext_len).to_vec();
    let private_key = read_slice(private_key, private_key_len).to_vec();
    let pass = if passphrase.is_null() || passphrase_len == 0 {
        None
    } else {
        Some(String::from_utf8_lossy(read_slice(passphrase, passphrase_len)).into_owned())
    };
    run(|| {
        clear_error();
        let plaintext = engine().pop_rsa_decrypt(&ciphertext, &private_key, pass.as_deref())?;
        unsafe { write_buf(&plaintext, out, out_len) };
        Ok(0)
    })
}

/// Detached signature verdict as JSON. `public_key` (optional) is a bundle
/// already held for the sender; `sender` (optional) is the From address.
#[no_mangle]
pub unsafe extern "C" fn scomm_smime_verify_detached(
    data: *const u8,
    data_len: usize,
    signature: *const u8,
    signature_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    sender: *const u8,
    sender_len: usize,
    json_out: *mut *mut u8,
    json_len: *mut usize,
) -> i32 {
    let data = read_slice(data, data_len).to_vec();
    let signature = read_slice(signature, signature_len).to_vec();
    let public_key = (!public_key.is_null() && public_key_len > 0)
        .then(|| read_slice(public_key, public_key_len).to_vec());
    let sender = read_opt_str(sender, sender_len);
    *json_out = ptr::null_mut();
    *json_len = 0;
    run(|| {
        clear_error();
        let v = engine().verify_detached(
            &data,
            &signature,
            public_key.as_deref(),
            sender.as_deref(),
        )?;
        unsafe { write_buf(verdict_json(&v).as_bytes(), json_out, json_len) };
        Ok(0)
    })
}

/// Detached signature with the named algorithm: S1 SignedData for RSA
/// PKCS#1 v1.5 now and for every algorithm once Release 2 writers are on.
#[no_mangle]
pub unsafe extern "C" fn scomm_smime_sign_detached(
    data: *const u8,
    data_len: usize,
    private_key: *const u8,
    private_key_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    algorithm: *const u8,
    algorithm_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let data = read_slice(data, data_len).to_vec();
    let private_key = read_slice(private_key, private_key_len).to_vec();
    let pass = read_opt_str(passphrase, passphrase_len);
    let algorithm = read_slice(algorithm, algorithm_len).to_vec();
    *out = ptr::null_mut();
    *out_len = 0;
    run(|| {
        clear_error();
        let options = SignOptions {
            detached: true,
            algorithm: sign_algorithm(&algorithm)?,
        };
        let sig = engine().sign(&data, &private_key, pass.as_deref(), &options)?;
        unsafe { write_buf(&sig, out, out_len) };
        Ok(0)
    })
}

/// Certificate details as JSON (PEM or DER input).
#[no_mangle]
pub unsafe extern "C" fn scomm_smime_cert_info(
    cert: *const u8,
    cert_len: usize,
    json_out: *mut *mut u8,
    json_len: *mut usize,
) -> i32 {
    let cert = read_slice(cert, cert_len).to_vec();
    *json_out = ptr::null_mut();
    *json_len = 0;
    run(|| {
        clear_error();
        let info = cert_info(&cert)?;
        let text = serde_json::to_string(&info).map_err(|e| SmimeError::Internal(e.to_string()))?;
        unsafe { write_buf(text.as_bytes(), json_out, json_len) };
        Ok(0)
    })
}

/// Loads the bundled e-mail roots (PEM); writes how many were read. Empty
/// input clears them.
#[no_mangle]
pub unsafe extern "C" fn scomm_smime_set_trust_roots(
    pem: *const u8,
    pem_len: usize,
    count_out: *mut usize,
) -> i32 {
    let pem = read_slice(pem, pem_len).to_vec();
    run(|| {
        clear_error();
        let n = set_trust_roots(&pem)?;
        unsafe { *count_out = n };
        Ok(0)
    })
}

/// Path B check of a certificate (with its chain, PEM) for signing
/// (`purpose` 0) or encryption (1); JSON `{chain, email_match}`.
#[no_mangle]
pub unsafe extern "C" fn scomm_smime_check_certificate(
    cert_pem: *const u8,
    cert_pem_len: usize,
    email: *const u8,
    email_len: usize,
    purpose: i32,
    json_out: *mut *mut u8,
    json_len: *mut usize,
) -> i32 {
    let cert_pem = read_slice(cert_pem, cert_pem_len).to_vec();
    let email = read_opt_str(email, email_len);
    *json_out = ptr::null_mut();
    *json_len = 0;
    run(|| {
        clear_error();
        let purpose = match purpose {
            0 => CertPurpose::SmimeSign,
            1 => CertPurpose::SmimeEncrypt,
            other => return Err(SmimeError::InvalidArgument(format!("purpose {other}"))),
        };
        let c = check_certificate(&cert_pem, email.as_deref(), purpose)?;
        let text = json!({"chain": chain_name(c.chain), "email_match": c.email_match}).to_string();
        unsafe { write_buf(text.as_bytes(), json_out, json_len) };
        Ok(0)
    })
}

/// ML-DSA certificate migration (Q5). Writes the updated secret bundle, or
/// leaves `out` empty when there is nothing to do.
#[no_mangle]
pub unsafe extern "C" fn scomm_smime_add_mldsa_certificates(
    secret: *const u8,
    secret_len: usize,
    email: *const u8,
    email_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let secret = read_slice(secret, secret_len).to_vec();
    let email = read_opt_str(email, email_len).unwrap_or_default();
    *out = ptr::null_mut();
    *out_len = 0;
    run(|| {
        clear_error();
        if let Some(updated) = add_mldsa_certificates(&secret, &email)? {
            unsafe { write_buf(&updated, out, out_len) };
        }
        Ok(0)
    })
}

/// ABI 4. Writes [secret] without the entries whose `spki_b64` is listed in
/// [spkis], a JSON array of strings. Fails rather than leave no entry.
#[no_mangle]
pub unsafe extern "C" fn scomm_smime_remove_entries(
    secret: *const u8,
    secret_len: usize,
    spkis: *const u8,
    spkis_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let secret = read_slice(secret, secret_len).to_vec();
    let spkis = read_slice(spkis, spkis_len).to_vec();
    *out = ptr::null_mut();
    *out_len = 0;
    run(|| {
        clear_error();
        let spkis: Vec<String> = serde_json::from_slice(&spkis)
            .map_err(|_| SmimeError::InvalidArgument("spkis must be a JSON string array".into()))?;
        let updated = remove_entries(&secret, &spkis)?;
        unsafe { write_buf(&updated, out, out_len) };
        Ok(0)
    })
}

/// ABI 6. Reads S/MIME import files (PKCS#12, PKCS#7, PEM/DER certificates
/// and keys). [files] uses the recipients buffer layout (u32 count, then
/// u32 length + bytes per file, big-endian). Writes JSON
/// `{certificates: [{cert_pem, spki_b64, is_ca, key_algorithm, pkcs8_b64?}],
/// unmatched_keys}`. Errors: 12 password required, 13 wrong password,
/// 2 malformed file, 1 unsupported file, 5 unsupported file encryption.
/// The output holds unencrypted private keys: callers store it at once and
/// must not log it.
#[no_mangle]
pub unsafe extern "C" fn scomm_smime_import(
    files: *const u8,
    files_len: usize,
    password: *const u8,
    password_len: usize,
    json_out: *mut *mut u8,
    json_len: *mut usize,
) -> i32 {
    let files = read_slice(files, files_len).to_vec();
    let password = read_slice(password, password_len).to_vec();
    *json_out = ptr::null_mut();
    *json_len = 0;
    run(|| {
        clear_error();
        let files = parse_recipients(&files)?;
        let password = String::from_utf8(password)
            .map_err(|_| SmimeError::InvalidArgument("password must be UTF-8".into()))?;
        let result = import(&files, &password)?;
        let text =
            serde_json::to_string(&result).map_err(|e| SmimeError::Internal(e.to_string()))?;
        unsafe { write_buf(text.as_bytes(), json_out, json_len) };
        Ok(0)
    })
}

/// ABI 7. A PKCS#10 request for a CA-issued S/MIME certificate with a new
/// RSA key. [request] is JSON `{email, name?, key_bits, sign, encrypt}`
/// (`key_bits` 2048 or 3072). Writes JSON `{csr_pem, pkcs8_b64, spki_b64,
/// spki_sha256}`; the request's self-signature is checked first. The output
/// holds the unencrypted private key: callers store it at once and must not
/// log it. Errors: 1 bad request, 5 unsupported key size.
#[no_mangle]
pub unsafe extern "C" fn scomm_smime_create_csr(
    request: *const u8,
    request_len: usize,
    json_out: *mut *mut u8,
    json_len: *mut usize,
) -> i32 {
    let request = read_slice(request, request_len).to_vec();
    *json_out = ptr::null_mut();
    *json_len = 0;
    run(|| {
        clear_error();
        let request = serde_json::from_slice(&request)
            .map_err(|_| SmimeError::InvalidArgument("csr request JSON".into()))?;
        let result = create_csr(&request)?;
        let text =
            serde_json::to_string(&result).map_err(|e| SmimeError::Internal(e.to_string()))?;
        unsafe { write_buf(text.as_bytes(), json_out, json_len) };
        Ok(0)
    })
}

/// [scomm_smime_decrypt] plus JSON `{format, algorithm}` (D6): the app
/// shows anything other than `f1` as not integrity protected.
#[no_mangle]
pub unsafe extern "C" fn scomm_smime_decrypt_ex(
    ciphertext: *const u8,
    ciphertext_len: usize,
    private_key: *const u8,
    private_key_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
    json_out: *mut *mut u8,
    json_len: *mut usize,
) -> i32 {
    let ciphertext = read_slice(ciphertext, ciphertext_len).to_vec();
    let private_key = read_slice(private_key, private_key_len).to_vec();
    let pass = read_opt_str(passphrase, passphrase_len);
    // D5: a failure leaves the caller with no buffer at all.
    *out = ptr::null_mut();
    *out_len = 0;
    *json_out = ptr::null_mut();
    *json_len = 0;
    run(|| {
        clear_error();
        let pt = engine().decrypt(&ciphertext, &private_key, pass.as_deref())?;
        let meta = json!({"format": pt.format, "algorithm": pt.algorithm}).to_string();
        unsafe {
            write_buf(&pt.plaintext, out, out_len);
            write_buf(meta.as_bytes(), json_out, json_len);
        }
        Ok(0)
    })
}

// Added independently of the existing ABI version and verdict payload.
#[no_mangle]
pub unsafe extern "C" fn scomm_smime_decrypt_with_details_v1(
    ciphertext: *const u8,
    ciphertext_len: usize,
    private_key: *const u8,
    private_key_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
    format: *mut *mut u8,
    format_len: *mut usize,
    details: *mut *mut u8,
    details_len: *mut usize,
) -> i32 {
    if out.is_null()
        || out_len.is_null()
        || format.is_null()
        || format_len.is_null()
        || details.is_null()
        || details_len.is_null()
    {
        return 1;
    }
    *out = ptr::null_mut();
    *out_len = 0;
    *format = ptr::null_mut();
    *format_len = 0;
    *details = ptr::null_mut();
    *details_len = 0;
    run(|| {
        clear_error();
        let _ = (passphrase, passphrase_len);
        let mut envelope = DecryptEnvelope::default();
        let opened = engine().decrypt_with_details(
            read_slice(ciphertext, ciphertext_len),
            read_slice(private_key, private_key_len),
            &mut envelope,
        );
        let mut evidence = json!({});
        if let Some(format) = envelope.format {
            evidence["container"] = json!({"state":"declared","value":format});
        }
        if let Some(count) = envelope.recipient_records {
            evidence["recipientRecordCount"] = json!({"state":"declared","value":count});
        }
        let pt = match opened {
            Ok(result) => result,
            Err(error) => {
                let (state, reason) = match error {
                    SmimeError::UnsupportedAlgorithm(_) => ("unsupported", "unsupported_algorithm"),
                    SmimeError::WrongPrivateKey => ("failed", "no_matching_key"),
                    SmimeError::InvalidKey(_) => ("failed", "key_unavailable"),
                    SmimeError::MalformedMessage => ("failed", "malformed_message"),
                    _ => ("failed", "decryption_failed"),
                };
                evidence["failure"] = json!({"state":"observed","value":reason});
                let report = json!({
                    "version": 1, "protocol": "smime", "source": "native_operation",
                    "operation": "decrypt", "state": state, "evidence": evidence,
                })
                .to_string();
                write_buf(report.as_bytes(), details, details_len);
                return Err(error);
            }
        };
        let meta = json!({"format": pt.format, "algorithm": pt.algorithm}).to_string();
        let integrity = match pt.format.as_str() {
            FORMAT_F1 => json!({"state":"verified","value":"aead_passed"}),
            FORMAT_F0_STD | FORMAT_F0_SCOMM => {
                json!({"state":"observed","value":"no_authenticated_integrity"})
            }
            _ => json!({"state":"unavailable"}),
        };
        evidence["format"] = json!({"state":"observed","value":pt.format});
        evidence["integrity"] = integrity;
        let evidence = json!({
            "version": 1, "protocol": "smime", "source": "native_operation",
            "operation": "decrypt", "state": "succeeded", "evidence": evidence,
        })
        .to_string();
        write_buf(&pt.plaintext, out, out_len);
        write_buf(meta.as_bytes(), format, format_len);
        write_buf(evidence.as_bytes(), details, details_len);
        Ok(0)
    })
}

#[no_mangle]
pub unsafe extern "C" fn scomm_smime_verify_detached_with_details_v1(
    data: *const u8,
    data_len: usize,
    signature: *const u8,
    signature_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    sender: *const u8,
    sender_len: usize,
    verdict: *mut *mut u8,
    verdict_len: *mut usize,
    details: *mut *mut u8,
    details_len: *mut usize,
) -> i32 {
    if verdict.is_null() || verdict_len.is_null() || details.is_null() || details_len.is_null() {
        return 1;
    }
    *verdict = ptr::null_mut();
    *verdict_len = 0;
    *details = ptr::null_mut();
    *details_len = 0;
    run(|| {
        clear_error();
        let sender = read_opt_str(sender, sender_len);
        let key = (!public_key.is_null() && public_key_len > 0)
            .then(|| read_slice(public_key, public_key_len));
        let (result, algorithms) = engine().verify_detached_with_details(
            read_slice(data, data_len),
            read_slice(signature, signature_len),
            key,
            sender.as_deref(),
        )?;
        let valid = result.validity == SignatureValidity::CryptographicallyValid;
        let mut evidence = json!({});
        if valid {
            evidence["signatureValidity"] = json!({"state":"verified","value":"valid"});
            if let Some(fp) = result.signer_fingerprint.as_ref() {
                evidence["signerSpkiFingerprint"] = json!({"state":"verified","value":fp});
            }
        }
        let provenance = if valid { "observed" } else { "declared" };
        for (field, oid) in [
            ("digestAlgorithm", algorithms.digest_oid),
            ("signatureAlgorithm", algorithms.signature_oid),
        ] {
            if let Some(oid) = oid {
                evidence[field] = json!({
                    "state":provenance, "value":{"namespace":"oid","id":oid},
                });
            }
        }
        let state = match result.validity {
            SignatureValidity::CryptographicallyValid => "succeeded",
            SignatureValidity::UnsupportedAlgorithm => "unsupported",
            SignatureValidity::UnknownSigner => "incomplete",
            _ => "failed",
        };
        let metadata = json!({
            "version": 1, "protocol": "smime", "source": "native_operation",
            "operation": "verify_detached", "state": state, "evidence": evidence,
        })
        .to_string();
        write_buf(verdict_json(&result).as_bytes(), verdict, verdict_len);
        write_buf(metadata.as_bytes(), details, details_len);
        Ok(0)
    })
}

/// Only complete DER envelopes are supported by this metadata-only reader.
#[no_mangle]
pub unsafe extern "C" fn scomm_smime_inspect_public_envelope_v1(
    envelope: *const u8,
    envelope_len: usize,
    input_kind: u32,
    input_extent: u32,
    details: *mut *mut u8,
    details_len: *mut usize,
) -> i32 {
    if details.is_null() || details_len.is_null() {
        return 1;
    }
    *details = ptr::null_mut();
    *details_len = 0;
    if envelope.is_null()
        || envelope_len == 0
        || !matches!(input_kind, 1 | 2)
        || !matches!(input_extent, 1 | 2)
    {
        return 1;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let mut report = json!({
            "version": 1, "protocol": "smime", "source": "public_inspection",
            "operation": "inspect_public_envelope", "state": "unavailable", "evidence": {},
        });
        if input_kind != 1 || input_extent != 1 {
            report["limit"] = json!("unsupported_input_extent");
        } else if envelope_len > 16 * 1024 {
            report["limit"] = json!("input_bytes");
        } else {
            match scomm_smime_cms::inspect_public_envelope(read_slice(envelope, envelope_len)) {
                Ok((format, oid, version, count)) => {
                    report["state"] = json!("complete");
                    report["evidence"] = json!({
                        "container": {"state":"declared","value":format},
                        "contentCipher": {"state":"declared","value":{"namespace":"oid","id":oid}},
                        "containerVersion": {"state":"declared","value":version},
                        "recipientRecordCount": {"state":"declared","value":count},
                    });
                }
                Err(_) => report["state"] = json!("malformed"),
            }
        }
        write_buf(report.to_string().as_bytes(), details, details_len);
        0
    }))
    .unwrap_or(2)
}

/// Largest plaintext `scomm_smime_encrypt` accepts (ABI 3). Anything the
/// engine writes within it can be read back.
#[no_mangle]
pub extern "C" fn scomm_smime_max_plaintext_len() -> usize {
    MAX_PLAINTEXT_LEN
}

/// Referenced by `libscomm_openpgp` so the linker keeps these CMS exports
/// in the one client library.
pub fn link_anchor() -> usize {
    let exports: [*const (); 31] = [
        scomm_smime_buffer_free as *const (),
        scomm_smime_last_error as *const (),
        scomm_smime_inspect as *const (),
        scomm_smime_generate as *const (),
        scomm_smime_export_public as *const (),
        scomm_smime_encrypt as *const (),
        scomm_smime_decrypt as *const (),
        scomm_smime_sign as *const (),
        scomm_smime_verify as *const (),
        scomm_smime_inspect_message as *const (),
        scomm_smime_test_passphrase as *const (),
        scomm_smime_pop_sign_mldsa as *const (),
        scomm_smime_pop_hybrid_shared as *const (),
        scomm_smime_pop_sign_classical as *const (),
        scomm_smime_pop_rsa_decrypt as *const (),
        scomm_smime_abi_version as *const (),
        scomm_smime_verify_detached as *const (),
        scomm_smime_sign_detached as *const (),
        scomm_smime_cert_info as *const (),
        scomm_smime_set_trust_roots as *const (),
        scomm_smime_check_certificate as *const (),
        scomm_smime_add_mldsa_certificates as *const (),
        scomm_smime_decrypt_ex as *const (),
        scomm_smime_decrypt_with_details_v1 as *const (),
        scomm_smime_inspect_public_envelope_v1 as *const (),
        scomm_smime_verify_detached_with_details_v1 as *const (),
        scomm_smime_max_plaintext_len as *const (),
        scomm_smime_remove_entries as *const (),
        scomm_smime_generate_with_validity as *const (),
        scomm_smime_import as *const (),
        scomm_smime_create_csr as *const (),
    ];
    exports
        .iter()
        .fold(0, |n, ptr| n.wrapping_add(*ptr as usize))
}
