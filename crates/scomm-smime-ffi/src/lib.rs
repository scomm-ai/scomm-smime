//! C ABI. CMS engine types do not cross this boundary.

use std::cell::RefCell;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;

use scomm_smime_cms::CmsSmime;
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
            return Err(SmimeError::InvalidArgument("truncated recipient key".into()));
        }
        out.push(buf[i..i + len].to_vec());
        i += len;
    }
    Ok(out)
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
pub unsafe extern "C" fn scomm_smime_last_error(
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
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
    let userid = String::from_utf8_lossy(read_slice(userid, userid_len)).into_owned();
    let pass = if passphrase.is_null() || passphrase_len == 0 {
        None
    } else {
        Some(String::from_utf8_lossy(read_slice(passphrase, passphrase_len)).into_owned())
    };
    let profile = match profile {
        0 => KeyProfile::Classical,
        1 => KeyProfile::PqcCms,
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
        })?;
        unsafe {
            write_buf(&generated.public, public_out, public_len);
            write_buf(&generated.secret, secret_out, secret_len);
            write_buf(key_info_json(&generated.info).as_bytes(), json_out, json_len);
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
        let sig = engine().sign(&data, &private_key, pass.as_deref(), &SignOptions::default())?;
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
        let shared = engine().pop_hybrid_shared(
            &private_key,
            pass.as_deref(),
            &kem,
            &eph,
        )?;
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
