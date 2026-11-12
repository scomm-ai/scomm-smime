//! Reader for standard CMS encryption, parsed and opened by OpenSSL only
//! (`design.md` D1, D2, D4, D5): AuthEnvelopedData (F1) and other clients'
//! EnvelopedData (F0-std) with RSA key transport.

use std::ffi::{c_char, c_int, c_void};
use std::ptr;

use foreign_types::ForeignType;
use openssl::cms::CmsContentInfo;
use openssl::error::ErrorStack;
use openssl::x509::X509;
use openssl_sys as ffi;
use scomm_smime_core::*;
use yasna::models::ObjectIdentifier;
use yasna::tags::TAG_OCTETSTRING;
use yasna::PCBit;

use crate::bundle::KeyBundle;
use crate::cert::rsa_from_pkcs8;

// Present in the linked libcrypto but not bound by openssl-sys.
extern "C" {
    fn CMS_decrypt_set1_pkey(
        cms: *mut ffi::CMS_ContentInfo,
        pk: *mut ffi::EVP_PKEY,
        cert: *mut ffi::X509,
    ) -> c_int;
    fn OPENSSL_cleanse(ptr: *mut c_void, len: usize);
    fn BIO_free(b: *mut ffi::BIO) -> c_int;
}

/// Drains OpenSSL's error queue so a failure here does not leak into the
/// next caller's error report.
pub(crate) fn ossl_failed(e: SmimeError) -> SmimeError {
    let _ = ErrorStack::get();
    e
}

/// Wipes a buffer that held plaintext or key material.
pub(crate) fn cleanse(buf: &mut [u8]) {
    if !buf.is_empty() {
        unsafe { OPENSSL_cleanse(buf.as_mut_ptr().cast(), buf.len()) };
    }
}

/// RFC 5084 allows GCM tags of 12 to 16 bytes. OpenSSL 4.1 CMS accepts a
/// `mac` as short as 4 bytes (forgeable by trial at about 2^-32), so the
/// engine enforces the range itself.
const GCM_TAG_LEN: std::ops::RangeInclusive<usize> = 12..=16;
const AUTH_ENVELOPED_ARCS: &[u64] = &[1, 2, 840, 113549, 1, 9, 16, 1, 23];

/// Length of the AuthEnvelopedData `mac`, or `None` for any other content
/// type. `der` is OpenSSL's own DER re-encoding, so BER input is covered.
/// `mac` is the only universal OCTET STRING directly inside
/// AuthEnvelopedData (RFC 5083 section 2.1).
fn auth_tag_len(der: &[u8]) -> Result<Option<usize>> {
    let auth_enveloped = ObjectIdentifier::from_slice(AUTH_ENVELOPED_ARCS);
    yasna::parse_der(der, |r| {
        r.read_sequence(|r| {
            if r.next().read_oid()? != auth_enveloped {
                r.next().read_der()?;
                return Ok(None);
            }
            r.next().read_tagged(yasna::Tag::context(0), |r| {
                r.read_sequence(|r| {
                    let mut mac = None;
                    while let Some(v) = r.read_optional(|r| r.read_tagged_der())? {
                        if mac.is_none()
                            && v.tag() == TAG_OCTETSTRING
                            && v.pcbit() == PCBit::Primitive
                        {
                            mac = Some(v.value().len());
                        }
                    }
                    Ok(mac.or(Some(0)))
                })
            })
        })
    })
    .map_err(|_| SmimeError::MalformedMessage)
}

/// D5: decrypts the content with the CEK a recipient already set. Bytes leave
/// only if OpenSSL reports success; the buffer is cleansed either way.
pub(crate) unsafe fn release_plaintext(cms: &CmsContentInfo) -> Result<Vec<u8>> {
    let der = cms
        .to_der()
        .map_err(|_| ossl_failed(SmimeError::MalformedMessage))?;
    if let Some(n) = auth_tag_len(&der)? {
        if !GCM_TAG_LEN.contains(&n) {
            return Err(SmimeError::DecryptionFailed);
        }
    }
    let out = ffi::BIO_new(ffi::BIO_s_mem());
    if out.is_null() {
        return Err(ossl_failed(SmimeError::Internal("BIO".into())));
    }
    let ok = ffi::CMS_decrypt(
        cms.as_ptr(),
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        out,
        ffi::CMS_BINARY,
    );
    let mut data: *mut c_char = ptr::null_mut();
    let n = ffi::BIO_get_mem_data(out, &mut data).max(0) as usize;
    let result = if ok == 1 {
        Ok(if n == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(data as *const u8, n).to_vec()
        })
    } else {
        Err(ossl_failed(SmimeError::DecryptionFailed))
    };
    if n > 0 {
        OPENSSL_cleanse(data.cast(), n);
    }
    BIO_free(out);
    result
}

/// Opens a standard enveloped message with the bundle's RSA keys (D2).
///
/// Each key is offered with its certificate, so OpenSSL only tries the
/// KeyTransRecipientInfo naming that certificate. When that RSA decryption
/// fails OpenSSL still reports a match and goes on with a random CEK, so a
/// bad wrapped key and bad content look the same (`cms_smime.c`, MMA defence);
/// the content step then fails. A failing key does not stop the next (D4).
pub(crate) fn decrypt(
    der: &[u8],
    authenticated: bool,
    bundle: &KeyBundle,
) -> Result<DecryptResult> {
    let cms =
        CmsContentInfo::from_der(der).map_err(|_| ossl_failed(SmimeError::MalformedMessage))?;
    let format = if authenticated {
        FORMAT_F1
    } else {
        FORMAT_F0_STD
    };
    let mut matched = false;
    let mut bad_key = None;
    for entry in bundle
        .encryption_entries()
        .filter(|e| e.alg.contains("rsa") && !e.cert_pem.is_empty())
    {
        let Some(pkcs8) = entry.pkcs8_b64.as_ref() else {
            continue;
        };
        let loaded = rsa_from_pkcs8(pkcs8.as_bytes()).and_then(|key| {
            X509::from_pem(entry.cert_pem.as_bytes())
                .map(|cert| (key, cert))
                .map_err(|_| ossl_failed(SmimeError::InvalidKey("X.509".into())))
        });
        let (key, cert) = match loaded {
            Ok(pair) => pair,
            Err(e) => {
                bad_key = Some(e);
                continue;
            }
        };
        if unsafe { CMS_decrypt_set1_pkey(cms.as_ptr(), key.as_ptr(), cert.as_ptr()) } != 1 {
            let _ = ErrorStack::get();
            continue;
        }
        matched = true;
        if let Ok(plaintext) = unsafe { release_plaintext(&cms) } {
            return Ok(DecryptResult {
                plaintext,
                algorithm: entry.alg.clone(),
                format: format.to_string(),
            });
        }
    }
    Err(if matched {
        SmimeError::DecryptionFailed
    } else {
        bad_key.unwrap_or(SmimeError::WrongPrivateKey)
    })
}
