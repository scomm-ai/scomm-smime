//! Certificate details for display and key handling (task 3.5, R7), read by
//! OpenSSL. Field names and strings match the Dart `X509CertInfo` it
//! replaces (`lib/features/crypto/data/smime_x509_info.dart`), so callers do
//! not change.

use std::ffi::{c_char, c_int};

use foreign_types::ForeignTypeRef;
use openssl::asn1::{Asn1Time, Asn1TimeRef};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::Id;
use openssl::x509::{X509NameRef, X509};
use openssl_sys as ffi;
use scomm_smime_core::*;

use crate::reader::ossl_failed;
use crate::trust::spki_fingerprint;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct CertInfo {
    pub version: i32,
    pub serial_hex: String,
    pub subject_dn: String,
    pub issuer_dn: String,
    /// Unix seconds.
    pub not_before: i64,
    pub not_after: i64,
    pub public_key_algorithm: String,
    pub key_bits: u32,
    pub sha1_hex: String,
    pub sha256_hex: String,
    /// The pin fingerprint the signature verdict reports (lowercase hex).
    pub spki_sha256_hex: String,
    pub is_self_signed: bool,
    pub key_usages: Vec<String>,
    pub extended_key_usages: Vec<String>,
    pub subject_key_identifier: Option<String>,
    pub email_address: Option<String>,
    pub common_name: Option<String>,
}

/// `KU_*` bits from `openssl/x509v3.h`, in the Dart parser's order.
const KEY_USAGES: [(u32, &str); 9] = [
    (0x0080, "Digital Signature"),
    (0x0040, "Non Repudiation"),
    (0x0020, "Key Encipherment"),
    (0x0010, "Data Encipherment"),
    (0x0008, "Key Agreement"),
    (0x0004, "Certificate Sign"),
    (0x0002, "CRL Sign"),
    (0x0001, "Encipher Only"),
    (0x8000, "Decipher Only"),
];

fn upper_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

fn oid_text(obj: &openssl::asn1::Asn1ObjectRef) -> String {
    let mut buf = [0u8; 128];
    let n = unsafe {
        ffi::OBJ_obj2txt(
            buf.as_mut_ptr() as *mut c_char,
            buf.len() as c_int,
            obj.as_ptr(),
            1,
        )
    };
    let n = (n.max(0) as usize).min(buf.len() - 1);
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

/// `CN=..., O=...` in certificate order, with the Dart parser's names.
fn dn(name: &X509NameRef) -> String {
    name.entries()
        .map(|e| {
            let key = match e.object().nid() {
                Nid::COMMONNAME => "CN".to_string(),
                Nid::COUNTRYNAME => "C".to_string(),
                Nid::LOCALITYNAME => "L".to_string(),
                Nid::STATEORPROVINCENAME => "ST".to_string(),
                Nid::ORGANIZATIONNAME => "O".to_string(),
                Nid::ORGANIZATIONALUNITNAME => "OU".to_string(),
                Nid::PKCS9_EMAILADDRESS => "emailAddress".to_string(),
                _ => oid_text(e.object()),
            };
            let value = e.data().to_string().unwrap_or_default();
            format!("{key}={value}")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn name_value(name: &X509NameRef, nid: Nid) -> Option<String> {
    name.entries_by_nid(nid)
        .next()
        .and_then(|e| e.data().to_string().ok())
}

fn unix(t: &Asn1TimeRef) -> i64 {
    Asn1Time::from_unix(0)
        .ok()
        .and_then(|epoch| epoch.diff(t).ok())
        .map(|d| i64::from(d.days) * 86_400 + i64::from(d.secs))
        .unwrap_or(0)
}

fn extended_key_usages(cert: &X509) -> Vec<String> {
    let mut out = Vec::new();
    unsafe {
        let ext = ffi::X509_get_ext_d2i(
            cert.as_ptr(),
            ffi::NID_ext_key_usage,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ) as *mut ffi::OPENSSL_STACK;
        if ext.is_null() {
            return out;
        }
        for i in 0..ffi::OPENSSL_sk_num(ext) {
            let obj = ffi::OPENSSL_sk_value(ext, i) as *mut ffi::ASN1_OBJECT;
            let text = oid_text(openssl::asn1::Asn1ObjectRef::from_ptr(obj));
            out.push(
                match text.as_str() {
                    "1.3.6.1.5.5.7.3.1" => "TLS Server Authentication",
                    "1.3.6.1.5.5.7.3.2" => "TLS Client Authentication",
                    "1.3.6.1.5.5.7.3.3" => "Code Signing",
                    "1.3.6.1.5.5.7.3.4" => "E-mail Protection",
                    "1.3.6.1.5.5.7.3.8" => "Time Stamping",
                    "1.3.6.1.5.5.7.3.9" => "OCSP Signing",
                    other => other,
                }
                .to_string(),
            );
        }
        ffi::OPENSSL_sk_pop_free(ext, Some(free_object));
    }
    out
}

extern "C" {
    fn X509_get_X509_PUBKEY(x: *const ffi::X509) -> *mut ffi::X509_PUBKEY;
    fn X509_PUBKEY_get0_param(
        ppkalg: *mut *mut ffi::ASN1_OBJECT,
        pk: *mut *const u8,
        ppklen: *mut c_int,
        pa: *mut *mut ffi::X509_ALGOR,
        public: *const ffi::X509_PUBKEY,
    ) -> c_int;
}

fn spki_algorithm_oid(cert: &X509) -> String {
    unsafe {
        let mut obj = std::ptr::null_mut();
        let spki = X509_get_X509_PUBKEY(cert.as_ptr());
        if spki.is_null()
            || X509_PUBKEY_get0_param(
                &mut obj,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                spki,
            ) != 1
            || obj.is_null()
        {
            return String::new();
        }
        oid_text(openssl::asn1::Asn1ObjectRef::from_ptr(obj))
    }
}

unsafe extern "C" fn free_object(p: *mut std::ffi::c_void) {
    ffi::ASN1_OBJECT_free(p as *mut ffi::ASN1_OBJECT);
}

/// Details of one certificate, PEM or DER.
pub fn cert_info(input: &[u8]) -> Result<CertInfo> {
    let cert = if input.trim_ascii_start().starts_with(b"-----BEGIN") {
        X509::from_pem(input)
    } else {
        X509::from_der(input)
    }
    .map_err(|_| ossl_failed(SmimeError::InvalidKey("certificate".into())))?;
    let key = cert
        .public_key()
        .map_err(|_| ossl_failed(SmimeError::InvalidKey("certificate key".into())))?;
    let (algorithm, bits) = match key.id() {
        Id::RSA => ("rsaEncryption".to_string(), key.bits()),
        Id::EC => match key.bits() {
            256 => ("ecdsa-secp256r1".to_string(), 256),
            384 => ("ecdsa-secp384r1".to_string(), 384),
            521 => ("ecdsa-secp521r1".to_string(), 521),
            _ => ("id-ecPublicKey".to_string(), 0),
        },
        Id::ED25519 => ("ed25519".to_string(), 256),
        Id::ED448 => ("ed448".to_string(), 456),
        Id::X25519 => ("x25519".to_string(), 256),
        _ if unsafe { ffi::EVP_PKEY_is_a(key.as_ptr(), c"ML-DSA-65".as_ptr()) } == 1 => {
            ("ml-dsa-65".to_string(), key.bits())
        }
        // As the Dart parser: the SPKI algorithm OID, no size.
        _ => (spki_algorithm_oid(&cert), 0),
    };
    let digest = |md| {
        cert.digest(md)
            .map(|d| upper_hex(&d))
            .map_err(|_| ossl_failed(SmimeError::Internal("digest".into())))
    };
    let raw_ku = unsafe { ffi::X509_get_key_usage(cert.as_ptr()) };
    let key_usages = if raw_ku == u32::MAX {
        Vec::new()
    } else {
        KEY_USAGES
            .iter()
            .filter(|(bit, _)| raw_ku & bit != 0)
            .map(|(_, name)| name.to_string())
            .collect()
    };
    let san_email = cert
        .subject_alt_names()
        .and_then(|names| names.iter().find_map(|n| n.email().map(str::to_string)));
    let serial = cert
        .serial_number()
        .to_bn()
        .and_then(|b| b.to_hex_str().map(|h| h.to_string()))
        .map_err(|_| ossl_failed(SmimeError::InvalidKey("serial".into())))?;
    let serial = serial.trim_start_matches('0');
    let issuer_der = cert.issuer_name().to_der().unwrap_or_default();
    let subject_der = cert.subject_name().to_der().unwrap_or_default();
    let info = CertInfo {
        version: cert.version() + 1,
        serial_hex: if serial.is_empty() { "0" } else { serial }.to_string(),
        subject_dn: dn(cert.subject_name()),
        issuer_dn: dn(cert.issuer_name()),
        not_before: unix(cert.not_before()),
        not_after: unix(cert.not_after()),
        public_key_algorithm: algorithm,
        key_bits: bits,
        sha1_hex: digest(MessageDigest::sha1())?,
        sha256_hex: digest(MessageDigest::sha256())?,
        spki_sha256_hex: spki_fingerprint(&key)?,
        is_self_signed: !issuer_der.is_empty() && issuer_der == subject_der,
        key_usages,
        extended_key_usages: extended_key_usages(&cert),
        subject_key_identifier: cert.subject_key_id().map(|s| upper_hex(s.as_slice())),
        email_address: san_email
            .or_else(|| name_value(cert.subject_name(), Nid::PKCS9_EMAILADDRESS)),
        common_name: name_value(cert.subject_name(), Nid::COMMONNAME),
    };
    let _ = openssl::error::ErrorStack::get();
    Ok(info)
}

#[cfg(test)]
mod tests;
