//! S1: RFC 5652 SignedData, detached, built and checked by OpenSSL CMS
//! (`design.md` "Signatures", R5). RSA PKCS#1 v1.5 is live from Release 1;
//! RSA-PSS, Ed25519 and ML-DSA-65 replace their S0 writers when
//! [crate::RELEASE_2_WRITERS] is on. The verifier reads every algorithm in
//! both releases.

use std::ffi::{c_int, c_uint, c_void};
use std::ptr;

use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::cms::{CMSOptions, CmsContentInfo};
use openssl::pkey::{Id, PKey, Private};
use openssl::stack::Stack;
use openssl::x509::{X509Ref, X509};
use openssl_sys as ffi;
use scomm_smime_core::*;

use crate::bundle::{b64_decode, KeyEntry};
use crate::cert::rsa_from_pkcs8;
use crate::pqc;
use crate::reader::ossl_failed;
use crate::trust::{chain_status, email_match, spki_fingerprint};

// Present in the linked libcrypto but not bound by openssl-sys.
extern "C" {
    fn CMS_sign_ex(
        signcert: *mut ffi::X509,
        pkey: *mut ffi::EVP_PKEY,
        certs: *mut c_void,
        data: *mut ffi::BIO,
        flags: c_uint,
        libctx: *mut c_void,
        propq: *const std::ffi::c_char,
    ) -> *mut ffi::CMS_ContentInfo;
    fn CMS_add1_signer(
        cms: *mut ffi::CMS_ContentInfo,
        signer: *mut ffi::X509,
        pk: *mut ffi::EVP_PKEY,
        md: *const ffi::EVP_MD,
        flags: c_uint,
    ) -> *mut c_void;
    fn CMS_SignerInfo_get0_pkey_ctx(si: *mut c_void) -> *mut ffi::EVP_PKEY_CTX;
    fn CMS_final(
        cms: *mut ffi::CMS_ContentInfo,
        data: *mut ffi::BIO,
        dcont: *mut ffi::BIO,
        flags: c_uint,
    ) -> c_int;
    fn EVP_PKEY_CTX_set_rsa_padding(ctx: *mut ffi::EVP_PKEY_CTX, pad: c_int) -> c_int;
    fn EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx: *mut ffi::EVP_PKEY_CTX, len: c_int) -> c_int;
    fn EVP_PKEY_CTX_set_rsa_mgf1_md(ctx: *mut ffi::EVP_PKEY_CTX, md: *const ffi::EVP_MD) -> c_int;
    fn BIO_free(b: *mut ffi::BIO) -> c_int;
    fn CMS_get0_SignerInfos(cms: *mut ffi::CMS_ContentInfo) -> *mut ffi::OPENSSL_STACK;
    fn CMS_set1_signers_certs(
        cms: *mut ffi::CMS_ContentInfo,
        certs: *mut ffi::stack_st_X509,
        flags: c_uint,
    ) -> c_int;
    fn CMS_SignerInfo_get0_algs(
        si: *mut c_void,
        pk: *mut *mut ffi::EVP_PKEY,
        signer: *mut *mut ffi::X509,
        pdig: *mut *mut ffi::X509_ALGOR,
        psig: *mut *mut ffi::X509_ALGOR,
    );
    fn CMS_get1_certs(cms: *mut ffi::CMS_ContentInfo) -> *mut ffi::stack_st_X509;
}

/// `openssl/cms.h` and `openssl/rsa.h`.
const CMS_DETACHED: c_uint = 0x40;
const CMS_BINARY: c_uint = 0x80;
const CMS_NOSMIMECAP: c_uint = 0x200;
const CMS_PARTIAL: c_uint = 0x4000;
const CMS_KEY_PARAM: c_uint = 0x40000;
const RSA_PKCS1_PSS_PADDING: c_int = 6;
const PSS_SALT_LEN: c_int = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SignAlg {
    RsaPkcs1,
    RsaPss,
    Ed25519,
    MlDsa65,
}

impl SignAlg {
    pub(crate) fn from_name(name: &str) -> Option<SignAlg> {
        Some(match name {
            ALG_RSA_PKCS1 => SignAlg::RsaPkcs1,
            ALG_RSA_PSS => SignAlg::RsaPss,
            ALG_ED25519 => SignAlg::Ed25519,
            ALG_MLDSA65 => SignAlg::MlDsa65,
            _ => return None,
        })
    }

    /// Which bundle entries can sign with this algorithm.
    pub(crate) fn matches_entry(self, alg: &str) -> bool {
        match self {
            SignAlg::RsaPkcs1 | SignAlg::RsaPss => alg.contains("rsa"),
            SignAlg::Ed25519 => alg == ALG_ED25519,
            SignAlg::MlDsa65 => is_pqc_catalog(alg),
        }
    }

    /// Message digest: SHA-256 for RSA; SHA-512 for Ed25519 (RFC 8419) and
    /// ML-DSA-65 (RFC 9882).
    fn digest(self) -> *const ffi::EVP_MD {
        unsafe {
            match self {
                SignAlg::RsaPkcs1 | SignAlg::RsaPss => ffi::EVP_sha256(),
                SignAlg::Ed25519 | SignAlg::MlDsa65 => ffi::EVP_sha512(),
            }
        }
    }

    fn private_key(self, entry: &KeyEntry) -> Result<PKey<Private>> {
        let secret = entry
            .pkcs8_b64
            .as_ref()
            .ok_or(SmimeError::NoSuitableSigningKey)?;
        match self {
            SignAlg::RsaPkcs1 | SignAlg::RsaPss => rsa_from_pkcs8(secret.as_bytes()),
            SignAlg::Ed25519 => PKey::private_key_from_raw_bytes(&b64_decode(secret)?, Id::ED25519)
                .map_err(|_| ossl_failed(SmimeError::InvalidKey("Ed25519 seed".into()))),
            SignAlg::MlDsa65 => pqc::mldsa_pkey(&b64_decode(secret)?),
        }
    }
}

/// Detached SignedData over `data` with the entry's certificate as the only
/// certificate and content type, message digest and signing time as the
/// only signed attributes.
pub(crate) fn sign(data: &[u8], entry: &KeyEntry, alg: SignAlg) -> Result<Vec<u8>> {
    sign_with_digest(data, entry, alg, alg.digest())
}

/// [sign] with an explicit message digest; tests use it to make weak
/// signatures the writer itself never produces.
fn sign_with_digest(
    data: &[u8],
    entry: &KeyEntry,
    alg: SignAlg,
    digest: *const ffi::EVP_MD,
) -> Result<Vec<u8>> {
    if entry.cert_pem.is_empty() {
        return Err(SmimeError::NoSuitableSigningKey);
    }
    let cert = X509::from_pem(entry.cert_pem.as_bytes())
        .map_err(|_| ossl_failed(SmimeError::InvalidKey("X.509".into())))?;
    let key = alg.private_key(entry)?;
    let len = c_int::try_from(data.len())
        .map_err(|_| SmimeError::InvalidArgument("message too large".into()))?;
    let flags = CMS_DETACHED | CMS_BINARY | CMS_NOSMIMECAP;
    unsafe {
        let raw = CMS_sign_ex(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            flags | CMS_PARTIAL,
            ptr::null_mut(),
            ptr::null(),
        );
        if raw.is_null() {
            return Err(ossl_failed(SmimeError::Internal("CMS_sign_ex".into())));
        }
        let cms = CmsContentInfo::from_ptr(raw);
        let key_param = if alg == SignAlg::RsaPss {
            CMS_KEY_PARAM
        } else {
            0
        };
        // Checks that the key belongs to the certificate.
        let si = CMS_add1_signer(
            cms.as_ptr(),
            cert.as_ptr(),
            key.as_ptr(),
            digest,
            flags | key_param,
        );
        if si.is_null() {
            return Err(ossl_failed(SmimeError::InvalidKey(
                "signing key and certificate".into(),
            )));
        }
        if alg == SignAlg::RsaPss {
            let ctx = CMS_SignerInfo_get0_pkey_ctx(si);
            if ctx.is_null()
                || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0
                || EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, PSS_SALT_LEN) <= 0
                || EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, ffi::EVP_sha256()) <= 0
            {
                return Err(ossl_failed(SmimeError::Internal("RSA-PSS".into())));
            }
        }
        let input = ffi::BIO_new_mem_buf(data.as_ptr().cast(), len);
        if input.is_null() {
            return Err(ossl_failed(SmimeError::Internal("BIO".into())));
        }
        let ok = CMS_final(cms.as_ptr(), input, ptr::null_mut(), flags);
        BIO_free(input);
        if ok != 1 {
            return Err(ossl_failed(SmimeError::Internal("CMS_final".into())));
        }
        cms.to_der()
            .map_err(|e| SmimeError::Internal(e.to_string()))
    }
}

/// Catalog name of the single signer's signature algorithm, for
/// `inspect_message`: ML-DSA-65 and Ed25519 by OID, anything else RSA.
/// `None` when the SignedData does not parse or has no single signer.
pub(crate) fn signer_algorithm(der: &[u8]) -> Option<&'static str> {
    let cms = CmsContentInfo::from_der(der).ok();
    let _ = openssl::error::ErrorStack::get();
    let cms = cms?;
    unsafe {
        let infos = CMS_get0_SignerInfos(cms.as_ptr());
        if infos.is_null() || ffi::OPENSSL_sk_num(infos) != 1 {
            return None;
        }
        let si = ffi::OPENSSL_sk_value(infos, 0);
        let (mut pk, mut signer, mut dig, mut sig) = (
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        CMS_SignerInfo_get0_algs(si, &mut pk, &mut signer, &mut dig, &mut sig);
        if sig.is_null() {
            return None;
        }
        let mut obj: *const ffi::ASN1_OBJECT = ptr::null();
        ffi::X509_ALGOR_get0(&mut obj, ptr::null_mut(), ptr::null_mut(), sig);
        let mut buf = [0u8; 64];
        let n = ffi::OBJ_obj2txt(buf.as_mut_ptr().cast(), buf.len() as c_int, obj, 1);
        let oid = std::str::from_utf8(&buf[..n.max(0) as usize]).ok()?;
        Some(match oid {
            "2.16.840.1.101.3.4.3.18" => scomm_smime_core::ALG_MLDSA65,
            "1.3.101.112" => scomm_smime_core::ALG_ED25519,
            _ => scomm_smime_core::ALG_RSA_PKCS1,
        })
    }
}

/// SHA-1 and MD5 message digests are weak (N1 for S/MIME).
unsafe fn digest_is_weak(alg: *mut ffi::X509_ALGOR) -> bool {
    if alg.is_null() {
        return false;
    }
    let mut obj: *const ffi::ASN1_OBJECT = ptr::null();
    ffi::X509_ALGOR_get0(&mut obj, ptr::null_mut(), ptr::null_mut(), alg);
    matches!(ffi::OBJ_obj2nid(obj), ffi::NID_sha1 | ffi::NID_md5)
}

/// S1 verdict for a detached SignedData over `data` (task 3.2). The signer
/// certificate comes from the message, or from `known` (certificates the
/// app already holds for the sender) when the message carries none.
/// Exactly one signer is accepted.
pub(crate) fn verify(
    data: &[u8],
    der: &[u8],
    known: &[X509],
    sender: Option<&str>,
) -> Result<SignatureVerdict> {
    let base = SignatureVerdict {
        format: Some(SignatureFormat::S1),
        ..SignatureVerdict::malformed()
    };
    let Ok(mut cms) = CmsContentInfo::from_der(der) else {
        let _ = openssl::error::ErrorStack::get();
        return Ok(base);
    };
    let internal = |_| ossl_failed(SmimeError::Internal("stack".into()));
    let mut known_stack = Stack::new().map_err(internal)?;
    for c in known {
        known_stack.push(c.clone()).map_err(internal)?;
    }
    let (cert, weak_digest) = unsafe {
        let infos = CMS_get0_SignerInfos(cms.as_ptr());
        if infos.is_null() || ffi::OPENSSL_sk_num(infos) != 1 {
            let _ = openssl::error::ErrorStack::get();
            return Ok(base);
        }
        CMS_set1_signers_certs(cms.as_ptr(), known_stack.as_ptr(), 0);
        let si = ffi::OPENSSL_sk_value(infos, 0);
        let (mut pk, mut signer, mut dig, mut sig) = (
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        CMS_SignerInfo_get0_algs(si, &mut pk, &mut signer, &mut dig, &mut sig);
        let _ = openssl::error::ErrorStack::get();
        if signer.is_null() {
            return Ok(SignatureVerdict {
                validity: SignatureValidity::UnknownSigner,
                ..base
            });
        }
        (X509Ref::from_ptr(signer).to_owned(), digest_is_weak(dig))
    };
    // Signature math only; the chain is judged separately below.
    let math = cms
        .verify(
            Some(&known_stack),
            None,
            Some(data),
            None,
            CMSOptions::NO_SIGNER_CERT_VERIFY | CMSOptions::BINARY | CMSOptions::DETACHED,
        )
        .is_ok();
    let _ = openssl::error::ErrorStack::get();
    let untrusted = unsafe {
        let certs = CMS_get1_certs(cms.as_ptr());
        if certs.is_null() {
            Stack::new().map_err(internal)?
        } else {
            Stack::<X509>::from_ptr(certs)
        }
    };
    let key = cert
        .public_key()
        .map_err(|_| ossl_failed(SmimeError::InvalidKey("signer public key".into())))?;
    let weak_key = key.id() == Id::RSA && key.bits() < 2048;
    Ok(SignatureVerdict {
        validity: if math {
            SignatureValidity::CryptographicallyValid
        } else {
            SignatureValidity::CryptographicallyInvalid
        },
        format: Some(SignatureFormat::S1),
        signer_fingerprint: Some(spki_fingerprint(&key)?),
        signer_cert_pem: cert.to_pem().ok().and_then(|p| String::from_utf8(p).ok()),
        chain: chain_status(&cert, &untrusted, CertPurpose::SmimeSign),
        email_match: sender.map(|e| email_match(&cert, e)),
        weak_algorithm: weak_digest || weak_key,
        revocation_checked: false,
    })
}

#[cfg(test)]
mod tests;
