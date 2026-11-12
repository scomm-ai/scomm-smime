//! Path B (`design.md` "Trust model", R4): offline chain checks against the
//! bundled Mozilla e-mail roots, the S/MIME purposes, and the e-mail match.
//! Revocation is never checked (no server contact).

use std::sync::RwLock;

use foreign_types::ForeignTypeRef;
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::{HasPublic, PKeyRef};
use openssl::stack::{Stack, StackRef};
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::x509::{X509PurposeId, X509Ref, X509StoreContext, X509VerifyResult, X509};
use openssl_sys as ffi;
use scomm_smime_core::*;

use crate::reader::ossl_failed;

/// `X509_V_ERR_*` from `openssl/x509_vfy.h`.
const ERR_CERT_NOT_YET_VALID: i32 = 9;
const ERR_CERT_HAS_EXPIRED: i32 = 10;
const ERR_INVALID_PURPOSE: i32 = 26;

struct Roots {
    sign: X509Store,
    encrypt: X509Store,
}

/// Set once at startup by the app; replaced whole on every call.
static ROOTS: RwLock<Option<Roots>> = RwLock::new(None);

fn store(roots: &[X509], purpose: X509PurposeId) -> Result<X509Store> {
    let failed = |_| ossl_failed(SmimeError::Internal("X509_STORE".into()));
    let mut b = X509StoreBuilder::new().map_err(failed)?;
    for cert in roots {
        b.add_cert(cert.clone()).map_err(failed)?;
    }
    b.set_purpose(purpose).map_err(failed)?;
    Ok(b.build())
}

/// Loads the bundled roots (a PEM file of certificates) and returns how many
/// were read. Empty input clears them, so nothing chains to a root.
pub fn set_trust_roots(pem: &[u8]) -> Result<usize> {
    let roots = if pem.iter().all(u8::is_ascii_whitespace) {
        Vec::new()
    } else {
        X509::stack_from_pem(pem)
            .map_err(|_| ossl_failed(SmimeError::InvalidArgument("trust roots PEM".into())))?
    };
    let built = Roots {
        sign: store(&roots, X509PurposeId::SMIME_SIGN)?,
        encrypt: store(&roots, X509PurposeId::SMIME_ENCRYPT)?,
    };
    *ROOTS.write().unwrap_or_else(|e| e.into_inner()) = Some(built);
    Ok(roots.len())
}

/// Lowercase hex SHA-256 of the SubjectPublicKeyInfo DER.
pub(crate) fn spki_fingerprint<T: HasPublic>(key: &PKeyRef<T>) -> Result<String> {
    let der = key
        .public_key_to_der()
        .map_err(|_| ossl_failed(SmimeError::InvalidKey("public key".into())))?;
    let d = openssl::hash::hash(MessageDigest::sha256(), &der)
        .map_err(|e| SmimeError::Internal(e.to_string()))?;
    Ok(d.iter().map(|b| format!("{b:02x}")).collect())
}

pub(crate) fn email_match(cert: &X509Ref, email: &str) -> bool {
    let ok = unsafe { ffi::X509_check_email(cert.as_ptr(), email.as_ptr().cast(), email.len(), 0) };
    ok == 1
}

/// Validity window first, so a self-signed (path A) certificate still
/// reports expiry; then the chain to the bundled roots for `purpose`.
pub(crate) fn chain_status(
    cert: &X509Ref,
    untrusted: &StackRef<X509>,
    purpose: CertPurpose,
) -> ChainStatus {
    let Ok(now) = Asn1Time::days_from_now(0) else {
        return ChainStatus::UntrustedRoot;
    };
    if cert.not_before() > now {
        return ChainStatus::NotYetValid;
    }
    if cert.not_after() < now {
        return ChainStatus::Expired;
    }
    let guard = ROOTS.read().unwrap_or_else(|e| e.into_inner());
    let Some(roots) = guard.as_ref() else {
        return ChainStatus::UntrustedRoot;
    };
    let store = match purpose {
        CertPurpose::SmimeSign => &roots.sign,
        CertPurpose::SmimeEncrypt => &roots.encrypt,
    };
    let result = X509StoreContext::new().and_then(|mut ctx| {
        ctx.init(store, cert, untrusted, |c| {
            c.verify_cert()?;
            Ok(c.error())
        })
    });
    let _ = openssl::error::ErrorStack::get();
    match result {
        Ok(e) if e == X509VerifyResult::OK => ChainStatus::TrustedRoot,
        Ok(e) => match e.as_raw() {
            ERR_INVALID_PURPOSE => ChainStatus::WrongPurpose,
            ERR_CERT_HAS_EXPIRED => ChainStatus::Expired,
            ERR_CERT_NOT_YET_VALID => ChainStatus::NotYetValid,
            _ => ChainStatus::UntrustedRoot,
        },
        Err(_) => ChainStatus::UntrustedRoot,
    }
}

/// Checks a certificate the app holds (for example an external recipient
/// chosen for encryption) for `purpose`, and its e-mail when given.
pub fn check_certificate(
    cert_pem: &[u8],
    email: Option<&str>,
    purpose: CertPurpose,
) -> Result<CertCheck> {
    let mut chain = X509::stack_from_pem(cert_pem)
        .map_err(|_| ossl_failed(SmimeError::InvalidKey("certificate PEM".into())))?
        .into_iter();
    let leaf = chain
        .next()
        .ok_or_else(|| SmimeError::InvalidKey("certificate PEM".into()))?;
    let mut untrusted =
        Stack::new().map_err(|_| ossl_failed(SmimeError::Internal("stack".into())))?;
    for c in chain {
        untrusted
            .push(c)
            .map_err(|_| ossl_failed(SmimeError::Internal("stack".into())))?;
    }
    Ok(CertCheck {
        chain: chain_status(&leaf, &untrusted, purpose),
        email_match: email.map(|e| email_match(&leaf, e)),
    })
}

#[cfg(test)]
pub(crate) fn clear_trust_roots() {
    *ROOTS.write().unwrap_or_else(|e| e.into_inner()) = None;
}

#[cfg(test)]
mod tests;
