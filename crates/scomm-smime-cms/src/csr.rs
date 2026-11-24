//! PKCS#10 certificate requests for a CA-issued S/MIME certificate (ABI 7).
//!
//! The key is generated here and returned with the request; the caller
//! stores it before showing the request. Only RSA is offered: it is the one
//! key type the app imports, signs and decrypts with once a CA has issued
//! the certificate. Nothing is sent anywhere.

use openssl::hash::{hash, MessageDigest};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::x509::extension::{ExtendedKeyUsage, KeyUsage, SubjectAlternativeName};
use openssl::x509::{X509NameBuilder, X509ReqBuilder};
use scomm_smime_core::*;
use serde::{Deserialize, Serialize};

use crate::bundle::b64_encode;

/// RSA sizes a request may use.
pub const CSR_KEY_BITS: [u32; 2] = [2048, 3072];

#[derive(Debug, Deserialize)]
pub struct CsrRequest {
    pub email: String,
    /// Individual-validated requests put the person's name in the subject
    /// CN; mailbox-validated ones leave it out and use the address.
    #[serde(default)]
    pub name: Option<String>,
    pub key_bits: u32,
    pub sign: bool,
    pub encrypt: bool,
}

#[derive(Debug, Serialize)]
pub struct CsrResult {
    pub csr_pem: String,
    /// The new private key, unencrypted PKCS#8 DER. Store it at once.
    pub pkcs8_b64: String,
    pub spki_b64: String,
    /// SHA-256 of the SubjectPublicKeyInfo, upper-case hex.
    pub spki_sha256: String,
}

fn invalid(what: &str) -> SmimeError {
    SmimeError::InvalidArgument(what.into())
}

fn ossl(e: openssl::error::ErrorStack) -> SmimeError {
    SmimeError::Internal(format!("csr: {e}"))
}

/// One `local@domain`, printable ASCII, no spaces (SAN rfc822Name is IA5).
fn valid_email(email: &str) -> bool {
    let mut parts = email.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    email.len() <= 254
        && !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && email.bytes().all(|b| b.is_ascii_graphic())
}

pub fn create_csr(req: &CsrRequest) -> Result<CsrResult> {
    let email = req.email.trim();
    if !valid_email(email) {
        return Err(invalid("csr email"));
    }
    if !CSR_KEY_BITS.contains(&req.key_bits) {
        return Err(SmimeError::UnsupportedAlgorithm(format!("RSA-{}", req.key_bits)));
    }
    if !req.sign && !req.encrypt {
        return Err(invalid("csr purpose"));
    }
    let name = req.name.as_deref().map(str::trim).filter(|n| !n.is_empty());
    // X.520 upper bound for commonName.
    if name.is_some_and(|n| n.chars().count() > 64 || n.chars().any(char::is_control)) {
        return Err(invalid("csr name"));
    }

    let key = PKey::from_rsa(Rsa::generate(req.key_bits).map_err(ossl)?).map_err(ossl)?;

    let mut subject = X509NameBuilder::new().map_err(ossl)?;
    subject
        .append_entry_by_nid(Nid::COMMONNAME, name.unwrap_or(email))
        .map_err(ossl)?;
    subject
        .append_entry_by_nid(Nid::PKCS9_EMAILADDRESS, email)
        .map_err(ossl)?;
    let subject = subject.build();

    let mut builder = X509ReqBuilder::new().map_err(ossl)?;
    builder.set_version(0).map_err(ossl)?;
    builder.set_subject_name(&subject).map_err(ossl)?;
    builder.set_pubkey(&key).map_err(ossl)?;
    let mut extensions = Stack::new().map_err(ossl)?;
    let san = SubjectAlternativeName::new()
        .email(email)
        .build(&builder.x509v3_context(None))
        .map_err(ossl)?;
    extensions.push(san).map_err(ossl)?;
    let mut usage = KeyUsage::new();
    usage.critical();
    if req.sign {
        usage.digital_signature();
    }
    if req.encrypt {
        usage.key_encipherment();
    }
    extensions.push(usage.build().map_err(ossl)?).map_err(ossl)?;
    extensions
        .push(ExtendedKeyUsage::new().email_protection().build().map_err(ossl)?)
        .map_err(ossl)?;
    builder.add_extensions(&extensions).map_err(ossl)?;
    builder.sign(&key, MessageDigest::sha256()).map_err(ossl)?;
    let csr = builder.build();

    // Re-read what will be handed out and check its self-signature.
    let pem = csr.to_pem().map_err(ossl)?;
    let parsed = openssl::x509::X509Req::from_pem(&pem).map_err(ossl)?;
    let public = parsed.public_key().map_err(ossl)?;
    if !public.public_eq(&key) || !parsed.verify(&public).map_err(ossl)? {
        return Err(SmimeError::Internal("csr self-signature".into()));
    }

    let spki = public.public_key_to_der().map_err(ossl)?;
    let digest = hash(MessageDigest::sha256(), &spki).map_err(ossl)?;
    Ok(CsrResult {
        csr_pem: String::from_utf8(pem).map_err(|_| SmimeError::Internal("csr pem".into()))?,
        pkcs8_b64: b64_encode(&key.private_key_to_pkcs8().map_err(ossl)?),
        spki_b64: b64_encode(&spki),
        spki_sha256: digest.iter().map(|b| format!("{b:02X}")).collect(),
    })
}

#[cfg(test)]
mod tests;
