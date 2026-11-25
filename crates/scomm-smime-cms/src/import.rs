//! Reads the S/MIME files CAs and mail clients hand out (ABI 6): PKCS#12
//! (`.p12`/`.pfx`), PEM and DER certificates, PKCS#7 bundles (`.p7b`/`.p7c`,
//! PEM or DER), PKCS#8 / PKCS#1 / SEC1 private keys, encrypted PKCS#8 and
//! OpenSSL `Proc-Type: 4,ENCRYPTED` keys, alone or as several files.
//!
//! Only text formatting is normalized: CRLF or LF, spaces and the whole PEM
//! block on one line (as some CAs send PKCS#7). Base64 and DER are never
//! repaired; anything that does not decode exactly is refused. Nothing read
//! here is trusted: CA certificates are returned, never added to the roots.

use std::os::raw::c_int;
use std::sync::Once;

use base64::Engine;
use foreign_types::ForeignType;
use openssl::error::ErrorStack;
use openssl::pkcs12::Pkcs12;
use openssl::pkcs7::Pkcs7;
use openssl::pkey::{Id, PKey, Private};
use openssl::provider::Provider;
use openssl::x509::X509;
use scomm_smime_core::*;
use serde::Serialize;

use crate::bundle::b64_encode;

/// Largest single import file read (a PFX with a long chain is ~20 KB).
pub const MAX_IMPORT_FILE_LEN: usize = 4 * 1024 * 1024;

extern "C" {
    fn X509_check_ca(x: *mut openssl_sys::X509) -> c_int;
}

#[derive(Debug, Serialize)]
pub struct ImportedCertificate {
    pub cert_pem: String,
    pub spki_b64: String,
    /// basicConstraints cA, or keyCertSign without basicConstraints.
    pub is_ca: bool,
    /// `rsa`, `ec`, `ed25519`, … (the certificate's key type).
    pub key_algorithm: String,
    /// The matching private key as unencrypted PKCS#8 DER, when the import
    /// carried it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pkcs8_b64: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ImportResult {
    pub certificates: Vec<ImportedCertificate>,
    /// Private keys that match none of the certificates.
    pub unmatched_keys: usize,
}

#[derive(Default)]
struct Collected {
    certs: Vec<X509>,
    keys: Vec<PKey<Private>>,
}

impl Collected {
    fn add_cert(&mut self, cert: X509) -> Result<()> {
        let der = cert.to_der().map_err(|_| malformed())?;
        if !self.certs.iter().any(|c| c.to_der().ok().as_deref() == Some(&der)) {
            self.certs.push(cert);
        }
        Ok(())
    }

    fn add_key(&mut self, key: PKey<Private>) {
        if !self.keys.iter().any(|k| k.public_eq(&key)) {
            self.keys.push(key);
        }
    }
}

fn malformed() -> SmimeError {
    SmimeError::InvalidKey("malformed import file".into())
}

fn unsupported_format() -> SmimeError {
    SmimeError::InvalidArgument("unsupported import file".into())
}

/// RC2-40 and 3DES PFX files (Windows, older OpenSSL) need the legacy
/// provider for RC2. Loaded once next to the default one; when this build
/// has no legacy provider, such files are refused as unsupported.
fn load_legacy_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if let Ok(p) = Provider::try_load(None, "legacy", true) {
            std::mem::forget(p);
        }
        let _ = ErrorStack::get();
    });
}

pub fn import(files: &[Vec<u8>], password: &str) -> Result<ImportResult> {
    load_legacy_provider();
    let mut out = Collected::default();
    for file in files {
        if file.len() > MAX_IMPORT_FILE_LEN {
            return Err(SmimeError::InvalidArgument("import file too large".into()));
        }
        read_file(file, password, &mut out)?;
    }
    let _ = ErrorStack::get();
    let mut used = vec![false; out.keys.len()];
    let mut certificates = Vec::with_capacity(out.certs.len());
    for cert in &out.certs {
        let public = cert.public_key().map_err(|_| malformed())?;
        let matched = out.keys.iter().position(|k| k.public_eq(&public));
        let pkcs8_b64 = match matched {
            Some(i) => {
                used[i] = true;
                Some(b64_encode(
                    &out.keys[i].private_key_to_pkcs8().map_err(|_| malformed())?,
                ))
            }
            None => None,
        };
        let ca = unsafe { X509_check_ca(cert.as_ptr()) };
        certificates.push(ImportedCertificate {
            cert_pem: String::from_utf8(cert.to_pem().map_err(|_| malformed())?)
                .map_err(|_| malformed())?,
            spki_b64: b64_encode(&public.public_key_to_der().map_err(|_| malformed())?),
            // 1: basicConstraints cA; 4: keyCertSign without it; 5: Netscape
            // CA type. 3 (any self-signed v1 certificate) is not a CA here.
            is_ca: matches!(ca, 1 | 4 | 5),
            key_algorithm: key_algorithm(public.id()),
            pkcs8_b64,
        });
    }
    // Personal certificates first, then end-entity, then CAs.
    certificates.sort_by_key(|c| (c.pkcs8_b64.is_none(), c.is_ca));
    Ok(ImportResult {
        certificates,
        unmatched_keys: used.iter().filter(|u| !**u).count(),
    })
}

fn key_algorithm(id: Id) -> String {
    match id {
        Id::RSA | Id::RSA_PSS => "rsa",
        Id::EC => "ec",
        Id::ED25519 => "ed25519",
        Id::ED448 => "ed448",
        Id::DSA => "dsa",
        _ => "other",
    }
    .to_string()
}

fn read_file(bytes: &[u8], password: &str, out: &mut Collected) -> Result<()> {
    if bytes.windows(11).any(|w| w == b"-----BEGIN ") {
        return read_pem(&String::from_utf8_lossy(bytes), password, out);
    }
    if !bytes.is_empty() && bytes.iter().all(|b| is_base64_or_space(*b)) {
        // Base64 of a DER file without armor, as some portals show it.
        return read_der(&strict_base64(&String::from_utf8_lossy(bytes))?, password, out);
    }
    // A DER file may legitimately end in a whitespace-valued byte (about 2%
    // of random keys), so trailing newlines are trimmed only if raw fails.
    let trimmed = trim_trailing_space(bytes);
    match read_der(bytes, password, out) {
        Err(_) if trimmed.len() != bytes.len() => read_der(trimmed, password, out),
        r => r,
    }
}

fn is_base64_or_space(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=') || b.is_ascii_whitespace()
}

fn trim_trailing_space(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(0, |i| i + 1);
    &bytes[..end]
}

/// Removes whitespace only, then decodes with padding required.
fn strict_base64(text: &str) -> Result<Vec<u8>> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.is_empty() {
        return Err(malformed());
    }
    base64::engine::general_purpose::STANDARD
        .decode(compact)
        .map_err(|_| malformed())
}

struct PemBlock {
    label: String,
    encrypted_header: bool,
    /// The block rebuilt with 64-column Base64, for OpenSSL's PEM readers.
    canonical: String,
    der: Vec<u8>,
}

/// Every `-----BEGIN X----- … -----END X-----` block, wherever its line
/// breaks are (none at all is fine).
fn pem_blocks(text: &str) -> Result<Vec<PemBlock>> {
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    let mut blocks = Vec::new();
    let mut rest = text.as_str();
    while let Some(start) = rest.find("-----BEGIN ") {
        let after = &rest[start + 11..];
        let label_end = after.find("-----").ok_or_else(malformed)?;
        let label = after[..label_end].trim().to_string();
        if label.is_empty() || label.contains('\n') {
            return Err(malformed());
        }
        let body_and_rest = &after[label_end + 5..];
        let end_marker = format!("-----END {label}-----");
        let body_end = body_and_rest.find(&end_marker).ok_or_else(malformed)?;
        let body = &body_and_rest[..body_end];
        if body.contains("-----BEGIN ") {
            return Err(malformed());
        }
        let mut headers = Vec::new();
        let mut b64 = String::new();
        for line in body.split('\n') {
            let line = line.trim();
            let is_header = b64.is_empty()
                && line
                    .split_once(':')
                    .is_some_and(|(k, _)| !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
            if is_header {
                headers.push(line.to_string());
            } else {
                b64.extend(line.chars().filter(|c| !c.is_whitespace()));
            }
        }
        let der = strict_base64(&b64)?;
        let mut canonical = format!("-----BEGIN {label}-----\n");
        for h in &headers {
            canonical.push_str(h);
            canonical.push('\n');
        }
        if !headers.is_empty() {
            canonical.push('\n');
        }
        for chunk in b64.as_bytes().chunks(64) {
            canonical.push_str(std::str::from_utf8(chunk).map_err(|_| malformed())?);
            canonical.push('\n');
        }
        canonical.push_str(&end_marker);
        canonical.push('\n');
        blocks.push(PemBlock {
            encrypted_header: headers
                .iter()
                .any(|h| h.starts_with("Proc-Type") && h.contains("ENCRYPTED")),
            label,
            canonical,
            der,
        });
        rest = &body_and_rest[body_end + end_marker.len()..];
    }
    if rest.contains("-----END ") {
        return Err(malformed());
    }
    Ok(blocks)
}

fn read_pem(text: &str, password: &str, out: &mut Collected) -> Result<()> {
    for block in pem_blocks(text)? {
        match block.label.as_str() {
            "CERTIFICATE" | "X509 CERTIFICATE" | "TRUSTED CERTIFICATE" => {
                // TRUSTED CERTIFICATE appends OpenSSL trust settings after
                // the certificate; they are ignored, never applied.
                out.add_cert(X509::from_der(&block.der).map_err(|_| malformed())?)?
            }
            "PKCS7" | "CMS" => read_pkcs7(&Pkcs7::from_der(&block.der).map_err(|_| malformed())?, out)?,
            "PKCS12" => read_pkcs12(&block.der, password, out)?,
            "ENCRYPTED PRIVATE KEY" => out.add_key(encrypted_pkcs8(&block.der, password)?),
            "PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY" if block.encrypted_header => {
                if password.is_empty() {
                    return Err(SmimeError::PasswordRequired);
                }
                let key = PKey::private_key_from_pem_passphrase(
                    block.canonical.as_bytes(),
                    password.as_bytes(),
                )
                .map_err(|e| password_error(&e))?;
                out.add_key(key);
            }
            "PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY" => out.add_key(
                PKey::private_key_from_pem(block.canonical.as_bytes()).map_err(|_| malformed())?,
            ),
            // PGP armor, PUBLIC KEY, CRLs: nothing to import here.
            _ => {}
        }
    }
    Ok(())
}

fn read_der(der: &[u8], password: &str, out: &mut Collected) -> Result<()> {
    if der.first() != Some(&0x30) {
        return Err(unsupported_format());
    }
    if let Ok(cert) = X509::from_der(der) {
        return out.add_cert(cert);
    }
    if let Ok(p7) = Pkcs7::from_der(der) {
        return read_pkcs7(&p7, out);
    }
    if Pkcs12::from_der(der).is_ok() {
        return read_pkcs12(der, password, out);
    }
    if is_encrypted_pkcs8(der) {
        out.add_key(encrypted_pkcs8(der, password)?);
        return Ok(());
    }
    if let Ok(key) = PKey::private_key_from_der(der) {
        out.add_key(key);
        return Ok(());
    }
    let _ = ErrorStack::get();
    Err(unsupported_format())
}

fn read_pkcs7(p7: &Pkcs7, out: &mut Collected) -> Result<()> {
    let certs = p7
        .signed()
        .and_then(|s| s.certificates())
        .ok_or_else(unsupported_format)?;
    for cert in certs {
        out.add_cert(cert.to_owned())?;
    }
    Ok(())
}

fn read_pkcs12(der: &[u8], password: &str, out: &mut Collected) -> Result<()> {
    let p12 = Pkcs12::from_der(der).map_err(|_| malformed())?;
    let parsed = p12.parse2(password).map_err(|e| {
        let err = password_error(&e);
        if password.is_empty() && matches!(err, SmimeError::WrongPassword) {
            SmimeError::PasswordRequired
        } else {
            err
        }
    })?;
    if let Some(key) = parsed.pkey {
        out.add_key(key);
    }
    if let Some(cert) = parsed.cert {
        out.add_cert(cert)?;
    }
    for cert in parsed.ca.into_iter().flatten() {
        out.add_cert(cert)?;
    }
    Ok(())
}

fn encrypted_pkcs8(der: &[u8], password: &str) -> Result<PKey<Private>> {
    if password.is_empty() {
        return Err(SmimeError::PasswordRequired);
    }
    PKey::private_key_from_pkcs8_passphrase(der, password.as_bytes()).map_err(|e| password_error(&e))
}

/// EncryptedPrivateKeyInfo: SEQUENCE { AlgorithmIdentifier, OCTET STRING }.
fn is_encrypted_pkcs8(der: &[u8]) -> bool {
    yasna::parse_der(der, |r| {
        r.read_sequence(|r| {
            r.next().read_sequence(|r| {
                r.next().read_oid()?;
                r.next().read_der()?;
                Ok(())
            })?;
            r.next().read_bytes()?;
            Ok(())
        })
    })
    .is_ok()
}

/// A wrong password shows as a failed MAC or bad padding; an algorithm this
/// build lacks (RC2 without the legacy provider) as unsupported.
fn password_error(e: &ErrorStack) -> SmimeError {
    let reasons: Vec<String> = e
        .errors()
        .iter()
        .filter_map(|x| x.reason().map(str::to_ascii_lowercase))
        .collect();
    let _ = ErrorStack::get();
    if reasons.iter().any(|r| r.contains("unsupported") || r.contains("fetch failed")) {
        SmimeError::UnsupportedAlgorithm("import file encryption".into())
    } else if reasons.iter().any(|r| {
        r.contains("mac verify") || r.contains("bad decrypt") || r.contains("decrypt") || r.contains("password")
    }) {
        SmimeError::WrongPassword
    } else {
        malformed()
    }
}

#[cfg(test)]
mod tests;
