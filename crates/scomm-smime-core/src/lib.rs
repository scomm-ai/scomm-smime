//! Scomm S/MIME types and provider contract.
//!
//! This crate must not depend on OpenSSL (or any other CMS engine).

mod error;
mod provider;
mod types;

pub use error::{Result, SmimeError};
pub use provider::SmimeProvider;
pub use types::*;

/// FFI / Dart ABI version. Bump when the C ABI breaks.
/// 3: verdict, detached signing, certificate info, trust roots, ML-DSA
/// certificate migration and decrypt with format (task 3.6).
/// 4: post-quantum-only key profiles (2, 3) and bundle entry removal.
/// 5: `scomm_smime_generate_with_validity` (certificate lifetime in years).
/// 6: `scomm_smime_import` (PKCS#12, PKCS#7, PEM/DER certificates and keys)
/// and error codes 12 (password required) and 13 (wrong password).
pub const ABI_VERSION: u32 = 6;
