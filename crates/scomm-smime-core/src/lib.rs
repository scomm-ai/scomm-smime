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
pub const ABI_VERSION: u32 = 3;
