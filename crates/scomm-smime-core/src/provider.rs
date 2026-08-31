use crate::error::{Result, SmimeError};
use crate::types::*;

/// Bytes-in / bytes-out CMS operations. No vault, network, or filesystem.
pub trait SmimeProvider: Send + Sync {
    fn inspect_key(&self, key: &[u8]) -> Result<SmimeKeyInfo>;

    fn generate_key(&self, options: &GenerateKeyOptions) -> Result<GeneratedKey>;

    fn pqc_ready(&self) -> bool {
        true
    }

    fn export_public_key(&self, secret_or_public: &[u8]) -> Result<Vec<u8>>;

    fn sign(
        &self,
        data: &[u8],
        private_key: &[u8],
        passphrase: Option<&str>,
        options: &SignOptions,
    ) -> Result<Vec<u8>>;

    fn verify(&self, data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<VerificationResult>;

    fn encrypt(
        &self,
        plaintext: &[u8],
        recipient_public_keys: &[&[u8]],
        options: &EncryptOptions,
    ) -> Result<Vec<u8>>;

    fn decrypt(
        &self,
        ciphertext: &[u8],
        private_key: &[u8],
        passphrase: Option<&str>,
    ) -> Result<DecryptResult>;

    fn inspect_message(&self, message: &[u8]) -> Result<MessageInfo>;

    fn test_passphrase(&self, private_key: &[u8], passphrase: Option<&str>) -> Result<()>;

    /// ML-DSA-65 signature over [data] (artifact_pop UTF-8).
    fn pop_sign_mldsa(
        &self,
        data: &[u8],
        private_key: &[u8],
        passphrase: Option<&str>,
    ) -> Result<Vec<u8>> {
        let _ = (data, private_key, passphrase);
        Err(SmimeError::UnsupportedAlgorithm(
            "ML-DSA-65 artifact PoP signing".into(),
        ))
    }

    /// `mlkem_shared || x25519_shared` for hybrid encrypt PoP (caller SHA-256s).
    fn pop_hybrid_shared(
        &self,
        private_key: &[u8],
        passphrase: Option<&str>,
        kem_ciphertext: &[u8],
        ephemeral_x25519: &[u8],
    ) -> Result<Vec<u8>> {
        let _ = (private_key, passphrase, kem_ciphertext, ephemeral_x25519);
        Err(SmimeError::UnsupportedAlgorithm(
            "hybrid artifact PoP decaps".into(),
        ))
    }
}
