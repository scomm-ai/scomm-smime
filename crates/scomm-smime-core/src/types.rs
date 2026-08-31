#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyProfile {
    /// RSA-OAEP encrypt + X25519 encrypt + RSA-PSS sign (Outlook classical).
    Classical,
    /// Classical dual-publish plus `smime-mlkem768-x25519` encrypt and `pqc-mldsa65` sign.
    PqcCms,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerateKeyOptions {
    pub userid: String,
    pub passphrase: Option<String>,
    pub profile: KeyProfile,
}

impl Default for GenerateKeyOptions {
    fn default() -> Self {
        Self {
            userid: String::new(),
            passphrase: None,
            profile: KeyProfile::Classical,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyUsage {
    Signing,
    Encryption,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmimeCertInfo {
    pub fingerprint: String,
    pub serial: String,
    pub algorithm: String,
    pub email: Option<String>,
    pub subject: String,
    pub not_before: i64,
    pub not_after: i64,
    pub usage: KeyUsage,
    pub has_secret: bool,
    pub pqc: bool,
}

impl SmimeCertInfo {
    pub fn is_pqc(&self) -> bool {
        self.pqc || is_pqc_catalog(&self.algorithm)
    }
}

pub fn is_pqc_catalog(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("mlkem")
        || n.contains("mldsa")
        || n.contains("ml-kem")
        || n.contains("ml-dsa")
        || n.starts_with("pqc-")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmimeKeyInfo {
    pub identities: Vec<SmimeCertInfo>,
}

impl SmimeKeyInfo {
    pub fn is_pqc(&self) -> bool {
        self.identities.iter().any(|c| c.is_pqc())
    }

    pub fn is_pqc_signing(&self) -> bool {
        self.identities.iter().any(|c| {
            c.usage == KeyUsage::Signing
                && (c.pqc || c.algorithm.eq_ignore_ascii_case("pqc-mldsa65"))
        })
    }

    pub fn primary_algorithm(&self) -> String {
        self.identities
            .iter()
            .find(|c| c.usage == KeyUsage::Encryption)
            .or_else(|| self.identities.first())
            .map(|c| c.algorithm.clone())
            .unwrap_or_default()
    }
}

#[derive(Clone, Debug)]
pub struct GeneratedKey {
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
    pub info: SmimeKeyInfo,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignOptions {
    pub detached: bool,
}

impl Default for SignOptions {
    fn default() -> Self {
        Self { detached: false }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncryptOptions {
    pub armored: bool,
}

impl Default for EncryptOptions {
    fn default() -> Self {
        Self { armored: true }
    }
}

#[derive(Clone, Debug)]
pub struct DecryptResult {
    pub plaintext: Vec<u8>,
    pub algorithm: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureValidity {
    CryptographicallyValid,
    CryptographicallyInvalid,
    UnknownSigner,
    MalformedSignature,
    UnsupportedAlgorithm,
}

#[derive(Clone, Debug)]
pub struct VerificationResult {
    pub validity: SignatureValidity,
}

#[derive(Clone, Debug, Default)]
pub struct MessageInfo {
    pub encrypted: bool,
    pub signed: bool,
    pub pqc: bool,
    pub algorithm: String,
}

pub const ALG_RSA_OAEP: &str = "smime-rsa-oaep-sha256";
pub const ALG_X25519: &str = "smime-x25519";
pub const ALG_RSA_PSS: &str = "smime-rsa-pss-sha256";
pub const ALG_MLKEM_HYBRID: &str = "smime-mlkem768-x25519";
pub const ALG_MLDSA65: &str = "pqc-mldsa65";
