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
    /// Earlier IDs of this key (an ML-DSA key's ID before it gained a
    /// certificate); references to them still mean this key.
    pub legacy_key_ids: Vec<String>,
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
    /// [`ALG_ED25519`], [`ALG_MLDSA65`] or [`ALG_RSA_PSS`]. A bundle can hold
    /// several signing keys, so the caller always names the one it means.
    pub algorithm: &'static str,
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
    /// Which message format was opened, for example [`FORMAT_F0_SCOMM`].
    /// Anything other than an authenticated format is shown to the user as
    /// not integrity protected.
    pub format: String,
}

/// AES-CBC EnvelopedData as older Scomm builds write it: RSA-OAEP-SHA256 key
/// transport, or X25519 / ML-KEM-768+X25519 recipients with an XOR-wrapped
/// content key. Read-only; not integrity protected.
pub const FORMAT_F0_SCOMM: &str = "f0-scomm";

/// EnvelopedData from other clients (AES-CBC, RSA key transport). Read-only;
/// standard but not integrity protected.
pub const FORMAT_F0_STD: &str = "f0-std";

/// RFC 5083 AuthEnvelopedData (AES-GCM). Integrity protected.
pub const FORMAT_F1: &str = "f1";

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

/// S1: RFC 5652 SignedData. S0: the legacy `SEQUENCE { oid, data, sig }`
/// older Scomm builds write; never a source of trust on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureFormat {
    S1,
    S0,
}

/// Path B result for the signer certificate (`design.md` "Trust model").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainStatus {
    /// Chains to a bundled root with the S/MIME purpose, inside validity.
    TrustedRoot,
    /// Self-signed, unknown CA, no roots loaded, or any other chain error.
    UntrustedRoot,
    /// No signer certificate (S0, or the signer could not be found).
    NoChain,
    Expired,
    NotYetValid,
    WrongPurpose,
}

/// Per-signature result. Validity and trust are separate: the app decides
/// `verified` from this plus its own pins, never from validity alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureVerdict {
    pub validity: SignatureValidity,
    /// `None` when the input is not a signature at all.
    pub format: Option<SignatureFormat>,
    /// Lowercase hex SHA-256 of the signer's SubjectPublicKeyInfo DER, the
    /// same for S0 and S1 so an upgrade does not look like a key change.
    pub signer_fingerprint: Option<String>,
    /// The signer certificate as PEM, for display and saving (S1 only).
    pub signer_cert_pem: Option<String>,
    pub chain: ChainStatus,
    /// `X509_check_email` against the sender; `None` when no sender was
    /// given or there is no certificate.
    pub email_match: Option<bool>,
    /// SHA-1 or MD5 digest, or an RSA key under 2048 bits.
    pub weak_algorithm: bool,
    /// Always false: revocation needs a server and the app contacts none.
    pub revocation_checked: bool,
}

impl SignatureVerdict {
    pub fn malformed() -> Self {
        SignatureVerdict {
            validity: SignatureValidity::MalformedSignature,
            format: None,
            signer_fingerprint: None,
            signer_cert_pem: None,
            chain: ChainStatus::NoChain,
            email_match: None,
            weak_algorithm: false,
            revocation_checked: false,
        }
    }
}

/// What a certificate is checked for against the bundled roots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertPurpose {
    SmimeSign,
    SmimeEncrypt,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertCheck {
    pub chain: ChainStatus,
    pub email_match: Option<bool>,
}

#[derive(Clone, Debug, Default)]
pub struct MessageInfo {
    pub encrypted: bool,
    pub signed: bool,
    pub pqc: bool,
    /// An enveloped message also wraps the content key to a classical
    /// recipient, so it is not post-quantum confidential and a classical key
    /// may open it.
    pub classical_recipient: bool,
    pub algorithm: String,
}

pub const ALG_RSA_OAEP: &str = "smime-rsa-oaep-sha256";
pub const ALG_X25519: &str = "smime-x25519";
pub const ALG_RSA_PSS: &str = "smime-rsa-pss-sha256";
/// RSA PKCS#1 v1.5 with SHA-256, the SignedData the app has always sent.
pub const ALG_RSA_PKCS1: &str = "smime-rsa-pkcs1-sha256";
pub const ALG_ED25519: &str = "smime-ed25519";
pub const ALG_MLKEM_HYBRID: &str = "smime-mlkem768-x25519";
pub const ALG_MLDSA65: &str = "pqc-mldsa65";
