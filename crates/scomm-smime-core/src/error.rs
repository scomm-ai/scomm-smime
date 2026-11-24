use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmimeError {
    InvalidArgument(String),
    InvalidKey(String),
    KeyExpired,
    UnsupportedAlgorithm(String),
    NoSuitableEncryptionKey,
    /// Recipient bundle `index` (0-based, in the order given) parsed but has
    /// no supported encryption entry. Same code as
    /// [`Self::NoSuitableEncryptionKey`] so older callers still fail closed.
    RecipientWithoutEncryptionKey {
        index: usize,
    },
    NoSuitableSigningKey,
    BadSignature,
    DecryptionFailed,
    WrongPrivateKey,
    MalformedMessage,
    /// An import file is password protected and no password was given (ABI 6).
    PasswordRequired,
    /// The password did not open an import file (ABI 6).
    WrongPassword,
    Internal(String),
}

impl SmimeError {
    pub fn code(&self) -> i32 {
        match self {
            Self::InvalidArgument(_) => 1,
            Self::InvalidKey(_) => 2,
            Self::KeyExpired => 3,
            Self::UnsupportedAlgorithm(_) => 5,
            Self::NoSuitableEncryptionKey | Self::RecipientWithoutEncryptionKey { .. } => 6,
            Self::NoSuitableSigningKey => 7,
            Self::BadSignature => 8,
            Self::DecryptionFailed => 9,
            Self::WrongPrivateKey => 10,
            Self::MalformedMessage => 11,
            Self::PasswordRequired => 12,
            Self::WrongPassword => 13,
            Self::Internal(_) => 99,
        }
    }
}

impl fmt::Display for SmimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument(m) => write!(f, "invalid argument: {m}"),
            Self::InvalidKey(m) => write!(f, "invalid key: {m}"),
            Self::KeyExpired => write!(f, "key expired"),
            Self::UnsupportedAlgorithm(m) => write!(f, "unsupported algorithm: {m}"),
            Self::NoSuitableEncryptionKey => write!(f, "no suitable encryption key"),
            // Callers parse this text: keep the format stable.
            Self::RecipientWithoutEncryptionKey { index } => {
                write!(f, "no suitable encryption key for recipient {index}")
            }
            Self::NoSuitableSigningKey => write!(f, "no suitable signing key"),
            Self::BadSignature => write!(f, "bad signature"),
            Self::DecryptionFailed => write!(f, "decryption failed"),
            Self::WrongPrivateKey => write!(f, "wrong private key"),
            Self::MalformedMessage => write!(f, "malformed message"),
            Self::PasswordRequired => write!(f, "password required"),
            Self::WrongPassword => write!(f, "wrong password"),
            Self::Internal(m) => write!(f, "internal error: {m}"),
        }
    }
}

impl std::error::Error for SmimeError {}

pub type Result<T> = std::result::Result<T, SmimeError>;
