use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmimeError {
    InvalidArgument(String),
    InvalidKey(String),
    KeyExpired,
    UnsupportedAlgorithm(String),
    NoSuitableEncryptionKey,
    NoSuitableSigningKey,
    BadSignature,
    DecryptionFailed,
    WrongPrivateKey,
    MalformedMessage,
    Internal(String),
}

impl SmimeError {
    pub fn code(&self) -> i32 {
        match self {
            Self::InvalidArgument(_) => 1,
            Self::InvalidKey(_) => 2,
            Self::KeyExpired => 3,
            Self::UnsupportedAlgorithm(_) => 5,
            Self::NoSuitableEncryptionKey => 6,
            Self::NoSuitableSigningKey => 7,
            Self::BadSignature => 8,
            Self::DecryptionFailed => 9,
            Self::WrongPrivateKey => 10,
            Self::MalformedMessage => 11,
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
            Self::NoSuitableSigningKey => write!(f, "no suitable signing key"),
            Self::BadSignature => write!(f, "bad signature"),
            Self::DecryptionFailed => write!(f, "decryption failed"),
            Self::WrongPrivateKey => write!(f, "wrong private key"),
            Self::MalformedMessage => write!(f, "malformed message"),
            Self::Internal(m) => write!(f, "internal error: {m}"),
        }
    }
}

impl std::error::Error for SmimeError {}

pub type Result<T> = std::result::Result<T, SmimeError>;
