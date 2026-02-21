//! Unified error type for all cryptographic operations.

use thiserror::Error;

/// All cryptographic operations return this error type.
#[derive(Debug, Clone, Error)]
pub enum CryptoError {
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("Invalid nonce")]
    InvalidNonce,

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Hashing failed: {0}")]
    HashingFailed(String),

    #[error("KDF failed: {0}")]
    KdfFailed(String),

    #[error("I/O error: {0}")]
    IoError(String),

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),
}

impl From<std::io::Error> for CryptoError {
    fn from(e: std::io::Error) -> Self {
        CryptoError::IoError(e.to_string())
    }
}
