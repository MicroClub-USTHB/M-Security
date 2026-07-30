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

    #[error("Compression failed: {0}")]
    CompressionFailed(String),

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Vault full: need {needed} bytes, {available} available")]
    VaultFull { needed: u64, available: u64 },

    #[error("Vault locked by another process")]
    VaultLocked,

    #[error("Segment not found: {0}")]
    SegmentNotFound(String),

    #[error("Duplicate segment {0}")]
    DuplicateSegment(String),

    #[error("Vault corrupted: {0}")]
    VaultCorrupted(String),

    #[error("Key rotation failed: {0}")]
    KeyRotationFailed(String),

    #[error("Export failed: {0}")]
    ExportFailed(String),

    #[error("Import failed: {0}")]
    ImportFailed(String),

    #[error("Argon2 policy violation: {0}")]
    Argon2PolicyViolation(String),

    #[error("Another Argon2 verification is already in progress")]
    Argon2VerificationBusy,

    #[error("Unauthenticated v1/v2 vault format denied: explicit opt-in required")]
    UnsafeLegacyFormatDenied,

    // Carried for the Dart compatibility stubs. Their native entry points are
    // gone, so nothing in this crate returns it.
    #[error("Format disabled in this release: {0}")]
    DisabledFormat(String),
}

impl From<std::io::Error> for CryptoError {
    fn from(e: std::io::Error) -> Self {
        CryptoError::IoError(e.to_string())
    }
}
