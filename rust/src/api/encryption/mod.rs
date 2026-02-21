//! Encryption API module.

pub mod noop;

use crate::core::error::CryptoError;
use crate::core::traits::Encryption;
use flutter_rust_bridge::frb;

/// Opaque handle wrapping any cipher implementation.
#[frb(opaque)]
pub struct CipherHandle {
    inner: Box<dyn Encryption>,
}

impl CipherHandle {
    fn new(cipher: Box<dyn Encryption>) -> Self {
        Self { inner: cipher }
    }
}

/// Create a noop encryption handle (for testing FRB opaque pattern).
pub fn create_noop_encryption() -> CipherHandle {
    CipherHandle::new(Box::new(noop::NoopEncryption {}))
}

/// Encrypt plaintext using the given cipher handle.
pub fn encrypt(
    cipher: &CipherHandle,
    plaintext: Vec<u8>,
    aad: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    if plaintext.is_empty() {
        return Err(CryptoError::InvalidParameter(
            "Plaintext cannot be empty".into(),
        ));
    }
    cipher.inner.encrypt(&plaintext, &aad)
}

/// Decrypt ciphertext using the given cipher handle.
pub fn decrypt(
    cipher: &CipherHandle,
    ciphertext: Vec<u8>,
    aad: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.is_empty() {
        return Err(CryptoError::InvalidParameter(
            "Ciphertext cannot be empty".into(),
        ));
    }
    cipher.inner.decrypt(&ciphertext, &aad)
}

/// Get the algorithm identifier for the cipher.
pub fn encryption_algorithm_id(cipher: &CipherHandle) -> String {
    cipher.inner.algorithm_id().to_string()
}
