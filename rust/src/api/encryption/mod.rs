//! Encryption API module.

pub mod aes_gcm;
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

/// Create an AES-256-GCM cipher handle from a 32-byte key.
pub fn create_aes256_gcm(key: Vec<u8>) -> Result<CipherHandle, CryptoError> {
    let cipher = aes_gcm::Aes256GcmCipher::new(key)?;
    Ok(CipherHandle::new(Box::new(cipher)))
}

/// Generate a random 32-byte key for AES-256-GCM.
pub fn generate_aes256_gcm_key() -> Result<Vec<u8>, CryptoError> {
    aes_gcm::generate_aes_key()
}

/// Encrypt plaintext using the given cipher handle.
///
/// Empty plaintext is valid — produces an authenticated tag with no ciphertext,
/// useful for authenticate-only use cases with AAD.
pub fn encrypt(
    cipher: &CipherHandle,
    plaintext: Vec<u8>,
    aad: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    cipher.inner.encrypt(&plaintext, &aad)
}

/// Decrypt ciphertext using the given cipher handle.
pub fn decrypt(
    cipher: &CipherHandle,
    ciphertext: Vec<u8>,
    aad: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    cipher.inner.decrypt(&ciphertext, &aad)
}

/// Get the algorithm identifier for the cipher.
pub fn encryption_algorithm_id(cipher: &CipherHandle) -> String {
    cipher.inner.algorithm_id().to_string()
}
