//! Encryption API module.

pub mod aes_gcm;
pub mod chacha20;
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

    /// Direct encrypt for internal use (streaming). Not FRB-visible.
    pub(crate) fn encrypt_raw(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.inner.encrypt(plaintext, aad)
    }

    /// Direct decrypt for internal use (streaming). Not FRB-visible.
    pub(crate) fn decrypt_raw(
        &self,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.inner.decrypt(ciphertext, aad)
    }

    /// Get the algorithm_id for internal use (streaming header).
    pub(crate) fn algorithm_id(&self) -> &'static str {
        self.inner.algorithm_id()
    }
}

/// Create a noop encryption handle (for testing FRB opaque pattern).
///
/// # Panics
/// Panics at runtime unless the `testing` feature is enabled.
/// **Never** enable the `testing` feature in production builds.
pub fn create_noop_encryption() -> CipherHandle {
    #[cfg(feature = "testing")]
    {
        CipherHandle::new(Box::new(noop::NoopEncryption {}))
    }
    #[cfg(not(feature = "testing"))]
    {
        panic!("noop cipher is disabled — enable the `testing` feature to use it")
    }
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

/// Create a ChaCha20-Poly1305 cipher handle from a 32-byte key.
pub fn create_chacha20_poly1305(key: Vec<u8>) -> Result<CipherHandle, CryptoError> {
    let cipher = chacha20::ChaCha20Poly1305Cipher::new(key)?;
    Ok(CipherHandle::new(Box::new(cipher)))
}

/// Generate a random 32-byte key for ChaCha20-Poly1305.
pub fn generate_chacha20_poly1305_key() -> Result<Vec<u8>, CryptoError> {
    chacha20::generate_chacha_key()
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
