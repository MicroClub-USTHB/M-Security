//! Core trait definitions for cryptographic operations.
//!
//! All traits require Send + Sync + 'static to ensure they can be
//! safely used across FFI boundaries with FRB opaque handles.

use flutter_rust_bridge::frb;

use crate::core::error::CryptoError;
use crate::core::secret::SecretBuffer;

/// Authenticated encryption operations.
///
/// Implementors provide AEAD (Authenticated Encryption with Associated Data).
/// The nonce is generated internally and prepended to the ciphertext.
#[frb(ignore)]
pub trait Encryption: Send + Sync + 'static {
    /// Encrypt plaintext with optional associated data.
    ///
    /// Returns nonce || ciphertext || tag as a single byte vector.
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Decrypt ciphertext with optional associated data.
    ///
    /// Expects input format: nonce || ciphertext || tag.
    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Returns the algorithm identifier (e.g., "aes-256-gcm").
    fn algorithm_id(&self) -> &'static str;
}

/// Streaming hash operations.
///
/// Implementors can accumulate data in chunks before producing a digest.
#[frb(ignore)]
pub trait Hasher: Send + Sync + 'static {
    /// Feed data into the hasher.
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError>;

    /// Reset the hasher to its initial state.
    fn reset(&mut self) -> Result<(), CryptoError>;

    /// Produce the final digest without consuming the hasher.
    ///
    /// Returns raw bytes, not hex-encoded.
    fn finalize(&self) -> Result<Vec<u8>, CryptoError>;

    /// Returns the algorithm identifier (e.g., "blake3").
    fn algorithm_id(&self) -> &'static str;
}

/// Key derivation operations.
///
/// Implementors derive cryptographic keys from passwords or master keys.
#[frb(ignore)]
pub trait Kdf: Send + Sync + 'static {
    /// Derive a key from password and salt.
    ///
    /// Returns the derived key wrapped in SecretBuffer for secure handling.
    fn derive(
        &self,
        password: &[u8],
        salt: &[u8],
        output_len: usize,
    ) -> Result<SecretBuffer, CryptoError>;

    /// Returns the algorithm identifier (e.g., "argon2id").
    fn algorithm_id(&self) -> &'static str;
}
