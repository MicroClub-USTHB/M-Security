//! No-op encryption for testing FRB opaque handles.

use crate::core::error::CryptoError;
use crate::core::traits::Encryption;

/// A no-op cipher that returns data unchanged.
/// Used to validate FRB opaque handle pattern works.
pub struct NoopEncryption {}

impl Encryption for NoopEncryption {
    fn encrypt(&self, plaintext: &[u8], _aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(plaintext.to_vec())
    }

    fn decrypt(&self, ciphertext: &[u8], _aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(ciphertext.to_vec())
    }

    fn algorithm_id(&self) -> &'static str {
        "noop"
    }
}
