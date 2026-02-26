//! BLAKE3 hasher implementation.

use crate::core::error::CryptoError;
use crate::core::traits::Hasher;
use flutter_rust_bridge::frb;

/// BLAKE3 hasher wrapping the blake3 crate.
#[frb(ignore)]
pub struct Blake3Hasher {
    inner: blake3::Hasher,
}

impl Blake3Hasher {
    /// Create a new BLAKE3 hasher.
    pub fn new() -> Self {
        Self {
            inner: blake3::Hasher::new(),
        }
    }
}

impl Default for Blake3Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for Blake3Hasher {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.inner.update(data);
        Ok(())
    }

    fn reset(&mut self) -> Result<(), CryptoError> {
        self.inner.reset();
        Ok(())
    }

    fn finalize(&self) -> Result<Vec<u8>, CryptoError> {
        let hash = self.inner.finalize();
        Ok(hash.as_bytes().to_vec())
    }

    fn algorithm_id(&self) -> &'static str {
        "blake3"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_input() {
        let hasher = Blake3Hasher::new();
        let digest = hasher.finalize().expect("finalize should succeed");

        // BLAKE3 empty string hash (official test vector)
        let expected =
            hex::decode("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
                .expect("valid hex");

        assert_eq!(digest, expected);
    }

    #[test]
    fn test_hello_world() {
        let mut hasher = Blake3Hasher::new();
        hasher
            .update(b"hello world")
            .expect("update should succeed");
        let digest = hasher.finalize().expect("finalize should succeed");

        // BLAKE3("hello world") - verified against reference implementation
        let expected =
            hex::decode("d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24")
                .expect("valid hex");

        assert_eq!(digest, expected);
    }

    #[test]
    fn test_incremental_equals_oneshot() {
        let data = b"The quick brown fox jumps over the lazy dog";

        // One-shot
        let oneshot = blake3::hash(data);

        // Incremental
        let mut hasher = Blake3Hasher::new();
        hasher.update(&data[..10]).expect("update should succeed");
        hasher.update(&data[10..]).expect("update should succeed");
        let incremental = hasher.finalize().expect("finalize should succeed");

        assert_eq!(incremental, oneshot.as_bytes().to_vec());
    }

    #[test]
    fn test_reset() {
        let mut hasher = Blake3Hasher::new();
        hasher.update(b"some data").expect("update should succeed");
        hasher.reset().expect("reset should succeed");

        // After reset, should produce empty hash
        let digest = hasher.finalize().expect("finalize should succeed");
        let empty_hash = Blake3Hasher::new()
            .finalize()
            .expect("finalize should succeed");

        assert_eq!(digest, empty_hash);
    }

    #[test]
    fn test_algorithm_id() {
        let hasher = Blake3Hasher::new();
        assert_eq!(hasher.algorithm_id(), "blake3");
    }

    #[test]
    fn test_digest_length() {
        let hasher = Blake3Hasher::new();
        let digest = hasher.finalize().expect("finalize should succeed");
        assert_eq!(digest.len(), 32); // BLAKE3 produces 32-byte digests by default
    }
}
