//! SHA-3 hasher implementation.

use crate::core::error::CryptoError;
use crate::core::traits::Hasher;
use flutter_rust_bridge::frb;
use sha3::{Digest, Sha3_256 as Sha3Digest};

/// SHA-3 hasher wrapping the sha3 crate.
#[frb(ignore)]
pub struct Sha3Hasher {
    inner: Sha3Digest,
}

impl Sha3Hasher {
    /// Create a new SHA-3 hasher.
    pub fn new() -> Self {
        Self {
            inner: Sha3Digest::new(),
        }
    }
}

impl Default for Sha3Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for Sha3Hasher {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        Digest::update(&mut self.inner, data);
        Ok(())
    }

    fn reset(&mut self) -> Result<(), CryptoError> {
        self.inner = Sha3Digest::new();
        Ok(())
    }

    fn finalize(&self) -> Result<Vec<u8>, CryptoError> {
        let hash = self.inner.clone().finalize();
        Ok(hash.to_vec())
    }

    fn algorithm_id(&self) -> &'static str {
        "sha3"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_input() {
        let hasher = Sha3Hasher::new();
        let digest = hasher.finalize().expect("finalize should succeed");

        // NIST SHA-3 empty string test vector
        let expected = hex::decode(
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        )
        .expect("valid hex");

        assert_eq!(digest, expected);
    }

    #[test]
    fn test_abc() {
        let mut hasher = Sha3Hasher::new();
        hasher.update(b"abc").expect("update should succeed");
        let digest = hasher.finalize().expect("finalize should succeed");

        // NIST SHA-3("abc") test vector
        let expected = hex::decode(
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
        )
        .expect("valid hex");

        assert_eq!(digest, expected);
    }

    #[test]
    fn test_incremental_equals_oneshot() {
        let data = b"The quick brown fox jumps over the lazy dog";

        // One-shot
        let oneshot = Sha3Digest::digest(data);

        // Incremental
        let mut hasher = Sha3Hasher::new();
        hasher.update(&data[..10]).expect("update should succeed");
        hasher.update(&data[10..]).expect("update should succeed");
        let incremental = hasher.finalize().expect("finalize should succeed");

        assert_eq!(incremental, oneshot.to_vec());
    }

    #[test]
    fn test_reset() {
        let mut hasher = Sha3Hasher::new();
        hasher.update(b"some data").expect("update should succeed");
        hasher.reset().expect("reset should succeed");

        // After reset, should produce empty hash
        let digest = hasher.finalize().expect("finalize should succeed");
        let empty_hash = Sha3Hasher::new().finalize().expect("finalize should succeed");

        assert_eq!(digest, empty_hash);
    }

    #[test]
    fn test_algorithm_id() {
        let hasher = Sha3Hasher::new();
        assert_eq!(hasher.algorithm_id(), "sha3");
    }

    #[test]
    fn test_digest_length() {
        let hasher = Sha3Hasher::new();
        let digest = hasher.finalize().expect("finalize should succeed");
        assert_eq!(digest.len(), 32); // SHA-3-256 produces 32 bytes
    }
}
