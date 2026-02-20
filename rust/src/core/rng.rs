//! Cryptographically secure random number generation.

use rand::{rngs::OsRng, RngCore};

use crate::core::error::CryptoError;
use crate::core::secret::SecretBuffer;

/// Maximum allowed key size in bytes.
const MAX_KEY_SIZE: usize = 64;

/// Generate cryptographically secure random bytes.
///
/// Uses the OS-provided CSPRNG (OsRng).
pub fn generate_random_bytes(len: usize) -> Result<Vec<u8>, CryptoError> {
    if len == 0 {
        return Err(CryptoError::InvalidParameter(
            "Length must be greater than 0".to_string(),
        ));
    }

    let mut buf = vec![0u8; len];
    OsRng.fill_bytes(&mut buf);
    Ok(buf)
}

/// Generate a cryptographic key of the specified length.
///
/// Returns the key wrapped in SecretBuffer for secure handling.
/// Key length must be between 1 and 64 bytes.
pub fn generate_key(len: usize) -> Result<SecretBuffer, CryptoError> {
    if len == 0 || len > MAX_KEY_SIZE {
        return Err(CryptoError::InvalidParameter(format!(
            "Key length must be 1-{} bytes, got {}",
            MAX_KEY_SIZE, len
        )));
    }

    let mut buf = SecretBuffer::from_size(len);
    OsRng.fill_bytes(buf.as_bytes_mut());
    Ok(buf)
}

/// Generate a nonce of the specified length.
pub fn generate_nonce(len: usize) -> Result<Vec<u8>, CryptoError> {
    generate_random_bytes(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_bytes() {
        let bytes = generate_random_bytes(32).expect("failed to generate");
        assert_eq!(bytes.len(), 32);
        // Extremely unlikely to be all zeros
        assert!(bytes.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_generate_random_bytes_zero_length() {
        let result = generate_random_bytes(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_key() {
        let key = generate_key(32).expect("failed to generate");
        assert_eq!(key.len(), 32);
        assert!(key.as_bytes().iter().any(|&b| b != 0));
    }

    #[test]
    fn test_generate_key_bounds() {
        assert!(generate_key(0).is_err());
        assert!(generate_key(65).is_err());
        assert!(generate_key(64).is_ok());
        assert!(generate_key(1).is_ok());
    }

    #[test]
    fn test_randomness() {
        // Generate two keys and verify they're different
        let key1 = generate_key(32).expect("failed");
        let key2 = generate_key(32).expect("failed");
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }
}
