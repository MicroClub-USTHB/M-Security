//! Argon2id password hashing with platform presets and PHC format output.

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use rand::rngs::OsRng;

use crate::core::error::CryptoError;

/// Platform-appropriate parameter presets for Argon2id.
pub enum Argon2Preset {
    /// Optimized for mobile devices (64 MiB, 3 iterations, 4 threads).
    Mobile,
    /// Optimized for desktop/server (256 MiB, 4 iterations, 8 threads).
    Desktop,
}

impl Argon2Preset {
    fn params(&self) -> Params {
        match self {
            Self::Mobile => Params::new(64 * 1024, 3, 4, None),
            Self::Desktop => Params::new(256 * 1024, 4, 8, None),
        }
        // SAFETY: These are known-valid parameter combinations
        .expect("valid Argon2 params")
    }
}

/// Hash a password using Argon2id with the given preset.
///
/// Generates a random salt internally and returns a PHC-format string
/// containing the algorithm, parameters, salt, and hash.
pub fn argon2id_hash(password: String, preset: Argon2Preset) -> Result<String, CryptoError> {
    let salt = SaltString::generate(&mut OsRng);
    let params = preset.params();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| CryptoError::HashingFailed(e.to_string()))?;

    Ok(hash.to_string())
}

/// Hash a password using Argon2id with an explicit salt.
///
/// The salt must be valid base64 (no padding), between 1-64 bytes decoded.
/// Returns a PHC-format string.
pub fn argon2id_hash_with_salt(
    password: String,
    salt: String,
    preset: Argon2Preset,
) -> Result<String, CryptoError> {
    let salt = SaltString::from_b64(&salt)
        .map_err(|e| CryptoError::InvalidParameter(format!("Invalid salt: {}", e)))?;
    let params = preset.params();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| CryptoError::HashingFailed(e.to_string()))?;

    Ok(hash.to_string())
}

/// Verify a password against an Argon2id PHC hash string.
///
/// Returns `Ok(())` if the password matches, or
/// `Err(CryptoError::AuthenticationFailed)` if it does not.
pub fn argon2id_verify(phc_hash: String, password: String) -> Result<(), CryptoError> {
    let parsed = PasswordHash::new(&phc_hash)
        .map_err(|e| CryptoError::InvalidParameter(format!("Invalid PHC string: {}", e)))?;

    // Extract params from the PHC string to reconstruct the hasher
    let argon2 = Argon2::default();

    argon2
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| CryptoError::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_produces_phc_string() {
        let hash = argon2id_hash("password123".into(), Argon2Preset::Mobile)
            .expect("hashing should succeed");

        // PHC strings start with $argon2id$
        assert!(hash.starts_with("$argon2id$"), "Not a PHC string: {}", hash);
    }

    #[test]
    fn test_hash_contains_preset_params() {
        let hash = argon2id_hash("test".into(), Argon2Preset::Mobile)
            .expect("hashing should succeed");

        // Mobile: m=65536 (64*1024), t=3, p=4
        assert!(hash.contains("m=65536"), "Missing memory param: {}", hash);
        assert!(hash.contains("t=3"), "Missing time param: {}", hash);
        assert!(hash.contains("p=4"), "Missing parallelism param: {}", hash);
    }

    #[test]
    fn test_hash_desktop_preset_params() {
        let hash = argon2id_hash("test".into(), Argon2Preset::Desktop)
            .expect("hashing should succeed");

        // Desktop: m=262144 (256*1024), t=4, p=8
        assert!(hash.contains("m=262144"), "Missing memory param: {}", hash);
        assert!(hash.contains("t=4"), "Missing time param: {}", hash);
        assert!(hash.contains("p=8"), "Missing parallelism param: {}", hash);
    }

    #[test]
    fn test_verify_correct_password() {
        let hash = argon2id_hash("correct_password".into(), Argon2Preset::Mobile)
            .expect("hashing should succeed");

        let result = argon2id_verify(hash, "correct_password".into());
        assert!(result.is_ok(), "Should verify correct password");
    }

    #[test]
    fn test_verify_wrong_password() {
        let hash = argon2id_hash("correct_password".into(), Argon2Preset::Mobile)
            .expect("hashing should succeed");

        let result = argon2id_verify(hash, "wrong_password".into());
        assert!(result.is_err(), "Should reject wrong password");

        match result {
            Err(CryptoError::AuthenticationFailed) => {} // expected
            other => panic!("Expected AuthenticationFailed, got {:?}", other),
        }
    }

    #[test]
    fn test_hash_with_salt_deterministic() {
        let salt = "c29tZXNhbHQ"; // "somesalt" in base64 no-pad

        let hash1 = argon2id_hash_with_salt("password".into(), salt.into(), Argon2Preset::Mobile)
            .expect("hashing should succeed");
        let hash2 = argon2id_hash_with_salt("password".into(), salt.into(), Argon2Preset::Mobile)
            .expect("hashing should succeed");

        assert_eq!(hash1, hash2, "Same password + salt should produce same hash");
    }

    #[test]
    fn test_hash_with_salt_different_passwords() {
        let salt = "c29tZXNhbHQ";

        let hash1 = argon2id_hash_with_salt("password1".into(), salt.into(), Argon2Preset::Mobile)
            .expect("hashing should succeed");
        let hash2 = argon2id_hash_with_salt("password2".into(), salt.into(), Argon2Preset::Mobile)
            .expect("hashing should succeed");

        assert_ne!(hash1, hash2, "Different passwords should produce different hashes");
    }

    #[test]
    fn test_hash_with_salt_verify_roundtrip() {
        let salt = "c29tZXNhbHQ";

        let hash = argon2id_hash_with_salt("mypassword".into(), salt.into(), Argon2Preset::Mobile)
            .expect("hashing should succeed");

        assert!(argon2id_verify(hash.clone(), "mypassword".into()).is_ok());
        assert!(argon2id_verify(hash, "notmypassword".into()).is_err());
    }

    #[test]
    fn test_random_salt_uniqueness() {
        let hash1 = argon2id_hash("same_password".into(), Argon2Preset::Mobile)
            .expect("hashing should succeed");
        let hash2 = argon2id_hash("same_password".into(), Argon2Preset::Mobile)
            .expect("hashing should succeed");

        // Random salts make each hash unique
        assert_ne!(hash1, hash2, "Random salts should produce different hashes");
    }

    #[test]
    fn test_invalid_phc_string() {
        let result = argon2id_verify("not_a_phc_string".into(), "password".into());
        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidParameter(_)) => {} // expected
            other => panic!("Expected InvalidParameter, got {:?}", other),
        }
    }

    #[test]
    fn test_invalid_salt() {
        let result = argon2id_hash_with_salt("password".into(), "!!!invalid!!!".into(), Argon2Preset::Mobile);
        assert!(result.is_err());
        match result {
            Err(CryptoError::InvalidParameter(_)) => {} // expected
            other => panic!("Expected InvalidParameter, got {:?}", other),
        }
    }

    #[test]
    fn test_empty_password_hashes() {
        // Empty password is valid — Argon2id should handle it
        let hash = argon2id_hash(String::new(), Argon2Preset::Mobile)
            .expect("empty password should hash");
        assert!(hash.starts_with("$argon2id$"));
        assert!(argon2id_verify(hash, String::new()).is_ok());
    }
}
