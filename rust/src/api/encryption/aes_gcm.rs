//! AES-256-GCM authenticated encryption.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm,
};

use crate::core::error::CryptoError;
use crate::core::rng::generate_nonce;
use crate::core::secret::SecretBuffer;
use crate::core::traits::Encryption;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// AES-256-GCM cipher with key stored in secure, zeroize-on-drop memory.
pub struct Aes256GcmCipher {
    key: SecretBuffer,
}

impl Aes256GcmCipher {
    pub fn new(key: Vec<u8>) -> Result<Self, CryptoError> {
        if key.len() != KEY_LEN {
            return Err(CryptoError::InvalidKeyLength {
                expected: KEY_LEN,
                actual: key.len(),
            });
        }
        Ok(Self {
            key: SecretBuffer::new(key),
        })
    }
}

impl Encryption for Aes256GcmCipher {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let cipher = Aes256Gcm::new_from_slice(self.key.as_bytes())
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        let nonce_bytes = generate_nonce(NONCE_LEN)?;
        let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);

        let payload = Payload {
            msg: plaintext,
            aad,
        };

        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        // Output: nonce (12) || ciphertext || tag (16)
        let mut output = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() < NONCE_LEN + TAG_LEN {
            return Err(CryptoError::AuthenticationFailed);
        }

        let (nonce_bytes, encrypted) = ciphertext.split_at(NONCE_LEN);
        let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(self.key.as_bytes())
            .map_err(|_| CryptoError::DecryptionFailed)?;

        let payload = Payload {
            msg: encrypted,
            aad,
        };

        cipher
            .decrypt(nonce, payload)
            .map_err(|_| CryptoError::AuthenticationFailed)
    }

    fn algorithm_id(&self) -> &'static str {
        "aes-256-gcm"
    }
}

/// Generate a random 32-byte AES-256 key.
pub fn generate_aes_key() -> Result<Vec<u8>, CryptoError> {
    crate::core::rng::generate_random_bytes(KEY_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key() -> Vec<u8> {
        generate_aes_key().expect("key gen failed")
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    #[test]
    fn encrypt_then_decrypt_roundtrip() {
        let key = make_key();
        let cipher = Aes256GcmCipher::new(key).expect("cipher creation failed");
        let plaintext = b"hello, AES-256-GCM!";
        let aad = b"metadata";

        let ciphertext = cipher.encrypt(plaintext, aad).expect("encrypt failed");
        let decrypted = cipher.decrypt(&ciphertext, aad).expect("decrypt failed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_returns_auth_error() {
        let cipher1 = Aes256GcmCipher::new(make_key()).expect("cipher1");
        let cipher2 = Aes256GcmCipher::new(make_key()).expect("cipher2");

        let ciphertext = cipher1.encrypt(b"secret", b"").expect("encrypt");
        let result = cipher2.decrypt(&ciphertext, b"");

        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn tampered_ciphertext_returns_auth_error() {
        let cipher = Aes256GcmCipher::new(make_key()).expect("cipher");
        let mut ciphertext = cipher.encrypt(b"secret", b"").expect("encrypt");

        // Flip a byte in the encrypted payload (after the nonce)
        let idx = NONCE_LEN + 1;
        ciphertext[idx] ^= 0xFF;

        let result = cipher.decrypt(&ciphertext, b"");
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn tampered_aad_returns_auth_error() {
        let cipher = Aes256GcmCipher::new(make_key()).expect("cipher");
        let ciphertext = cipher.encrypt(b"secret", b"original-aad").expect("encrypt");

        let result = cipher.decrypt(&ciphertext, b"tampered-aad");
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn same_plaintext_produces_different_ciphertext() {
        let cipher = Aes256GcmCipher::new(make_key()).expect("cipher");
        let plaintext = b"same data";

        let ct1 = cipher.encrypt(plaintext, b"").expect("encrypt1");
        let ct2 = cipher.encrypt(plaintext, b"").expect("encrypt2");

        // Different nonces produce different output
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn empty_plaintext_works() {
        let cipher = Aes256GcmCipher::new(make_key()).expect("cipher");

        let ciphertext = cipher.encrypt(b"", b"").expect("encrypt empty");
        // nonce (12) + tag (16) = 28 bytes minimum
        assert_eq!(ciphertext.len(), NONCE_LEN + TAG_LEN);

        let decrypted = cipher.decrypt(&ciphertext, b"").expect("decrypt empty");
        assert!(decrypted.is_empty());
    }

    #[test]
    fn bad_key_size_returns_error() {
        let result = Aes256GcmCipher::new(vec![0u8; 16]);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: 16
            })
        ));
    }

    #[test]
    fn generate_aes_key_returns_32_bytes() {
        let key = generate_aes_key().expect("key gen");
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn generate_aes_key_is_random() {
        let k1 = generate_aes_key().expect("k1");
        let k2 = generate_aes_key().expect("k2");
        assert_ne!(k1, k2);
    }

    #[test]
    fn algorithm_id_is_correct() {
        let cipher = Aes256GcmCipher::new(make_key()).expect("cipher");
        assert_eq!(cipher.algorithm_id(), "aes-256-gcm");
    }

    #[test]
    fn too_short_ciphertext_returns_auth_error() {
        let cipher = Aes256GcmCipher::new(make_key()).expect("cipher");
        // Less than nonce + tag = 28 bytes
        let result = cipher.decrypt(&[0u8; 27], b"");
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    // NIST SP 800-38D Test Case 16 (AES-256, 96-bit IV, with AAD)
    #[test]
    fn nist_test_vector_decrypt() {
        let key = hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let nonce = hex("cafebabefacedbaddecaf888");
        let expected_pt = hex(
            "d9313225f88406e5a55909c5aff5269a\
             86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525\
             b16aedf5aa0de657ba637b39",
        );
        let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let ct = hex(
            "522dc1f099567d07f47f37a32a84427d\
             643a8cdcbfe5c0c97598a2bd2555d1aa\
             8cb08e48590dbb3da7b08b1056828838\
             c5f61e6393ba7a0abcc9f662",
        );
        let tag = hex("76fc6ece0f4e1768cddf8853bb2d551b");

        // Build wire format: nonce || ciphertext || tag
        let mut input = Vec::with_capacity(nonce.len() + ct.len() + tag.len());
        input.extend_from_slice(&nonce);
        input.extend_from_slice(&ct);
        input.extend_from_slice(&tag);

        let cipher = Aes256GcmCipher::new(key).expect("cipher");
        let plaintext = cipher.decrypt(&input, &aad).expect("decrypt");
        assert_eq!(plaintext, expected_pt);
    }

    // NIST SP 800-38D Test Case 14 (AES-256, 96-bit IV, no AAD)
    #[test]
    fn nist_test_vector_no_aad() {
        let key = hex("0000000000000000000000000000000000000000000000000000000000000000");
        let nonce = hex("000000000000000000000000");
        let expected_pt = hex("");
        let ct = hex("");
        let tag = hex("530f8afbc74536b9a963b4f1c4cb738b");

        let mut input = Vec::with_capacity(nonce.len() + ct.len() + tag.len());
        input.extend_from_slice(&nonce);
        input.extend_from_slice(&ct);
        input.extend_from_slice(&tag);

        let cipher = Aes256GcmCipher::new(key).expect("cipher");
        let plaintext = cipher.decrypt(&input, &expected_pt).expect("decrypt");
        assert_eq!(plaintext, expected_pt);
    }

    #[test]
    fn large_payload_roundtrip() {
        let cipher = Aes256GcmCipher::new(make_key()).expect("cipher");
        let plaintext = vec![0xABu8; 1_000_000]; // 1 MB
        let aad = b"large-payload-test";

        let ciphertext = cipher.encrypt(&plaintext, aad).expect("encrypt");
        // nonce (12) + plaintext (1M) + tag (16)
        assert_eq!(ciphertext.len(), NONCE_LEN + plaintext.len() + TAG_LEN);

        let decrypted = cipher.decrypt(&ciphertext, aad).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn empty_aad_roundtrip() {
        let cipher = Aes256GcmCipher::new(make_key()).expect("cipher");
        let plaintext = b"data with no associated data";

        let ciphertext = cipher.encrypt(plaintext, b"").expect("encrypt");
        let decrypted = cipher.decrypt(&ciphertext, b"").expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }
}
