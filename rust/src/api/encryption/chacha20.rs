//! ChaCha20-Poly1305 authenticated encryption.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};

use crate::core::error::CryptoError;
use crate::core::rng::generate_nonce;
use crate::core::secret::SecretBuffer;
use crate::core::traits::Encryption;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// ChaCha20-Poly1305 cipher with key stored in secure, zeroize-on-drop memory.
pub struct ChaCha20Poly1305Cipher {
    key: SecretBuffer,
}

impl ChaCha20Poly1305Cipher {
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

impl Encryption for ChaCha20Poly1305Cipher {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let cipher = ChaCha20Poly1305::new_from_slice(self.key.as_bytes())
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        let nonce_bytes = generate_nonce(NONCE_LEN)?;
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);

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
        let nonce = chacha20poly1305::Nonce::from_slice(nonce_bytes);

        let cipher = ChaCha20Poly1305::new_from_slice(self.key.as_bytes())
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
        "chacha20-poly1305"
    }
}

/// Generate a random 32-byte ChaCha20-Poly1305 key.
pub fn generate_chacha_key() -> Result<Vec<u8>, CryptoError> {
    crate::core::rng::generate_random_bytes(KEY_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::encryption::aes_gcm::Aes256GcmCipher;

    fn make_key() -> Vec<u8> {
        generate_chacha_key().expect("key gen failed")
    }

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    #[test]
    fn encrypt_then_decrypt_roundtrip() {
        let cipher = ChaCha20Poly1305Cipher::new(make_key()).expect("cipher");
        let plaintext = b"hello, ChaCha20-Poly1305!";
        let aad = b"metadata";

        let ciphertext = cipher.encrypt(plaintext, aad).expect("encrypt");
        let decrypted = cipher.decrypt(&ciphertext, aad).expect("decrypt");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_returns_auth_error() {
        let cipher1 = ChaCha20Poly1305Cipher::new(make_key()).expect("c1");
        let cipher2 = ChaCha20Poly1305Cipher::new(make_key()).expect("c2");

        let ciphertext = cipher1.encrypt(b"secret", b"").expect("encrypt");
        let result = cipher2.decrypt(&ciphertext, b"");

        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn tampered_ciphertext_returns_auth_error() {
        let cipher = ChaCha20Poly1305Cipher::new(make_key()).expect("cipher");
        let mut ciphertext = cipher.encrypt(b"secret", b"").expect("encrypt");

        let idx = NONCE_LEN + 1;
        ciphertext[idx] ^= 0xFF;

        let result = cipher.decrypt(&ciphertext, b"");
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn tampered_aad_returns_auth_error() {
        let cipher = ChaCha20Poly1305Cipher::new(make_key()).expect("cipher");
        let ciphertext = cipher.encrypt(b"secret", b"original-aad").expect("encrypt");

        let result = cipher.decrypt(&ciphertext, b"tampered-aad");
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn same_plaintext_produces_different_ciphertext() {
        let cipher = ChaCha20Poly1305Cipher::new(make_key()).expect("cipher");
        let plaintext = b"same data";

        let ct1 = cipher.encrypt(plaintext, b"").expect("encrypt1");
        let ct2 = cipher.encrypt(plaintext, b"").expect("encrypt2");

        assert_ne!(ct1, ct2);
    }

    #[test]
    fn empty_plaintext_works() {
        let cipher = ChaCha20Poly1305Cipher::new(make_key()).expect("cipher");

        let ciphertext = cipher.encrypt(b"", b"").expect("encrypt empty");
        assert_eq!(ciphertext.len(), NONCE_LEN + TAG_LEN);

        let decrypted = cipher.decrypt(&ciphertext, b"").expect("decrypt empty");
        assert!(decrypted.is_empty());
    }

    #[test]
    fn bad_key_size_returns_error() {
        let result = ChaCha20Poly1305Cipher::new(vec![0u8; 16]);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: 16
            })
        ));
    }

    #[test]
    fn generate_chacha_key_returns_32_bytes() {
        let key = generate_chacha_key().expect("key gen");
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn generate_chacha_key_is_random() {
        let k1 = generate_chacha_key().expect("k1");
        let k2 = generate_chacha_key().expect("k2");
        assert_ne!(k1, k2);
    }

    #[test]
    fn algorithm_id_is_correct() {
        let cipher = ChaCha20Poly1305Cipher::new(make_key()).expect("cipher");
        assert_eq!(cipher.algorithm_id(), "chacha20-poly1305");
    }

    #[test]
    fn too_short_ciphertext_returns_auth_error() {
        let cipher = ChaCha20Poly1305Cipher::new(make_key()).expect("cipher");
        // One byte below minimum (nonce + tag = 28)
        let result = cipher.decrypt(&[0u8; NONCE_LEN + TAG_LEN - 1], b"");
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    // RFC 8439 §2.8.2 test vector
    #[test]
    fn rfc8439_test_vector_decrypt() {
        let key = from_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce = from_hex("070000004041424344454647");
        let aad = from_hex("50515253c0c1c2c3c4c5c6c7");
        let expected_pt = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";
        let ct = from_hex(
            "d31a8d34648e60db7b86afbc53ef7ec2\
             a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b\
             1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58\
             fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b\
             6116",
        );
        let tag = from_hex("1ae10b594f09e26a7e902ecbd0600691");

        // Wire format: nonce || ciphertext || tag
        let mut input = Vec::with_capacity(nonce.len() + ct.len() + tag.len());
        input.extend_from_slice(&nonce);
        input.extend_from_slice(&ct);
        input.extend_from_slice(&tag);

        let cipher = ChaCha20Poly1305Cipher::new(key).expect("cipher");
        let plaintext = cipher.decrypt(&input, &aad).expect("decrypt");
        assert_eq!(plaintext, expected_pt);
    }

    #[test]
    fn large_payload_roundtrip() {
        let cipher = ChaCha20Poly1305Cipher::new(make_key()).expect("cipher");
        let plaintext = vec![0xABu8; 1_000_000];
        let aad = b"large-payload-test";

        let ciphertext = cipher.encrypt(&plaintext, aad).expect("encrypt");
        assert_eq!(ciphertext.len(), NONCE_LEN + plaintext.len() + TAG_LEN);

        let decrypted = cipher.decrypt(&ciphertext, aad).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn empty_aad_roundtrip() {
        let cipher = ChaCha20Poly1305Cipher::new(make_key()).expect("cipher");
        let plaintext = b"data with no associated data";

        let ciphertext = cipher.encrypt(plaintext, b"").expect("encrypt");
        let decrypted = cipher.decrypt(&ciphertext, b"").expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    // Cross-algorithm tests: AES-GCM and ChaCha20 must not be interchangeable
    #[test]
    fn aes_gcm_ciphertext_not_decryptable_by_chacha20() {
        let key = make_key();
        let aes = Aes256GcmCipher::new(key.clone()).expect("aes");
        let chacha = ChaCha20Poly1305Cipher::new(key).expect("chacha");

        let ciphertext = aes.encrypt(b"cross-algo test", b"").expect("encrypt");
        let result = chacha.decrypt(&ciphertext, b"");

        assert!(result.is_err());
    }

    #[test]
    fn chacha20_ciphertext_not_decryptable_by_aes_gcm() {
        let key = make_key();
        let chacha = ChaCha20Poly1305Cipher::new(key.clone()).expect("chacha");
        let aes = Aes256GcmCipher::new(key).expect("aes");

        let ciphertext = chacha.encrypt(b"cross-algo test", b"").expect("encrypt");
        let result = aes.decrypt(&ciphertext, b"");

        assert!(result.is_err());
    }
}
