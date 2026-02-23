//! Shared crypto primitives for streaming encrypt/decrypt.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::core::error::CryptoError;
use crate::core::format::Algorithm;

use super::format::STREAM_HEADER_SIZE;
use super::{StreamCipher, NONCE_LEN};

/// HKDF info prefix for per-file encryption key derivation.
const KEY_INFO: &[u8] = b"msec-stream-key";

/// HKDF info prefix for per-chunk nonce derivation.
const NONCE_INFO_PREFIX: &[u8] = b"msec-stream-nonce";

/// Combined size: prefix length + u64 chunk index (8 bytes).
const NONCE_INFO_SIZE: usize = NONCE_INFO_PREFIX.len() + 8;

/// Internal cipher dispatch — avoids trait object overhead in the hot loop.
pub(crate) enum CipherInstance {
    AesGcm(Box<Aes256Gcm>),
    ChaCha(ChaCha20Poly1305),
}

impl CipherInstance {
    pub(crate) fn new(algorithm: StreamCipher, key: &[u8]) -> Result<Self, CryptoError> {
        match algorithm {
            StreamCipher::AesGcm => {
                let cipher = Aes256Gcm::new_from_slice(key)
                    .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
                Ok(Self::AesGcm(Box::new(cipher)))
            }
            StreamCipher::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
                Ok(Self::ChaCha(cipher))
            }
        }
    }

    pub(crate) fn from_algorithm(algorithm: Algorithm, key: &[u8]) -> Result<Self, CryptoError> {
        match algorithm {
            Algorithm::AesGcm => {
                let cipher = Aes256Gcm::new_from_slice(key)
                    .map_err(|_| CryptoError::DecryptionFailed)?;
                Ok(Self::AesGcm(Box::new(cipher)))
            }
            Algorithm::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|_| CryptoError::DecryptionFailed)?;
                Ok(Self::ChaCha(cipher))
            }
            Algorithm::XChaCha20Poly1305 => Err(CryptoError::InvalidParameter(
                "XChaCha20-Poly1305 streaming not yet supported".to_string(),
            )),
        }
    }

    pub(crate) fn encrypt(&self, nonce: &[u8], payload: Payload<'_, '_>) -> Result<Vec<u8>, CryptoError> {
        match self {
            Self::AesGcm(c) => c
                .encrypt(aes_gcm::Nonce::from_slice(nonce), payload)
                .map_err(|e| CryptoError::EncryptionFailed(e.to_string())),
            Self::ChaCha(c) => c
                .encrypt(chacha20poly1305::Nonce::from_slice(nonce), payload)
                .map_err(|e| CryptoError::EncryptionFailed(e.to_string())),
        }
    }

    pub(crate) fn decrypt(&self, nonce: &[u8], payload: Payload<'_, '_>) -> Result<Vec<u8>, CryptoError> {
        match self {
            Self::AesGcm(c) => c
                .decrypt(aes_gcm::Nonce::from_slice(nonce), payload)
                .map_err(|_| CryptoError::AuthenticationFailed),
            Self::ChaCha(c) => c
                .decrypt(chacha20poly1305::Nonce::from_slice(nonce), payload)
                .map_err(|_| CryptoError::AuthenticationFailed),
        }
    }
}

/// HKDF context for per-file key and nonce derivation.
///
/// Derives a separate file encryption key from the master key + file salt,
/// so the master key never touches the AEAD cipher directly.
pub(crate) struct StreamKeyContext {
    hkdf: Hkdf<Sha256>,
}

impl StreamKeyContext {
    /// Extract PRK from master key + file salt.
    pub(crate) fn new(master_key: &[u8], file_salt: &[u8]) -> Self {
        Self {
            hkdf: Hkdf::<Sha256>::new(Some(file_salt), master_key),
        }
    }

    /// Derive the per-file encryption key (32 bytes), zeroized on drop.
    pub(crate) fn derive_file_key(&self) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        let mut key = Zeroizing::new([0u8; 32]);
        self.hkdf
            .expand(KEY_INFO, key.as_mut())
            .map_err(|_| CryptoError::KdfFailed("file key derivation failed".to_string()))?;
        Ok(key)
    }

    /// Derive a 12-byte nonce for a specific chunk.
    pub(crate) fn derive_chunk_nonce(&self, chunk_index: u64) -> Result<[u8; NONCE_LEN], CryptoError> {
        let mut info = [0u8; NONCE_INFO_SIZE];
        info[..NONCE_INFO_PREFIX.len()].copy_from_slice(NONCE_INFO_PREFIX);
        info[NONCE_INFO_PREFIX.len()..].copy_from_slice(&chunk_index.to_le_bytes());

        let mut nonce = [0u8; NONCE_LEN];
        self.hkdf
            .expand(&info, &mut nonce)
            .map_err(|_| CryptoError::KdfFailed("chunk nonce derivation failed".to_string()))?;
        Ok(nonce)
    }
}

/// Build AAD for a chunk: header_bytes (50) || chunk_index as LE u64 (8).
///
/// Including the header in AAD integrity-protects the algorithm, chunk_size,
/// total_chunks, and file_salt fields against tampering.
pub(crate) fn build_chunk_aad(header_bytes: &[u8; STREAM_HEADER_SIZE], chunk_index: u64) -> [u8; STREAM_HEADER_SIZE + 8] {
    let mut aad = [0u8; STREAM_HEADER_SIZE + 8];
    aad[..STREAM_HEADER_SIZE].copy_from_slice(header_bytes);
    aad[STREAM_HEADER_SIZE..].copy_from_slice(&chunk_index.to_le_bytes());
    aad
}

pub(crate) fn algorithm_to_format(alg: StreamCipher) -> Algorithm {
    match alg {
        StreamCipher::AesGcm => Algorithm::AesGcm,
        StreamCipher::ChaCha20Poly1305 => Algorithm::ChaCha20Poly1305,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::rng::generate_random_bytes;

    fn make_key() -> Vec<u8> {
        generate_random_bytes(32).expect("key gen")
    }

    #[test]
    fn file_key_differs_from_master_key() {
        let master = make_key();
        let salt = [42u8; 32];
        let ctx = StreamKeyContext::new(&master, &salt);
        let file_key = ctx.derive_file_key().expect("derive");
        assert_ne!(file_key.as_ref(), master.as_slice());
    }

    #[test]
    fn file_key_is_deterministic() {
        let master = make_key();
        let salt = [42u8; 32];
        let k1 = StreamKeyContext::new(&master, &salt).derive_file_key().expect("k1");
        let k2 = StreamKeyContext::new(&master, &salt).derive_file_key().expect("k2");
        assert_eq!(*k1, *k2);
    }

    #[test]
    fn file_key_differs_by_salt() {
        let master = make_key();
        let k1 = StreamKeyContext::new(&master, &[1u8; 32]).derive_file_key().expect("k1");
        let k2 = StreamKeyContext::new(&master, &[2u8; 32]).derive_file_key().expect("k2");
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn nonce_is_deterministic() {
        let ctx = StreamKeyContext::new(&make_key(), &[42u8; 32]);
        let n1 = ctx.derive_chunk_nonce(0).expect("n1");
        let n2 = ctx.derive_chunk_nonce(0).expect("n2");
        assert_eq!(n1, n2);
    }

    #[test]
    fn nonce_differs_by_index() {
        let ctx = StreamKeyContext::new(&make_key(), &[42u8; 32]);
        let n0 = ctx.derive_chunk_nonce(0).expect("n0");
        let n1 = ctx.derive_chunk_nonce(1).expect("n1");
        assert_ne!(n0, n1);
    }

    #[test]
    fn nonce_differs_by_salt() {
        let key = make_key();
        let na = StreamKeyContext::new(&key, &[1u8; 32]).derive_chunk_nonce(0).expect("na");
        let nb = StreamKeyContext::new(&key, &[2u8; 32]).derive_chunk_nonce(0).expect("nb");
        assert_ne!(na, nb);
    }

    #[test]
    fn aad_includes_header_and_index() {
        let header = [0xAA; STREAM_HEADER_SIZE];
        let aad = build_chunk_aad(&header, 42);
        assert_eq!(&aad[..STREAM_HEADER_SIZE], &header);
        assert_eq!(&aad[STREAM_HEADER_SIZE..], &42u64.to_le_bytes());
    }
}
