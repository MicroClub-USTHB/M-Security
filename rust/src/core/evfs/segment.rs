//! Per-segment encryption, integrity, and secure deletion.

use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::core::error::CryptoError;
use crate::core::format::Algorithm;
use crate::core::secret::SecretBuffer;

#[cfg(feature = "compression")]
use crate::api::compression::{self, CompressionAlgorithm, CompressionConfig};

use std::io::{Seek, SeekFrom, Write};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CIPHER_KEY_INFO: &[u8] = b"msec-vault-cipher-key";
const NONCE_KEY_INFO: &[u8] = b"msec-vault-nonce-key";
const INDEX_KEY_INFO: &[u8] = b"msec-vault-index-key";
const INDEX_NONCE_INFO: &[u8] = b"msec-vault-index-nonce";

const SUB_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Chunk size for streaming pre-allocation and secure erase (64KB).
const IO_CHUNK_SIZE: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// VaultKeys
// ---------------------------------------------------------------------------

/// Derived sub-keys from the master key. All fields use SecretBuffer (ZeroizeOnDrop).
pub struct VaultKeys {
    pub cipher_key: SecretBuffer,
    pub nonce_key: SecretBuffer,
    pub index_key: SecretBuffer,
}

/// Derive three domain-separated sub-keys from a master key via HKDF-SHA256.
pub fn derive_vault_keys(master_key: &[u8]) -> Result<VaultKeys, CryptoError> {
    if master_key.is_empty() {
        return Err(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: 0,
        });
    }
    let hk = Hkdf::<Sha256>::new(None, master_key);

    let mut cipher_key = SecretBuffer::from_size(SUB_KEY_LEN);
    hk.expand(CIPHER_KEY_INFO, cipher_key.as_bytes_mut())
        .map_err(|_| CryptoError::KdfFailed("HKDF expand failed for cipher_key".into()))?;

    let mut nonce_key = SecretBuffer::from_size(SUB_KEY_LEN);
    hk.expand(NONCE_KEY_INFO, nonce_key.as_bytes_mut())
        .map_err(|_| CryptoError::KdfFailed("HKDF expand failed for nonce_key".into()))?;

    let mut index_key = SecretBuffer::from_size(SUB_KEY_LEN);
    hk.expand(INDEX_KEY_INFO, index_key.as_bytes_mut())
        .map_err(|_| CryptoError::KdfFailed("HKDF expand failed for index_key".into()))?;

    Ok(VaultKeys {
        cipher_key,
        nonce_key,
        index_key,
    })
}

// ---------------------------------------------------------------------------
// Nonce derivation
// ---------------------------------------------------------------------------

/// Derive a deterministic nonce for a segment.
///
/// `info = segment_index(LE) || generation(LE)`
///
/// Including the generation counter ensures overwriting a segment at
/// the same index always produces a different nonce.
pub fn derive_segment_nonce(
    nonce_key: &[u8],
    segment_index: u64,
    generation: u64,
    nonce_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let hk = Hkdf::<Sha256>::from_prk(nonce_key)
        .map_err(|_| CryptoError::KdfFailed("nonce_key too short for HKDF-PRK".into()))?;

    let mut info = [0u8; 16];
    info[..8].copy_from_slice(&segment_index.to_le_bytes());
    info[8..].copy_from_slice(&generation.to_le_bytes());

    let mut nonce = vec![0u8; nonce_len];
    hk.expand(&info, &mut nonce)
        .map_err(|_| CryptoError::KdfFailed("HKDF expand failed for nonce".into()))?;
    Ok(nonce)
}

// ---------------------------------------------------------------------------
// Streaming segment support (per-chunk nonce + AAD)
// ---------------------------------------------------------------------------

/// Per-chunk AAD for vault streaming segments.
///
/// Extends standalone `ChunkAad` with `generation` to bind each chunk to its
/// specific segment write, preventing cross-segment splice attacks.
///
/// Wire format: `[generation: u64 LE] [chunk_index: u64 LE] [is_final: u8]` = 17 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultChunkAad {
    pub generation: u64,
    pub chunk_index: u64,
    pub is_final: bool,
}

/// Wire size of `VaultChunkAad`.
pub const VAULT_CHUNK_AAD_SIZE: usize = 17;

impl VaultChunkAad {
    pub fn to_bytes(self) -> [u8; VAULT_CHUNK_AAD_SIZE] {
        let mut buf = [0u8; VAULT_CHUNK_AAD_SIZE];
        buf[0..8].copy_from_slice(&self.generation.to_le_bytes());
        buf[8..16].copy_from_slice(&self.chunk_index.to_le_bytes());
        buf[16] = u8::from(self.is_final);
        buf
    }
}

/// Derive a unique nonce for a specific chunk within a streaming segment.
///
/// Uses a domain-separated HKDF info (`0x01 || chunk_index || generation`)
/// to ensure chunk nonces never collide with monolithic segment nonces
/// (which use `segment_index || generation` without a domain prefix).
pub fn derive_chunk_nonce(
    nonce_key: &[u8],
    chunk_index: u64,
    generation: u64,
) -> Result<Vec<u8>, CryptoError> {
    let hk = Hkdf::<Sha256>::from_prk(nonce_key)
        .map_err(|_| CryptoError::KdfFailed("nonce_key too short for HKDF-PRK".into()))?;

    // 17-byte info: domain(1) || chunk_index(LE8) || generation(LE8)
    let mut info = [0u8; 17];
    info[0] = 0x01;
    info[1..9].copy_from_slice(&chunk_index.to_le_bytes());
    info[9..17].copy_from_slice(&generation.to_le_bytes());

    let mut nonce = vec![0u8; NONCE_LEN];
    hk.expand(&info, &mut nonce)
        .map_err(|_| CryptoError::KdfFailed("HKDF expand failed for chunk nonce".into()))?;
    Ok(nonce)
}

// ---------------------------------------------------------------------------
// AEAD helpers (algorithm dispatch)
// ---------------------------------------------------------------------------

fn aead_encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    algorithm: Algorithm,
) -> Result<Vec<u8>, CryptoError> {
    match algorithm {
        Algorithm::AesGcm => aead_encrypt_aes_gcm(key, nonce, plaintext, aad),
        Algorithm::ChaCha20Poly1305 => aead_encrypt_chacha(key, nonce, plaintext, aad),
        Algorithm::XChaCha20Poly1305 => Err(CryptoError::InvalidParameter(
            "XChaCha20-Poly1305 not yet supported for EVFS".into(),
        )),
    }
}

fn aead_decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
    algorithm: Algorithm,
) -> Result<Vec<u8>, CryptoError> {
    match algorithm {
        Algorithm::AesGcm => aead_decrypt_aes_gcm(key, nonce, ciphertext, aad),
        Algorithm::ChaCha20Poly1305 => aead_decrypt_chacha(key, nonce, ciphertext, aad),
        Algorithm::XChaCha20Poly1305 => Err(CryptoError::InvalidParameter(
            "XChaCha20-Poly1305 not yet supported for EVFS".into(),
        )),
    }
}

fn aead_encrypt_aes_gcm(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::Aes256Gcm;

    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
    let nonce = aes_gcm::Nonce::from_slice(nonce);
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    cipher
        .encrypt(nonce, payload)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))
}

fn aead_decrypt_aes_gcm(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::Aes256Gcm;

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::DecryptionFailed)?;
    let nonce = aes_gcm::Nonce::from_slice(nonce);
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::AuthenticationFailed)
}

fn aead_encrypt_chacha(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::ChaCha20Poly1305;

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
    let nonce = chacha20poly1305::Nonce::from_slice(nonce);
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    cipher
        .encrypt(nonce, payload)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))
}

fn aead_decrypt_chacha(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::ChaCha20Poly1305;

    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::DecryptionFailed)?;
    let nonce = chacha20poly1305::Nonce::from_slice(nonce);
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::AuthenticationFailed)
}

// ---------------------------------------------------------------------------
// AEAD helpers for vault API (random nonce, stored nonce)
// ---------------------------------------------------------------------------

/// Encrypt with a random nonce. Returns `nonce || ciphertext || tag`.
pub fn aead_encrypt_random_nonce(
    key: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    algorithm: Algorithm,
) -> Result<Vec<u8>, CryptoError> {
    use rand::{rngs::OsRng, RngCore};
    let mut nonce = vec![0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct_tag = aead_encrypt(key, &nonce, plaintext, aad, algorithm)?;
    let mut output = Vec::with_capacity(NONCE_LEN + ct_tag.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ct_tag);
    Ok(output)
}

/// Decrypt data where the nonce is stored as a prefix.
/// Input: `nonce || ciphertext || tag`.
pub fn aead_decrypt_with_stored_nonce(
    key: &[u8],
    encrypted: &[u8],
    aad: &[u8],
    algorithm: Algorithm,
) -> Result<Vec<u8>, CryptoError> {
    if encrypted.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::AuthenticationFailed);
    }
    let (nonce, ct_tag) = encrypted.split_at(NONCE_LEN);
    aead_decrypt(key, nonce, ct_tag, aad, algorithm)
}

// ---------------------------------------------------------------------------
// Segment encrypt / decrypt
// ---------------------------------------------------------------------------

/// Parameters for segment encrypt/decrypt operations.
pub struct SegmentCryptoParams<'a> {
    pub cipher_key: &'a [u8],
    pub nonce_key: &'a [u8],
    pub algorithm: Algorithm,
    pub segment_index: u64,
    pub generation: u64,
}

/// Compress-then-encrypt a segment's plaintext data.
///
/// Returns `(nonce || ciphertext || tag, effective_compression_algorithm)`.
///
/// BLAKE3 checksum should be computed by the caller on the original plaintext
/// **before** calling this function.
#[cfg(feature = "compression")]
pub fn encrypt_segment(
    params: &SegmentCryptoParams<'_>,
    plaintext: &[u8],
    segment_name: &str,
    compression: &CompressionConfig,
) -> Result<(Vec<u8>, CompressionAlgorithm), CryptoError> {
    // MIME-aware skip
    let effective_algo = if compression.algorithm != CompressionAlgorithm::None
        && compression::should_skip_compression(segment_name)
    {
        CompressionAlgorithm::None
    } else {
        compression.algorithm
    };

    // Compress
    let mut data = if effective_algo != CompressionAlgorithm::None {
        compression::compress(
            plaintext,
            &CompressionConfig {
                algorithm: effective_algo,
                level: compression.level,
            },
        )?
    } else {
        plaintext.to_vec()
    };

    // Derive nonce and encrypt
    let nonce = derive_segment_nonce(
        params.nonce_key,
        params.segment_index,
        params.generation,
        NONCE_LEN,
    )?;
    let result = aead_encrypt(params.cipher_key, &nonce, &data, &[], params.algorithm);
    data.zeroize();
    let ct_tag = result?;

    // Wire format: nonce || ciphertext || tag
    let mut output = Vec::with_capacity(NONCE_LEN + ct_tag.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ct_tag);

    Ok((output, effective_algo))
}

/// Decrypt-then-decompress a segment's encrypted data.
///
/// The `compression` argument comes from `SegmentEntry.compression`.
#[cfg(feature = "compression")]
pub fn decrypt_segment(
    params: &SegmentCryptoParams<'_>,
    encrypted: &[u8],
    compression: CompressionAlgorithm,
) -> Result<Vec<u8>, CryptoError> {
    if encrypted.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::AuthenticationFailed);
    }

    let (stored_nonce, ct_tag) = encrypted.split_at(NONCE_LEN);

    // Derive expected nonce and verify it matches
    let expected_nonce = derive_segment_nonce(
        params.nonce_key,
        params.segment_index,
        params.generation,
        NONCE_LEN,
    )?;
    if stored_nonce.ct_ne(&expected_nonce).into() {
        return Err(CryptoError::AuthenticationFailed);
    }

    let decrypted = aead_decrypt(
        params.cipher_key,
        stored_nonce,
        ct_tag,
        &[],
        params.algorithm,
    )?;

    // Decompress if needed
    if compression != CompressionAlgorithm::None {
        compression::decompress(&decrypted, compression)
    } else {
        Ok(decrypted)
    }
}

// ---------------------------------------------------------------------------
// Index encrypt / decrypt
// ---------------------------------------------------------------------------

/// Encrypt the segment index using the index sub-key.
///
/// `generation` is the `SegmentIndex.next_generation` value at the time of
/// writing. It is included in nonce derivation so that every index write
/// produces a unique nonce (preventing nonce reuse on repeated saves).
pub fn encrypt_index(
    index_key: &[u8],
    algorithm: Algorithm,
    generation: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let nonce = derive_index_nonce(index_key, generation)?;
    let ct_tag = aead_encrypt(index_key, &nonce, plaintext, &[], algorithm)?;

    let mut output = Vec::with_capacity(NONCE_LEN + ct_tag.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ct_tag);
    Ok(output)
}

/// Decrypt the segment index using the index sub-key.
///
/// `generation` must match the value used during encryption.
pub fn decrypt_index(
    index_key: &[u8],
    algorithm: Algorithm,
    generation: u64,
    encrypted: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if encrypted.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::AuthenticationFailed);
    }
    let (stored_nonce, ct_tag) = encrypted.split_at(NONCE_LEN);

    // Verify nonce matches the expected derivation
    let expected_nonce = derive_index_nonce(index_key, generation)?;
    if stored_nonce.ct_ne(&expected_nonce).into() {
        return Err(CryptoError::AuthenticationFailed);
    }

    aead_decrypt(index_key, stored_nonce, ct_tag, &[], algorithm)
}

fn derive_index_nonce(index_key: &[u8], generation: u64) -> Result<Vec<u8>, CryptoError> {
    let hk = Hkdf::<Sha256>::from_prk(index_key)
        .map_err(|_| CryptoError::KdfFailed("index_key too short for HKDF-PRK".into()))?;
    // info = fixed domain || generation(LE)
    let mut info = Vec::with_capacity(INDEX_NONCE_INFO.len() + 8);
    info.extend_from_slice(INDEX_NONCE_INFO);
    info.extend_from_slice(&generation.to_le_bytes());
    let mut nonce = vec![0u8; NONCE_LEN];
    hk.expand(&info, &mut nonce)
        .map_err(|_| CryptoError::KdfFailed("HKDF expand failed for index nonce".into()))?;
    Ok(nonce)
}

// ---------------------------------------------------------------------------
// BLAKE3 checksums
// ---------------------------------------------------------------------------

/// Compute BLAKE3 checksum of plaintext data (pre-compression).
pub fn compute_checksum(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}

/// Verify BLAKE3 checksum using constant-time comparison.
pub fn verify_checksum(data: &[u8], expected: &[u8; 32]) -> bool {
    let actual = compute_checksum(data);
    actual.ct_eq(expected).into()
}

// ---------------------------------------------------------------------------
// Pre-allocation and secure erase
// ---------------------------------------------------------------------------

/// Pre-allocate a vault file filled with CSPRNG random data.
///
/// Writes in 64KB chunks to keep memory constant for large vaults.
pub fn preallocate_vault(file: &mut std::fs::File, total_size: u64) -> Result<(), CryptoError> {
    use rand::{rngs::OsRng, RngCore};

    let mut remaining = total_size;
    let mut buf = vec![0u8; IO_CHUNK_SIZE];

    while remaining > 0 {
        let chunk_len = std::cmp::min(remaining, IO_CHUNK_SIZE as u64) as usize;
        OsRng.fill_bytes(&mut buf[..chunk_len]);
        file.write_all(&buf[..chunk_len])?;
        remaining -= chunk_len as u64;
    }
    file.sync_all()?;
    Ok(())
}

/// Securely erase a region of the vault file by overwriting with CSPRNG bytes.
///
/// Writes random data in 64KB chunks, then fsyncs.
pub fn secure_erase_region(
    file: &mut std::fs::File,
    offset: u64,
    size: u64,
) -> Result<(), CryptoError> {
    use rand::{rngs::OsRng, RngCore};

    file.seek(SeekFrom::Start(offset))?;

    let mut remaining = size;
    let mut buf = vec![0u8; IO_CHUNK_SIZE];

    while remaining > 0 {
        let chunk_len = std::cmp::min(remaining, IO_CHUNK_SIZE as u64) as usize;
        OsRng.fill_bytes(&mut buf[..chunk_len]);
        file.write_all(&buf[..chunk_len])?;
        remaining -= chunk_len as u64;
    }
    file.sync_all()?;
    Ok(())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_master_key() -> Vec<u8> {
        vec![0xAA; 32]
    }

    fn other_master_key() -> Vec<u8> {
        vec![0xBB; 32]
    }

    // -- Key derivation -----------------------------------------------------

    #[test]
    fn test_derive_vault_keys_empty_master_rejected() {
        assert!(derive_vault_keys(&[]).is_err());
    }

    #[test]
    fn test_derive_vault_keys_deterministic() {
        let k1 = derive_vault_keys(&test_master_key()).expect("derive");
        let k2 = derive_vault_keys(&test_master_key()).expect("derive");
        assert_eq!(k1.cipher_key.as_bytes(), k2.cipher_key.as_bytes());
        assert_eq!(k1.nonce_key.as_bytes(), k2.nonce_key.as_bytes());
        assert_eq!(k1.index_key.as_bytes(), k2.index_key.as_bytes());
    }

    #[test]
    fn test_derive_vault_keys_domain_separation() {
        let keys = derive_vault_keys(&test_master_key()).expect("derive");
        assert_ne!(keys.cipher_key.as_bytes(), keys.nonce_key.as_bytes());
        assert_ne!(keys.cipher_key.as_bytes(), keys.index_key.as_bytes());
        assert_ne!(keys.nonce_key.as_bytes(), keys.index_key.as_bytes());
    }

    #[test]
    fn test_derive_vault_keys_different_master() {
        let k1 = derive_vault_keys(&test_master_key()).expect("derive");
        let k2 = derive_vault_keys(&other_master_key()).expect("derive");
        assert_ne!(k1.cipher_key.as_bytes(), k2.cipher_key.as_bytes());
        assert_ne!(k1.nonce_key.as_bytes(), k2.nonce_key.as_bytes());
        assert_ne!(k1.index_key.as_bytes(), k2.index_key.as_bytes());
    }

    // -- Nonce derivation ---------------------------------------------------

    #[test]
    fn test_nonce_deterministic() {
        let keys = derive_vault_keys(&test_master_key()).expect("derive");
        let n1 = derive_segment_nonce(keys.nonce_key.as_bytes(), 0, 0, NONCE_LEN).expect("nonce");
        let n2 = derive_segment_nonce(keys.nonce_key.as_bytes(), 0, 0, NONCE_LEN).expect("nonce");
        assert_eq!(n1, n2);
    }

    #[test]
    fn test_nonce_unique_by_index() {
        let keys = derive_vault_keys(&test_master_key()).expect("derive");
        let n0 = derive_segment_nonce(keys.nonce_key.as_bytes(), 0, 0, NONCE_LEN).expect("nonce");
        let n1 = derive_segment_nonce(keys.nonce_key.as_bytes(), 1, 0, NONCE_LEN).expect("nonce");
        assert_ne!(n0, n1);
    }

    #[test]
    fn test_nonce_unique_by_generation() {
        let keys = derive_vault_keys(&test_master_key()).expect("derive");
        let n0 = derive_segment_nonce(keys.nonce_key.as_bytes(), 0, 0, NONCE_LEN).expect("nonce");
        let n1 = derive_segment_nonce(keys.nonce_key.as_bytes(), 0, 1, NONCE_LEN).expect("nonce");
        assert_ne!(n0, n1);
    }

    #[test]
    fn test_nonce_length_12() {
        let keys = derive_vault_keys(&test_master_key()).expect("derive");
        let nonce =
            derive_segment_nonce(keys.nonce_key.as_bytes(), 0, 0, NONCE_LEN).expect("nonce");
        assert_eq!(nonce.len(), 12);
    }

    // -- Segment encrypt/decrypt (no compression) ---------------------------

    #[cfg(feature = "compression")]
    fn no_compression_config() -> CompressionConfig {
        CompressionConfig {
            algorithm: CompressionAlgorithm::None,
            level: None,
        }
    }

    #[cfg(feature = "compression")]
    fn params<'a>(
        keys: &'a VaultKeys,
        algorithm: Algorithm,
        segment_index: u64,
        generation: u64,
    ) -> SegmentCryptoParams<'a> {
        SegmentCryptoParams {
            cipher_key: keys.cipher_key.as_bytes(),
            nonce_key: keys.nonce_key.as_bytes(),
            algorithm,
            segment_index,
            generation,
        }
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_segment_encrypt_decrypt_roundtrip() {
        let keys = derive_vault_keys(&test_master_key()).expect("derive");
        let plaintext = b"hello vault segment";
        let p = params(&keys, Algorithm::AesGcm, 0, 0);

        let (encrypted, effective) =
            encrypt_segment(&p, plaintext, "test.txt", &no_compression_config()).expect("encrypt");
        assert_eq!(effective, CompressionAlgorithm::None);

        let decrypted =
            decrypt_segment(&p, &encrypted, CompressionAlgorithm::None).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_segment_wrong_generation_fails() {
        let keys = derive_vault_keys(&test_master_key()).expect("derive");
        let p = params(&keys, Algorithm::AesGcm, 0, 0);

        let (encrypted, _) =
            encrypt_segment(&p, b"data", "test.txt", &no_compression_config()).expect("encrypt");

        // Decrypt with wrong generation
        let wrong_p = params(&keys, Algorithm::AesGcm, 0, 1);
        let result = decrypt_segment(&wrong_p, &encrypted, CompressionAlgorithm::None);
        assert!(result.is_err());
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_segment_wrong_key_fails() {
        let keys = derive_vault_keys(&test_master_key()).expect("derive");
        let wrong_keys = derive_vault_keys(&other_master_key()).expect("derive");
        let p = params(&keys, Algorithm::AesGcm, 0, 0);

        let (encrypted, _) =
            encrypt_segment(&p, b"secret", "test.txt", &no_compression_config()).expect("encrypt");

        let wrong_p = params(&wrong_keys, Algorithm::AesGcm, 0, 0);
        let result = decrypt_segment(&wrong_p, &encrypted, CompressionAlgorithm::None);
        assert!(result.is_err());
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_segment_tampered_ciphertext_fails() {
        let keys = derive_vault_keys(&test_master_key()).expect("derive");
        let p = params(&keys, Algorithm::AesGcm, 0, 0);

        let (mut encrypted, _) =
            encrypt_segment(&p, b"data", "test.txt", &no_compression_config()).expect("encrypt");
        encrypted[NONCE_LEN + 1] ^= 0xFF;

        let result = decrypt_segment(&p, &encrypted, CompressionAlgorithm::None);
        assert!(result.is_err());
    }

    // -- Segment compress+encrypt/decrypt+decompress ------------------------

    #[cfg(feature = "compression")]
    #[test]
    fn test_segment_zstd_roundtrip() {
        let keys = derive_vault_keys(&test_master_key()).expect("derive");
        let plaintext = b"compressible data repeated ".repeat(100);
        let config = CompressionConfig {
            algorithm: CompressionAlgorithm::Zstd,
            level: None,
        };
        let p = params(&keys, Algorithm::ChaCha20Poly1305, 5, 3);

        let (encrypted, effective) =
            encrypt_segment(&p, &plaintext, "data.txt", &config).expect("encrypt");
        assert_eq!(effective, CompressionAlgorithm::Zstd);

        let decrypted =
            decrypt_segment(&p, &encrypted, CompressionAlgorithm::Zstd).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_segment_brotli_roundtrip() {
        let keys = derive_vault_keys(&test_master_key()).expect("derive");
        let plaintext = b"brotli test data ".repeat(80);
        let config = CompressionConfig {
            algorithm: CompressionAlgorithm::Brotli,
            level: None,
        };
        let p = params(&keys, Algorithm::AesGcm, 2, 1);

        let (encrypted, effective) =
            encrypt_segment(&p, &plaintext, "notes.txt", &config).expect("encrypt");
        assert_eq!(effective, CompressionAlgorithm::Brotli);

        let decrypted =
            decrypt_segment(&p, &encrypted, CompressionAlgorithm::Brotli).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_segment_mime_skip() {
        let keys = derive_vault_keys(&test_master_key()).expect("derive");
        let plaintext = b"fake jpeg data";
        let config = CompressionConfig {
            algorithm: CompressionAlgorithm::Zstd,
            level: None,
        };
        let p = params(&keys, Algorithm::AesGcm, 0, 0);

        let (encrypted, effective) =
            encrypt_segment(&p, plaintext, "photo.jpg", &config).expect("encrypt");
        assert_eq!(effective, CompressionAlgorithm::None);

        let decrypted =
            decrypt_segment(&p, &encrypted, CompressionAlgorithm::None).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_segment_compressed_smaller() {
        let keys = derive_vault_keys(&test_master_key()).expect("derive");
        let plaintext = b"aaaa".repeat(1000);

        let p0 = params(&keys, Algorithm::AesGcm, 0, 0);
        let (compressed_enc, _) = encrypt_segment(
            &p0,
            &plaintext,
            "text.txt",
            &CompressionConfig {
                algorithm: CompressionAlgorithm::Zstd,
                level: None,
            },
        )
        .expect("compress+encrypt");

        let p1 = params(&keys, Algorithm::AesGcm, 1, 0);
        let (uncompressed_enc, _) =
            encrypt_segment(&p1, &plaintext, "text.txt", &no_compression_config())
                .expect("encrypt only");

        assert!(compressed_enc.len() < uncompressed_enc.len());
    }

    // -- Index encryption ---------------------------------------------------

    #[test]
    fn test_index_encrypt_decrypt_roundtrip() {
        let keys = derive_vault_keys(&test_master_key()).expect("derive");
        let plaintext = b"index payload bytes for testing roundtrip";

        let encrypted = encrypt_index(keys.index_key.as_bytes(), Algorithm::AesGcm, 0, plaintext)
            .expect("encrypt");

        let decrypted = decrypt_index(keys.index_key.as_bytes(), Algorithm::AesGcm, 0, &encrypted)
            .expect("decrypt");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_index_wrong_generation_fails() {
        let keys = derive_vault_keys(&test_master_key()).expect("derive");
        let plaintext = b"index data";

        let encrypted = encrypt_index(keys.index_key.as_bytes(), Algorithm::AesGcm, 5, plaintext)
            .expect("encrypt");

        // Decrypt with wrong generation
        let result = decrypt_index(keys.index_key.as_bytes(), Algorithm::AesGcm, 6, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_index_nonce_unique_per_generation() {
        let keys = derive_vault_keys(&test_master_key()).expect("derive");
        let plaintext = b"same index data";

        let enc0 = encrypt_index(keys.index_key.as_bytes(), Algorithm::AesGcm, 0, plaintext)
            .expect("encrypt gen 0");
        let enc1 = encrypt_index(keys.index_key.as_bytes(), Algorithm::AesGcm, 1, plaintext)
            .expect("encrypt gen 1");

        // Nonce (first 12 bytes) must differ
        assert_ne!(&enc0[..NONCE_LEN], &enc1[..NONCE_LEN]);
    }

    // -- Checksums ----------------------------------------------------------

    #[test]
    fn test_checksum_roundtrip() {
        let data = b"hello checksum";
        let checksum = compute_checksum(data);
        assert!(verify_checksum(data, &checksum));
    }

    #[test]
    fn test_checksum_tampered() {
        let data = b"original data";
        let checksum = compute_checksum(data);
        let mut tampered = data.to_vec();
        tampered[0] ^= 0xFF;
        assert!(!verify_checksum(&tampered, &checksum));
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_checksum_covers_original_plaintext() {
        let plaintext = b"checksum covers pre-compression data ".repeat(50);
        let checksum = compute_checksum(&plaintext);

        // Compress the data
        let compressed = compression::compress(
            &plaintext,
            &CompressionConfig {
                algorithm: CompressionAlgorithm::Zstd,
                level: None,
            },
        )
        .expect("compress");

        // Checksum should NOT match the compressed form
        assert!(!verify_checksum(&compressed, &checksum));

        // Decompress and verify against original plaintext
        let decompressed =
            compression::decompress(&compressed, CompressionAlgorithm::Zstd).expect("decompress");
        assert!(verify_checksum(&decompressed, &checksum));
    }

    // -- Pre-allocation and secure erase ------------------------------------

    #[test]
    fn test_preallocate_size() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.test");
        let mut file = std::fs::File::create(&path).expect("create");

        preallocate_vault(&mut file, 4096).expect("preallocate");

        let meta = std::fs::metadata(&path).expect("metadata");
        assert_eq!(meta.len(), 4096);
    }

    #[test]
    fn test_preallocate_random_fill() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.test");
        let mut file = std::fs::File::create(&path).expect("create");

        preallocate_vault(&mut file, 4096).expect("preallocate");

        let data = std::fs::read(&path).expect("read");
        // Extremely unlikely all zeros if filled with CSPRNG
        assert!(data.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_preallocate_streaming() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault_10mb.test");
        let mut file = std::fs::File::create(&path).expect("create");

        let size = 10 * 1024 * 1024; // 10MB
        preallocate_vault(&mut file, size).expect("preallocate 10MB");

        let meta = std::fs::metadata(&path).expect("metadata");
        assert_eq!(meta.len(), size);
    }

    #[test]
    fn test_secure_erase_region() {
        use std::io::Read;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("erase.test");

        // Write known pattern
        let pattern = vec![0xAA; 1024];
        std::fs::write(&path, &pattern).expect("write");

        // Erase a region in the middle
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .read(true)
            .open(&path)
            .expect("open");

        secure_erase_region(&mut file, 256, 512).expect("erase");

        // Read back the erased region
        file.seek(SeekFrom::Start(256)).expect("seek");
        let mut erased = vec![0u8; 512];
        file.read_exact(&mut erased).expect("read");

        // Should no longer be the original 0xAA pattern
        assert_ne!(erased, vec![0xAA; 512]);

        // Regions outside the erased area should be untouched
        file.seek(SeekFrom::Start(0)).expect("seek");
        let mut before = vec![0u8; 256];
        file.read_exact(&mut before).expect("read");
        assert_eq!(before, vec![0xAA; 256]);

        file.seek(SeekFrom::Start(768)).expect("seek");
        let mut after = vec![0u8; 256];
        file.read_exact(&mut after).expect("read");
        assert_eq!(after, vec![0xAA; 256]);
    }

    // -- Chunk nonce derivation (streaming segments) ------------------------

    #[test]
    fn test_chunk_nonce_deterministic() {
        let keys = derive_vault_keys(&test_master_key()).expect("derive");
        let n1 = derive_chunk_nonce(keys.nonce_key.as_bytes(), 0, 0).expect("nonce");
        let n2 = derive_chunk_nonce(keys.nonce_key.as_bytes(), 0, 0).expect("nonce");
        assert_eq!(n1, n2);
        assert_eq!(n1.len(), NONCE_LEN);
    }

    #[test]
    fn test_chunk_nonce_unique_per_chunk() {
        let keys = derive_vault_keys(&test_master_key()).expect("derive");
        let n0 = derive_chunk_nonce(keys.nonce_key.as_bytes(), 0, 0).expect("nonce");
        let n1 = derive_chunk_nonce(keys.nonce_key.as_bytes(), 1, 0).expect("nonce");
        let n2 = derive_chunk_nonce(keys.nonce_key.as_bytes(), 2, 0).expect("nonce");
        assert_ne!(n0, n1);
        assert_ne!(n1, n2);
        assert_ne!(n0, n2);
    }

    #[test]
    fn test_chunk_nonce_unique_per_generation() {
        let keys = derive_vault_keys(&test_master_key()).expect("derive");
        let n_gen0 = derive_chunk_nonce(keys.nonce_key.as_bytes(), 0, 0).expect("nonce");
        let n_gen1 = derive_chunk_nonce(keys.nonce_key.as_bytes(), 0, 1).expect("nonce");
        assert_ne!(n_gen0, n_gen1);
    }

    #[test]
    fn test_chunk_nonce_domain_separation() {
        // derive_chunk_nonce uses a domain-separated HKDF info, so it must
        // NOT produce the same nonce as derive_segment_nonce with identical
        // (index, generation) params. This prevents nonce collisions between
        // monolithic segments and streaming chunk nonces.
        let keys = derive_vault_keys(&test_master_key()).expect("derive");
        let chunk = derive_chunk_nonce(keys.nonce_key.as_bytes(), 42, 7).expect("chunk");
        let segment =
            derive_segment_nonce(keys.nonce_key.as_bytes(), 42, 7, NONCE_LEN).expect("segment");
        assert_ne!(chunk, segment);
    }

    #[test]
    fn test_vault_chunk_aad_wire_format() {
        let aad = VaultChunkAad {
            generation: 3,
            chunk_index: 99,
            is_final: true,
        };
        let bytes = aad.to_bytes();
        assert_eq!(bytes.len(), VAULT_CHUNK_AAD_SIZE);
        // generation = 3 LE
        assert_eq!(u64::from_le_bytes(bytes[0..8].try_into().unwrap()), 3);
        // chunk_index = 99 LE
        assert_eq!(u64::from_le_bytes(bytes[8..16].try_into().unwrap()), 99);
        // is_final = true
        assert_eq!(bytes[16], 1);
    }

    #[test]
    fn test_vault_chunk_aad_not_final() {
        let aad = VaultChunkAad {
            generation: 0,
            chunk_index: 0,
            is_final: false,
        };
        let bytes = aad.to_bytes();
        assert_eq!(bytes[16], 0);
    }
}
