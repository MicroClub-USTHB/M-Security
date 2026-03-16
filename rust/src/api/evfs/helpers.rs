use crate::core::error::CryptoError;
use crate::core::evfs::format::{
    self, SegmentIndex, ENCRYPTED_INDEX_SIZE, PRIMARY_INDEX_OFFSET, VAULT_HEADER_SIZE,
};
use crate::core::evfs::segment::{self, VaultKeys};
use crate::core::format::Algorithm;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

pub(crate) fn parse_algorithm(s: &str) -> Result<Algorithm, CryptoError> {
    match s {
        "aes-256-gcm" => Ok(Algorithm::AesGcm),
        "chacha20-poly1305" => Ok(Algorithm::ChaCha20Poly1305),
        _ => Err(CryptoError::InvalidParameter(format!(
            "unsupported algorithm: '{s}' (expected 'aes-256-gcm' or 'chacha20-poly1305')"
        ))),
    }
}

/// Encrypt the in-memory index and write to both primary and shadow locations.
pub(crate) fn flush_index(
    file: &mut File,
    index: &SegmentIndex,
    keys: &VaultKeys,
    algorithm: Algorithm,
    capacity: u64,
) -> Result<(), CryptoError> {
    let plaintext = index.to_bytes()?;
    let encrypted =
        segment::aead_encrypt_random_nonce(keys.index_key.as_bytes(), &plaintext, &[], algorithm)?;

    // Primary
    file.seek(SeekFrom::Start(PRIMARY_INDEX_OFFSET))?;
    file.write_all(&encrypted)?;

    // Shadow
    let shadow_off = format::shadow_index_offset(capacity)?;
    file.seek(SeekFrom::Start(shadow_off))?;
    file.write_all(&encrypted)?;

    file.sync_all()?;
    Ok(())
}

/// Read raw encrypted index bytes from a given file offset.
pub(crate) fn read_encrypted_index(file: &mut File, offset: u64) -> Result<Vec<u8>, CryptoError> {
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; ENCRYPTED_INDEX_SIZE];
    file.read_exact(&mut buf)?;
    Ok(buf)
}

/// Decrypt an encrypted index blob into a SegmentIndex.
pub(crate) fn decrypt_index_blob(
    encrypted: &[u8],
    keys: &VaultKeys,
    algorithm: Algorithm,
) -> Result<SegmentIndex, CryptoError> {
    let plaintext = segment::aead_decrypt_with_stored_nonce(
        keys.index_key.as_bytes(),
        encrypted,
        &[],
        algorithm,
    )?;
    SegmentIndex::from_bytes(&plaintext)
}

/// Compute vault data capacity from file size.
pub(crate) fn capacity_from_file_size(file_size: u64) -> Result<u64, CryptoError> {
    let overhead = VAULT_HEADER_SIZE as u64 + 2 * ENCRYPTED_INDEX_SIZE as u64;
    file_size
        .checked_sub(overhead)
        .ok_or_else(|| CryptoError::VaultCorrupted("vault file too small".into()))
}
