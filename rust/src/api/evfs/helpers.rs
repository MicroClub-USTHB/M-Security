use crate::core::error::CryptoError;
use crate::core::evfs::format::{self, SegmentIndex, PRIMARY_INDEX_OFFSET, VAULT_HEADER_SIZE};
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
    index_pad_size: usize,
) -> Result<(), CryptoError> {
    let plaintext = index.to_bytes(index_pad_size)?;
    let encrypted =
        segment::aead_encrypt_random_nonce(keys.index_key.as_bytes(), &plaintext, &[], algorithm)?;

    // Primary
    file.seek(SeekFrom::Start(PRIMARY_INDEX_OFFSET))?;
    file.write_all(&encrypted)?;

    // Shadow
    let shadow_off = format::shadow_index_offset(capacity, index_pad_size)?;
    file.seek(SeekFrom::Start(shadow_off))?;
    file.write_all(&encrypted)?;

    file.sync_all()?;
    Ok(())
}

/// Read raw encrypted index bytes from a given file offset.
///
/// `enc_index_size` is derived from the header's `index_size` field, which
/// is validated to be within `MIN..MAX_INDEX_PAD_SIZE` by `VaultHeader::from_bytes`.
pub(crate) fn read_encrypted_index(
    file: &mut File,
    offset: u64,
    enc_index_size: usize,
) -> Result<Vec<u8>, CryptoError> {
    // Defense-in-depth: reject unreasonable sizes even if header validation was bypassed
    let max = format::encrypted_index_size(format::MAX_INDEX_PAD_SIZE);
    if enc_index_size > max {
        return Err(CryptoError::VaultCorrupted(format!(
            "encrypted index size {enc_index_size} exceeds maximum {max}"
        )));
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; enc_index_size];
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
pub(crate) fn capacity_from_file_size(
    file_size: u64,
    index_pad_size: usize,
) -> Result<u64, CryptoError> {
    let enc_size = format::encrypted_index_size(index_pad_size) as u64;
    let overhead = VAULT_HEADER_SIZE as u64 + 2 * enc_size;
    file_size
        .checked_sub(overhead)
        .ok_or_else(|| CryptoError::VaultCorrupted("vault file too small".into()))
}
