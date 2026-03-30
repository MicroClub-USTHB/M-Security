use crate::core::error::CryptoError;
use crate::core::evfs::format::{self, SegmentIndex, PRIMARY_INDEX_OFFSET, VAULT_HEADER_SIZE};
use crate::core::evfs::segment::{self, VaultKeys};
use crate::core::format::Algorithm;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

#[cfg(feature = "compression")]
use crate::api::compression::CompressionAlgorithm;
#[cfg(feature = "compression")]
use subtle::ConstantTimeEq;

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

/// Decrypt all chunks of a streaming segment, calling `on_chunk(plaintext, chunk_index)`
/// for each decrypted chunk. Returns the BLAKE3 checksum of the full decrypted data.
///
/// When `mmap` is `Some`, chunks are read via zero-copy slices into the mapped
/// file. Falls back to heap-allocated `read_exact` when mmap is unavailable.
#[allow(clippy::too_many_arguments)]
#[cfg(feature = "compression")]
pub(crate) fn decrypt_streaming_chunks(
    file: &mut File,
    mmap: Option<&super::types::VaultMmap>,
    cipher_key: &[u8],
    nonce_key: &[u8],
    algorithm: Algorithm,
    index_pad_size: usize,
    seg_offset: u64,
    generation: u64,
    compression: CompressionAlgorithm,
    chunk_count: u32,
    mut on_chunk: impl FnMut(Vec<u8>, u32) -> Result<(), CryptoError>,
) -> Result<[u8; 32], CryptoError> {
    let data_region = format::data_region_offset(index_pad_size);
    let enc_chunk_size = crate::core::streaming::ENCRYPTED_CHUNK_SIZE;
    let mut hasher = blake3::Hasher::new();
    let mut decompressor = if compression != CompressionAlgorithm::None {
        Some(crate::core::compression::streaming::new_decompressor(
            compression,
        )?)
    } else {
        None
    };
    let mut decomp_buf = Vec::with_capacity(crate::core::streaming::CHUNK_SIZE * 2);

    for i in 0..chunk_count {
        let chunk_offset = (i as u64)
            .checked_mul(enc_chunk_size as u64)
            .and_then(|co| data_region.checked_add(seg_offset)?.checked_add(co))
            .ok_or_else(|| CryptoError::InvalidParameter("chunk offset overflow".into()))?;

        // Zero-copy path: slice directly into mmap; fallback: heap read
        let heap_buf;
        let encrypted_ref: &[u8] = if let Some(m) = mmap {
            m.slice(chunk_offset, enc_chunk_size as u64)?
        } else {
            file.seek(SeekFrom::Start(chunk_offset))?;
            heap_buf = {
                let mut buf = vec![0u8; enc_chunk_size];
                file.read_exact(&mut buf)?;
                buf
            };
            &heap_buf
        };

        let expected_nonce = segment::derive_chunk_nonce(nonce_key, i as u64, generation)?;
        let (stored_nonce, _) = encrypted_ref.split_at(crate::core::streaming::NONCE_SIZE);
        if stored_nonce.ct_ne(&expected_nonce).into() {
            return Err(CryptoError::AuthenticationFailed);
        }

        let is_final = i == chunk_count - 1;
        let aad = segment::VaultChunkAad {
            generation,
            chunk_index: i as u64,
            is_final,
        }
        .to_bytes();

        let decrypted =
            segment::aead_decrypt_with_stored_nonce(cipher_key, encrypted_ref, &aad, algorithm)?;

        let plaintext = if is_final {
            crate::core::streaming::strip_last_chunk_padding(&decrypted)?
        } else {
            decrypted
        };

        let final_data = if let Some(ref mut dec) = decompressor {
            dec.decompress_chunk(&plaintext, &mut decomp_buf)?;
            if is_final {
                dec.finish(&mut decomp_buf)?;
            }
            let data = decomp_buf.clone();
            decomp_buf.clear();
            data
        } else {
            plaintext
        };

        hasher.update(&final_data);
        on_chunk(final_data, i)?;
    }

    Ok(hasher.finalize().into())
}

/// Decrypt a raw encrypted monolithic segment blob (`nonce || ciphertext || tag`)
/// without going through a `VaultHandle` read path.
///
/// # Errors
///
/// - [`CryptoError::AuthenticationFailed`] — nonce mismatch or AEAD tag failure.
/// - [`CryptoError::VaultCorrupted`] — BLAKE3 checksum mismatch after decryption.
/// - Any lower-level [`CryptoError`] propagated from decompression or AEAD.
#[cfg(feature = "compression")]
pub(crate) fn decrypt_segment_raw(
    encrypted: &[u8],
    cipher_key: &[u8],
    nonce_key: &[u8],
    algorithm: Algorithm,
    generation: u64,
    compression: CompressionAlgorithm,
    expected_checksum: &[u8; 32],
) -> Result<Vec<u8>, CryptoError> {
    let params = segment::SegmentCryptoParams {
        cipher_key,
        nonce_key,
        algorithm,
        segment_index: 0, // monolithic segments always use index 0 for nonce derivation
        generation,
    };

    let plaintext = segment::decrypt_segment(&params, encrypted, compression)?;

    if !segment::verify_checksum(&plaintext, expected_checksum) {
        return Err(CryptoError::VaultCorrupted(
            "decrypt_segment_raw: BLAKE3 integrity check failed".into(),
        ));
    }

    Ok(plaintext)
}
