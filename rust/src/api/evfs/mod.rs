//! Encrypted Virtual File System — .vault container format and operations.

mod helpers;
#[cfg(all(test, feature = "compression"))]
mod tests;
pub mod types;

use helpers::*;
pub use types::*;
use types::VaultMmap;

use crate::api::compression::{CompressionAlgorithm, CompressionConfig};
use crate::core::error::CryptoError;
use crate::core::evfs::format::{
    self, SegmentEntry, SegmentIndex, VaultHeader, PRIMARY_INDEX_OFFSET, VAULT_HEADER_SIZE,
};
use crate::core::evfs::segment::{self, SegmentCryptoParams};
use crate::core::evfs::wal::{VaultLock, WalOp, WriteAheadLog};
use crate::core::format::Algorithm;
use crate::frb_generated::StreamSink;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Create a new vault file at `path` with the given capacity.
///
/// The algorithm string must be "aes-256-gcm" or "chacha20-poly1305".
#[cfg(feature = "compression")]
pub fn vault_create(
    path: String,
    mut key: Vec<u8>,
    algorithm: String,
    capacity_bytes: u64,
) -> Result<VaultHandle, CryptoError> {
    let algo = parse_algorithm(&algorithm)?;
    let lock = VaultLock::acquire(&path)?;
    let keys = segment::derive_vault_keys(&key)?;
    key.zeroize();
    let index_pad_size = format::compute_index_size(capacity_bytes);
    let total_size = format::total_vault_size(capacity_bytes, index_pad_size)?;

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| CryptoError::IoError(format!("cannot create vault: {e}")))?;

    // Pre-allocate with CSPRNG random fill
    segment::preallocate_vault(&mut file, total_size)?;

    // Write header (includes index_size for open to read back)
    let header = VaultHeader::new(algo.to_byte(), index_pad_size as u32);
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&header.to_bytes())?;

    // Create empty index and flush to primary + shadow
    let index = SegmentIndex::new(capacity_bytes);
    flush_index(
        &mut file,
        &index,
        &keys,
        algo,
        capacity_bytes,
        index_pad_size,
    )?;

    // Create fresh WAL (checkpoint to clear any stale data)
    let mut wal = WriteAheadLog::open(&path)?;
    wal.checkpoint()?;

    let mmap = VaultMmap::new(&file).ok();
    Ok(VaultHandle {
        path,
        algorithm: algo,
        keys,
        index,
        index_pad_size,
        file,
        mmap,
        wal,
        lock,
    })
}

/// Open an existing vault, running WAL recovery if needed.
#[cfg(feature = "compression")]
pub fn vault_open(path: String, mut key: Vec<u8>) -> Result<VaultHandle, CryptoError> {
    let lock = VaultLock::acquire(&path)?;

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|e| CryptoError::IoError(format!("cannot open vault: {e}")))?;

    // Read header — includes index_size since dynamic index sizing
    let mut header_buf = [0u8; VAULT_HEADER_SIZE];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut header_buf)?;
    let header = VaultHeader::from_bytes(&header_buf)?;
    let algorithm = Algorithm::from_byte(header.algorithm)?;
    let index_pad_size = header.index_size as usize;
    let enc_idx_size = format::encrypted_index_size(index_pad_size);
    let data_off = format::data_region_offset(index_pad_size);

    // Derive keys
    let keys = segment::derive_vault_keys(&key)?;
    key.zeroize();

    // Compute capacity from file size
    let file_size = file.seek(SeekFrom::End(0))?;
    let capacity = capacity_from_file_size(file_size, index_pad_size)?;

    // Defrag backup recovery: if a crash occurred during an overlapping defrag
    // move, restore the segment data from the backup file before WAL recovery.
    // Must happen first because WAL restores the index pointing to the old
    // offset, and the backup restores the data at that offset.
    let defrag_backup_path = format!("{path}.defrag");
    let mut wal = WriteAheadLog::open(&path)?;
    let wal_snapshot = wal.recover()?;
    if std::path::Path::new(&defrag_backup_path).exists() {
        if wal_snapshot.is_some() {
            // WAL uncommitted + backup exists → crash during overlapping defrag
            // move. Restore segment data to the old position. Errors here are
            // fatal: if the backup can't be read the segment data at the old
            // offset is corrupted and the vault would silently serve bad data.
            let mut backup = File::open(&defrag_backup_path)
                .map_err(|e| CryptoError::IoError(format!("defrag backup open: {e}")))?;
            let mut hdr = [0u8; 16];
            backup
                .read_exact(&mut hdr)
                .map_err(|e| CryptoError::VaultCorrupted(format!("defrag backup header: {e}")))?;
            let offset = u64::from_le_bytes([
                hdr[0], hdr[1], hdr[2], hdr[3], hdr[4], hdr[5], hdr[6], hdr[7],
            ]);
            let size = u64::from_le_bytes([
                hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13], hdr[14], hdr[15],
            ]);
            const MAX_BACKUP_SIZE: u64 = 256 * 1024 * 1024;
            if size == 0 || size > capacity || size > MAX_BACKUP_SIZE {
                return Err(CryptoError::VaultCorrupted(format!(
                    "defrag backup has invalid size {size} (capacity {capacity})"
                )));
            }
            let mut data = vec![0u8; size as usize];
            backup
                .read_exact(&mut data)
                .map_err(|e| CryptoError::VaultCorrupted(format!("defrag backup data: {e}")))?;
            file.seek(SeekFrom::Start(data_off + offset))?;
            file.write_all(&data)?;
            file.sync_all()?;
        }
        let _ = std::fs::remove_file(&defrag_backup_path);
    }

    // WAL recovery — only restore primary index. Shadow position depends on
    // capacity which may have changed during an interrupted resize; the
    // post-recovery reconciliation below fixes the shadow.
    let wal_recovered = if let Some(old_encrypted_index) = wal_snapshot {
        if old_encrypted_index.len() != enc_idx_size {
            return Err(CryptoError::VaultCorrupted(format!(
                "WAL snapshot size {} != expected {enc_idx_size}",
                old_encrypted_index.len()
            )));
        }
        file.seek(SeekFrom::Start(PRIMARY_INDEX_OFFSET))?;
        file.write_all(&old_encrypted_index)?;
        file.sync_all()?;
        true
    } else {
        false
    };
    wal.checkpoint()?;

    // Decrypt index (try primary, fall back to shadow)
    let mut index = {
        let primary_bytes = read_encrypted_index(&mut file, PRIMARY_INDEX_OFFSET, enc_idx_size)?;
        match decrypt_index_blob(&primary_bytes, &keys, algorithm) {
            Ok(idx) => idx,
            Err(_) => {
                let shadow_off = format::shadow_index_offset(capacity, index_pad_size)?;
                let shadow_bytes = read_encrypted_index(&mut file, shadow_off, enc_idx_size)?;
                let idx = decrypt_index_blob(&shadow_bytes, &keys, algorithm).map_err(|_| {
                    CryptoError::VaultCorrupted(
                        "both primary and shadow index are corrupted".into(),
                    )
                })?;
                // Restore primary from shadow
                file.seek(SeekFrom::Start(PRIMARY_INDEX_OFFSET))?;
                file.write_all(&shadow_bytes)?;
                file.sync_all()?;
                idx
            }
        }
    };

    // After WAL recovery, bump the generation counter to prevent nonce
    // reuse. The crashed write consumed generation N but the restored index
    // still has next_generation=N. Without this bump the next write would
    // derive the same nonce with potentially different plaintext.
    if wal_recovered {
        index.next_generation = index.next_generation.saturating_add(1);
        flush_index(
            &mut file,
            &index,
            &keys,
            algorithm,
            index.capacity,
            index_pad_size,
        )?;
    }

    // Post-recovery reconciliation: if an interrupted resize left the file
    // at the wrong size, fix the file and shadow to match the index.
    let expected_total = format::total_vault_size(index.capacity, index_pad_size)?;
    let actual_size = file.seek(SeekFrom::End(0))?;
    if actual_size != expected_total {
        file.set_len(expected_total)?;
        let primary_bytes = read_encrypted_index(&mut file, PRIMARY_INDEX_OFFSET, enc_idx_size)?;
        let shadow_off = format::shadow_index_offset(index.capacity, index_pad_size)?;
        file.seek(SeekFrom::Start(shadow_off))?;
        file.write_all(&primary_bytes)?;
        file.sync_all()?;
    }

    let mmap = VaultMmap::new(&file).ok();
    Ok(VaultHandle {
        path,
        algorithm,
        keys,
        index,
        index_pad_size,
        file,
        mmap,
        wal,
        lock,
    })
}

/// Write (or overwrite) a named segment.
///
/// Compression is transparent: pass a `CompressionConfig` to compress before
/// encryption. MIME-aware skip applies when the segment name has an
/// already-compressed extension.
#[cfg(feature = "compression")]
pub fn vault_write(
    handle: &mut VaultHandle,
    name: String,
    mut data: Vec<u8>,
    compression: Option<CompressionConfig>,
) -> Result<(), CryptoError> {
    let config = compression.unwrap_or(CompressionConfig {
        algorithm: CompressionAlgorithm::None,
        level: None,
    });

    // 1. Checksum on original plaintext (pre-compression)
    let checksum = segment::compute_checksum(&data);

    // 2. Compress-then-encrypt
    let gen = handle.index.next_gen();
    let params = SegmentCryptoParams {
        cipher_key: handle.keys.cipher_key.as_bytes(),
        nonce_key: handle.keys.nonce_key.as_bytes(),
        algorithm: handle.algorithm,
        segment_index: 0,
        generation: gen,
    };
    let (encrypted, effective_algo) = segment::encrypt_segment(&params, &data, &name, &config)?;
    data.zeroize();

    // 3. WAL journal old index
    let old_encrypted_index = read_encrypted_index(
        &mut handle.file,
        PRIMARY_INDEX_OFFSET,
        format::encrypted_index_size(handle.index_pad_size),
    )?;
    handle
        .wal
        .begin(WalOp::WriteSegment, &old_encrypted_index)?;

    // 4. If overwrite: secure-erase old region, deallocate
    if let Some(old_entry) = handle.index.remove(&name) {
        segment::secure_erase_region(
            &mut handle.file,
            format::data_region_offset(handle.index_pad_size) + old_entry.offset,
            old_entry.size,
        )?;
        handle.index.deallocate(old_entry.offset, old_entry.size);
    }

    // 5. Allocate space (free list first, then append)
    let offset = handle.index.allocate(encrypted.len() as u64)?;

    // 6. Write encrypted segment at allocated offset + fsync before index update
    handle.file.seek(SeekFrom::Start(
        format::data_region_offset(handle.index_pad_size) + offset,
    ))?;
    handle.file.write_all(&encrypted)?;
    handle.file.sync_all()?;

    // 7. Update index
    let entry = SegmentEntry::new(
        &name,
        offset,
        encrypted.len() as u64,
        gen,
        checksum,
        effective_algo,
        0, // monolithic (one-shot) segment
    )?;
    handle.index.add(entry)?;

    // 8. Flush index (primary + shadow)
    flush_index(
        &mut handle.file,
        &handle.index,
        &handle.keys,
        handle.algorithm,
        handle.index.capacity,
        handle.index_pad_size,
    )?;

    // 9. WAL commit + refresh mmap (file contents changed)
    handle.wal.commit()?;
    handle.refresh_mmap();

    Ok(())
}

/// Read a named segment. Handles both monolithic and streaming segments.
/// Decompression is automatic for monolithic segments.
#[cfg(feature = "compression")]
pub fn vault_read(handle: &mut VaultHandle, name: String) -> Result<Vec<u8>, CryptoError> {
    let entry = handle
        .index
        .find(&name)
        .ok_or_else(|| CryptoError::SegmentNotFound(name.clone()))?;

    let seg_offset = entry.offset;
    let seg_size = entry.size;
    let seg_gen = entry.generation;
    let seg_compression = entry.compression;
    let seg_checksum = entry.checksum;
    let chunk_count = entry.chunk_count;

    // INTEROP: If the segment is chunked, reassemble it into a single vector
    if chunk_count > 0 {
        let mut full_plaintext = Vec::new();
        let checksum = decrypt_streaming_chunks(
            &mut handle.file,
            handle.mmap.as_ref(),
            handle.keys.cipher_key.as_bytes(),
            handle.keys.nonce_key.as_bytes(),
            handle.algorithm,
            handle.index_pad_size,
            seg_offset,
            seg_gen,
            seg_compression,
            chunk_count,
            |data, _| {
                full_plaintext.extend_from_slice(&data);
                Ok(())
            },
        )?;

        if checksum.ct_ne(&seg_checksum).into() {
            return Err(CryptoError::VaultCorrupted(format!(
                "integrity check failed for segment '{name}'"
            )));
        }

        return Ok(full_plaintext);
    }

    // Monolithic read (chunk_count == 0): prefer mmap zero-copy, fall back to heap
    let abs_offset = format::data_region_offset(handle.index_pad_size) + seg_offset;
    let params = SegmentCryptoParams {
        cipher_key: handle.keys.cipher_key.as_bytes(),
        nonce_key: handle.keys.nonce_key.as_bytes(),
        algorithm: handle.algorithm,
        segment_index: 0,
        generation: seg_gen,
    };

    let plaintext = if let Some(ref mmap) = handle.mmap {
        let encrypted = mmap.slice(abs_offset, seg_size)?;
        segment::decrypt_segment(&params, encrypted, seg_compression)?
    } else {
        // Fallback: heap-allocated read_exact (32-bit or mmap-failed)
        let read_len = usize::try_from(seg_size).map_err(|_| {
            CryptoError::VaultCorrupted(format!(
                "segment size {seg_size} exceeds platform address space"
            ))
        })?;
        handle.file.seek(SeekFrom::Start(abs_offset))?;
        let mut buf = vec![0u8; read_len];
        handle.file.read_exact(&mut buf)?;
        segment::decrypt_segment(&params, &buf, seg_compression)?
    };

    // Verify checksum on decompressed plaintext
    if !segment::verify_checksum(&plaintext, &seg_checksum) {
        return Err(CryptoError::VaultCorrupted(format!(
            "integrity check failed for segment '{name}'"
        )));
    }

    Ok(plaintext)
}

/// Read a named segment sequentially through a stream. Decompression is automatic.
#[cfg(feature = "compression")]
pub fn vault_read_stream(
    handle: &mut VaultHandle,
    name: String,
    verify_checksum: bool,
    sink: StreamSink<Vec<u8>>,
    on_progress: StreamSink<f64>,
) -> Result<(), CryptoError> {
    let entry = handle
        .index
        .find(&name)
        .ok_or_else(|| CryptoError::SegmentNotFound(name.clone()))?;

    let seg_offset = entry.offset;
    let seg_gen = entry.generation;
    let seg_compression = entry.compression;
    let seg_checksum = entry.checksum;
    let chunk_count = entry.chunk_count;

    // INTEROP: If chunk_count is 0, this is a monolithic segment. Handle with a one-shot read.
    if chunk_count == 0 {
        let plaintext = vault_read(handle, name)?;
        let _ = sink.add(plaintext);
        let _ = on_progress.add(1.0);
        return Ok(());
    }

    let checksum = decrypt_streaming_chunks(
        &mut handle.file,
        handle.mmap.as_ref(),
        handle.keys.cipher_key.as_bytes(),
        handle.keys.nonce_key.as_bytes(),
        handle.algorithm,
        handle.index_pad_size,
        seg_offset,
        seg_gen,
        seg_compression,
        chunk_count,
        |data, i| {
            let _ = sink.add(data);
            let _ = on_progress.add(((i + 1) as f64) / (chunk_count as f64));
            Ok(())
        },
    )?;

    if verify_checksum && checksum.ct_ne(&seg_checksum).into() {
        return Err(CryptoError::VaultCorrupted(format!(
            "integrity check failed for segment '{name}'"
        )));
    }

    Ok(())
}

/// Write (or overwrite) a named segment using streaming chunked encryption.
#[cfg(feature = "compression")]
pub fn vault_write_stream(
    handle: &mut VaultHandle,
    name: String,
    total_plaintext_size: u64,
    data_stream: impl Iterator<Item = Vec<u8>>,
) -> Result<(), CryptoError> {
    use crate::core::streaming::{pad_last_chunk, CHUNK_SIZE};

    let expected_chunks = format::streaming_chunk_count(total_plaintext_size)?;
    let total_encrypted_size = format::streaming_segment_size(total_plaintext_size)?;

    let gen = handle.index.next_gen();

    let old_encrypted_index = read_encrypted_index(
        &mut handle.file,
        PRIMARY_INDEX_OFFSET,
        format::encrypted_index_size(handle.index_pad_size),
    )?;
    handle
        .wal
        .begin(WalOp::WriteSegment, &old_encrypted_index)?;

    if let Some(old_entry) = handle.index.remove(&name) {
        segment::secure_erase_region(
            &mut handle.file,
            format::data_region_offset(handle.index_pad_size) + old_entry.offset,
            old_entry.size,
        )?;
        handle.index.deallocate(old_entry.offset, old_entry.size);
    }

    let offset = handle.index.allocate(total_encrypted_size)?;
    let data_off = format::data_region_offset(handle.index_pad_size);

    let mut hasher = blake3::Hasher::new();
    let mut chunk_buf = vec![0u8; CHUNK_SIZE];
    let mut buf_len = 0usize;
    let mut total_received: u64 = 0;
    let mut chunk_index: u64 = 0;
    let nonce_key = handle.keys.nonce_key.as_bytes();
    let cipher_key = handle.keys.cipher_key.as_bytes();
    let algorithm = handle.algorithm;

    for mut input in data_stream {
        hasher.update(&input);
        total_received = total_received
            .checked_add(input.len() as u64)
            .ok_or_else(|| CryptoError::InvalidParameter("stream size overflow".into()))?;

        if total_received > total_plaintext_size {
            input.zeroize();
            chunk_buf.zeroize();
            return Err(CryptoError::InvalidParameter(format!(
                "stream exceeded total_plaintext_size: received >{total_received}, \
                 expected {total_plaintext_size}"
            )));
        }

        let mut pos = 0;
        while pos < input.len() {
            let take = std::cmp::min(CHUNK_SIZE - buf_len, input.len() - pos);
            chunk_buf[buf_len..buf_len + take].copy_from_slice(&input[pos..pos + take]);
            buf_len += take;
            pos += take;

            if buf_len == CHUNK_SIZE {
                let abs_off = chunk_abs_offset(data_off, offset, chunk_index)?;
                write_encrypted_chunk(
                    &mut handle.file,
                    cipher_key,
                    nonce_key,
                    algorithm,
                    &chunk_buf[..CHUNK_SIZE],
                    chunk_index,
                    gen,
                    false,
                    abs_off,
                )?;
                chunk_index += 1;
                buf_len = 0;
            }
        }
        input.zeroize();
    }

    if total_received != total_plaintext_size {
        chunk_buf.zeroize();
        return Err(CryptoError::InvalidParameter(format!(
            "stream underflow: received {total_received} bytes, \
             expected {total_plaintext_size}"
        )));
    }

    let mut padded = pad_last_chunk(&chunk_buf[..buf_len])?;
    chunk_buf.zeroize();
    let final_off = chunk_abs_offset(data_off, offset, chunk_index)?;
    let final_result = write_encrypted_chunk(
        &mut handle.file,
        cipher_key,
        nonce_key,
        algorithm,
        &padded,
        chunk_index,
        gen,
        true,
        final_off,
    );
    padded.zeroize();
    final_result?;

    // Single durability barrier after all chunks — WAL provides atomicity
    handle.file.sync_all()?;

    let actual_chunks = chunk_index + 1;
    if actual_chunks != expected_chunks as u64 {
        return Err(CryptoError::VaultCorrupted(format!(
            "chunk count mismatch: wrote {actual_chunks}, expected {expected_chunks}"
        )));
    }

    let checksum: [u8; 32] = hasher.finalize().into();

    let entry = SegmentEntry::new(
        &name,
        offset,
        total_encrypted_size,
        gen,
        checksum,
        CompressionAlgorithm::None,
        expected_chunks,
    )?;
    handle.index.add(entry)?;

    flush_index(
        &mut handle.file,
        &handle.index,
        &handle.keys,
        handle.algorithm,
        handle.index.capacity,
        handle.index_pad_size,
    )?;

    handle.wal.commit()?;
    handle.wal.checkpoint()?;
    handle.refresh_mmap();

    Ok(())
}

/// Write a file into the vault as a streaming segment.
///
/// Reads `file_path` in 64KB chunks and encrypts each independently.
/// This is the FRB-callable wrapper around `vault_write_stream`.
#[cfg(feature = "compression")]
pub fn vault_write_file(
    handle: &mut VaultHandle,
    name: String,
    file_path: String,
    on_progress: StreamSink<f64>,
) -> Result<(), CryptoError> {
    use crate::core::streaming::CHUNK_SIZE;

    let mut file = File::open(&file_path)
        .map_err(|e| CryptoError::IoError(format!("cannot open '{file_path}': {e}")))?;

    let file_size = file.seek(SeekFrom::End(0))?;
    file.seek(SeekFrom::Start(0))?;

    let mut bytes_read: u64 = 0;
    let mut read_error: Option<std::io::Error> = None;
    let data_stream = std::iter::from_fn(|| {
        if read_error.is_some() {
            return None;
        }
        let mut buf = vec![0u8; CHUNK_SIZE];
        match file.read(&mut buf) {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                bytes_read += n as u64;
                if file_size > 0 {
                    let _ = on_progress.add(bytes_read as f64 / file_size as f64);
                }
                Some(buf)
            }
            Err(e) => {
                read_error = Some(e);
                None
            }
        }
    });

    let result = vault_write_stream(handle, name, file_size, data_stream);

    // Surface the real I/O error instead of a misleading "stream underflow"
    if let Some(io_err) = read_error {
        return Err(CryptoError::IoError(format!(
            "read error on '{file_path}': {io_err}"
        )));
    }
    result?;

    let _ = on_progress.add(1.0);
    Ok(())
}

fn chunk_abs_offset(data_off: u64, seg_offset: u64, chunk_index: u64) -> Result<u64, CryptoError> {
    use crate::core::streaming::ENCRYPTED_CHUNK_SIZE;
    chunk_index
        .checked_mul(ENCRYPTED_CHUNK_SIZE as u64)
        .and_then(|co| data_off.checked_add(seg_offset)?.checked_add(co))
        .ok_or_else(|| CryptoError::InvalidParameter("chunk offset overflow".into()))
}

#[allow(clippy::too_many_arguments)]
fn write_encrypted_chunk(
    file: &mut File,
    cipher_key: &[u8],
    nonce_key: &[u8],
    algorithm: crate::core::format::Algorithm,
    plaintext: &[u8],
    chunk_index: u64,
    generation: u64,
    is_final: bool,
    abs_offset: u64,
) -> Result<(), CryptoError> {
    use crate::core::streaming::{CHUNK_SIZE, NONCE_SIZE};

    if plaintext.len() != CHUNK_SIZE {
        return Err(CryptoError::InvalidParameter(format!(
            "chunk plaintext must be {CHUNK_SIZE} bytes, got {}",
            plaintext.len()
        )));
    }

    let nonce = segment::derive_chunk_nonce(nonce_key, chunk_index, generation)?;
    let aad = segment::VaultChunkAad {
        generation,
        chunk_index,
        is_final,
    }
    .to_bytes();

    let ct_tag = segment::aead_encrypt_with_key(cipher_key, &nonce, plaintext, &aad, algorithm)?;

    let mut wire = Vec::with_capacity(NONCE_SIZE + ct_tag.len());
    wire.extend_from_slice(&nonce);
    wire.extend_from_slice(&ct_tag);

    file.seek(SeekFrom::Start(abs_offset))?;
    file.write_all(&wire)?;

    Ok(())
}

/// Delete a named segment. The region is secure-erased and returned to the
/// free list for reuse by future writes.
#[cfg(feature = "compression")]
pub fn vault_delete(handle: &mut VaultHandle, name: String) -> Result<(), CryptoError> {
    // WAL journal old index
    let old_encrypted_index = read_encrypted_index(
        &mut handle.file,
        PRIMARY_INDEX_OFFSET,
        format::encrypted_index_size(handle.index_pad_size),
    )?;
    handle
        .wal
        .begin(WalOp::DeleteSegment, &old_encrypted_index)?;

    let entry = handle
        .index
        .remove(&name)
        .ok_or_else(|| CryptoError::SegmentNotFound(name.clone()))?;

    // Secure erase (CSPRNG overwrite + fsync)
    segment::secure_erase_region(
        &mut handle.file,
        format::data_region_offset(handle.index_pad_size) + entry.offset,
        entry.size,
    )?;

    // Return space to free list
    handle.index.deallocate(entry.offset, entry.size);

    // Flush index (primary + shadow)
    flush_index(
        &mut handle.file,
        &handle.index,
        &handle.keys,
        handle.algorithm,
        handle.index.capacity,
        handle.index_pad_size,
    )?;

    // WAL commit + refresh mmap (file contents changed)
    handle.wal.commit()?;
    handle.refresh_mmap();

    Ok(())
}

/// Resize vault data region capacity.
///
/// - Grow: extend file, CSPRNG-fill new space, relocate shadow index + WAL
/// - Shrink: validate segments fit, relocate shadow + WAL, truncate file
/// - Returns VaultFull if shrink would lose data
#[cfg(feature = "compression")]
pub fn vault_resize(handle: &mut VaultHandle, new_capacity: u64) -> Result<(), CryptoError> {
    let old_capacity = handle.index.capacity;
    if old_capacity == new_capacity {
        Ok(())
    } else if old_capacity > new_capacity {
        vault_resize_shrink_impl(handle, old_capacity, new_capacity)
    } else {
        vault_resize_grow_impl(handle, old_capacity, new_capacity)
    }
}

#[cfg(feature = "compression")]
fn vault_resize_grow_impl(
    handle: &mut VaultHandle,
    old_capacity: u64,
    new_capacity: u64,
) -> Result<(), CryptoError> {
    let old_encrypted_index = read_encrypted_index(
        &mut handle.file,
        PRIMARY_INDEX_OFFSET,
        format::encrypted_index_size(handle.index_pad_size),
    )?;
    handle.wal.begin(WalOp::UpdateIndex, &old_encrypted_index)?;

    // Extend file and CSPRNG-fill new space (also overwrites old shadow position)
    let new_total = format::total_vault_size(new_capacity, handle.index_pad_size)?;
    handle.file.set_len(new_total)?;
    let fill_offset = format::data_region_offset(handle.index_pad_size) + old_capacity;
    let fill_size = new_capacity - old_capacity;
    segment::secure_erase_region(&mut handle.file, fill_offset, fill_size)?;

    // Update capacity and flush index to primary + shadow at new position
    handle.index.capacity = new_capacity;
    flush_index(
        &mut handle.file,
        &handle.index,
        &handle.keys,
        handle.algorithm,
        new_capacity,
        handle.index_pad_size,
    )?;

    handle.wal.commit()?;
    handle.wal.checkpoint()?;
    handle.refresh_mmap();

    Ok(())
}

#[cfg(feature = "compression")]
fn vault_resize_shrink_impl(
    handle: &mut VaultHandle,
    _old_capacity: u64,
    new_capacity: u64,
) -> Result<(), CryptoError> {
    // Validate: every live segment must fit within the new capacity.
    let max_used = handle
        .index
        .entries
        .iter()
        .map(|e| e.offset.saturating_add(e.size))
        .max()
        .unwrap_or(0);
    if max_used > new_capacity {
        return Err(CryptoError::VaultFull {
            needed: max_used,
            available: new_capacity,
        });
    }

    // WAL begin — journal the current encrypted index for crash recovery.
    let old_encrypted_index = read_encrypted_index(
        &mut handle.file,
        PRIMARY_INDEX_OFFSET,
        format::encrypted_index_size(handle.index_pad_size),
    )?;
    handle.wal.begin(WalOp::UpdateIndex, &old_encrypted_index)?;

    // Update index metadata for the new capacity.
    handle.index.capacity = new_capacity;
    if handle.index.next_free_offset > new_capacity {
        handle.index.next_free_offset = new_capacity;
    }

    // Remove free regions beyond new boundary; truncate partial overlaps.
    handle.index.free_regions.retain_mut(|r| {
        if r.offset >= new_capacity {
            return false;
        }
        let end = r.offset.saturating_add(r.size);
        if end > new_capacity {
            r.size = new_capacity - r.offset;
        }
        true
    });

    // Flush index to primary + shadow at new position.
    flush_index(
        &mut handle.file,
        &handle.index,
        &handle.keys,
        handle.algorithm,
        new_capacity,
        handle.index_pad_size,
    )?;

    // Truncate file to new total size.
    let new_total = format::total_vault_size(new_capacity, handle.index_pad_size)?;
    handle.file.set_len(new_total)?;
    handle.file.sync_all()?;

    handle.wal.commit()?;
    handle.wal.checkpoint()?;
    handle.refresh_mmap();

    Ok(())
}

/// List all segment names in the vault.
pub fn vault_list(handle: &VaultHandle) -> Vec<String> {
    handle
        .index
        .entries
        .iter()
        .map(|e| e.name.clone())
        .collect()
}

/// Get vault capacity info.
pub fn vault_capacity(handle: &VaultHandle) -> VaultCapacityInfo {
    let h = handle.health();
    VaultCapacityInfo {
        total_bytes: h.total_bytes,
        used_bytes: h.used_bytes,
        free_list_bytes: h.free_list_bytes,
        unallocated_bytes: h.unallocated_bytes,
        segment_count: h.segment_count as usize,
    }
}

/// Get vault health/diagnostics (read-only).
pub fn vault_health(handle: &VaultHandle) -> VaultHealthInfo {
    handle.health()
}

/// Defragment the vault: compact all segments toward the data region start,
/// coalesce free space into a single contiguous block at the end.
///
/// Each segment move is individually WAL-protected for crash safety.
/// Encrypted bytes are copied as-is (no re-encryption). The free tail
/// is secure-erased with CSPRNG after all moves complete.
#[cfg(feature = "compression")]
pub fn vault_defragment(handle: &mut VaultHandle) -> Result<DefragResult, CryptoError> {
    let free_regions_before = handle.index.free_regions.len() as u32;
    let bytes_reclaimed = handle.index.free_list_bytes();

    // Nothing to defrag — already compact
    if !handle.index.needs_defrag() {
        return Ok(DefragResult {
            segments_moved: 0,
            bytes_reclaimed: 0,
            free_regions_before: 0,
        });
    }

    // Compute move plan from the core index logic
    let moves = handle.index.plan_defrag();
    let segments_moved = moves.len() as u32;

    let defrag_backup_path = format!("{}.defrag", handle.path);

    for m in &moves {
        // --- WAL-protected move ---

        // Read encrypted segment bytes from old offset
        let read_len = usize::try_from(m.size).map_err(|_| {
            CryptoError::VaultCorrupted(format!(
                "segment size {} exceeds platform address space",
                m.size
            ))
        })?;
        handle.file.seek(SeekFrom::Start(
            format::data_region_offset(handle.index_pad_size) + m.old_offset,
        ))?;
        let mut buf = vec![0u8; read_len];
        handle.file.read_exact(&mut buf)?;

        // For overlapping moves (gap < size), writing to the new position
        // corrupts the overlap zone at the old position. Save a backup so
        // crash recovery can restore it.
        let gap = m.old_offset - m.new_offset;
        if gap < m.size {
            let mut backup = File::create(&defrag_backup_path)
                .map_err(|e| CryptoError::IoError(format!("defrag backup: {e}")))?;
            backup.write_all(&m.old_offset.to_le_bytes())?;
            backup.write_all(&m.size.to_le_bytes())?;
            backup.write_all(&buf)?;
            backup.sync_all()?;
        }

        // Journal current encrypted index before mutation
        let old_encrypted_index = read_encrypted_index(
            &mut handle.file,
            PRIMARY_INDEX_OFFSET,
            format::encrypted_index_size(handle.index_pad_size),
        )?;
        handle
            .wal
            .begin(WalOp::WriteSegment, &old_encrypted_index)?;

        // Write to new target offset and fsync
        handle.file.seek(SeekFrom::Start(
            format::data_region_offset(handle.index_pad_size) + m.new_offset,
        ))?;
        handle.file.write_all(&buf)?;
        buf.zeroize();
        handle.file.sync_all()?;

        // Update entry offset in index (generation, checksum, etc. stay the same)
        handle.index.apply_move(m.entry_index, m.new_offset)?;

        // Flush index to primary + shadow
        flush_index(
            &mut handle.file,
            &handle.index,
            &handle.keys,
            handle.algorithm,
            handle.index.capacity,
            handle.index_pad_size,
        )?;

        // WAL commit — move is now durable
        handle.wal.commit()?;

        // Remove defrag backup after successful commit
        let _ = std::fs::remove_file(&defrag_backup_path);

        // Secure-erase non-overlapping tail of old region (stale ciphertext).
        // Done AFTER commit so crash-recovery never points to erased data.
        let erase_start = std::cmp::max(m.new_offset + m.size, m.old_offset);
        let erase_end = m.old_offset + m.size;
        if erase_end > erase_start {
            segment::secure_erase_region(
                &mut handle.file,
                format::data_region_offset(handle.index_pad_size) + erase_start,
                erase_end - erase_start,
            )?;
        }

        // Checkpoint WAL — truncate history for faster recovery
        handle.wal.checkpoint()?;
    }

    // --- Post-compaction cleanup ---

    // Finalize: clear free_regions, set next_free_offset = sum of all sizes
    let packed_end = handle.index.used_bytes();
    handle.index.complete_defrag();

    // Flush the cleaned-up index
    flush_index(
        &mut handle.file,
        &handle.index,
        &handle.keys,
        handle.algorithm,
        handle.index.capacity,
        handle.index_pad_size,
    )?;

    // Secure-erase the free tail (CSPRNG overwrite + fsync)
    if packed_end < handle.index.capacity {
        segment::secure_erase_region(
            &mut handle.file,
            format::data_region_offset(handle.index_pad_size) + packed_end,
            handle.index.capacity - packed_end,
        )?;
    }

    // Checkpoint WAL (clear history) + refresh mmap (data moved)
    handle.wal.checkpoint()?;
    handle.refresh_mmap();

    Ok(DefragResult {
        segments_moved,
        bytes_reclaimed,
        free_regions_before,
    })
}

/// Close the vault — checkpoint WAL, release lock, zeroize keys on drop.
#[cfg(feature = "compression")]
pub fn vault_close(mut handle: VaultHandle) -> Result<(), CryptoError> {
    handle.wal.checkpoint()?;
    handle.lock.release()?;
    // VaultKeys are zeroized on drop (ZeroizeOnDrop)
    Ok(())
}
