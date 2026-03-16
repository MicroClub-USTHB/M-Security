//! Encrypted Virtual File System — .vault container format and operations.

mod helpers;
#[cfg(all(test, feature = "compression"))]
mod tests;
pub mod types;

use helpers::*;
pub use types::*;

use crate::api::compression::{CompressionAlgorithm, CompressionConfig};
use crate::core::error::CryptoError;
use crate::core::evfs::format::{
    self, SegmentEntry, SegmentIndex, VaultHeader, DATA_REGION_OFFSET, ENCRYPTED_INDEX_SIZE,
    PRIMARY_INDEX_OFFSET, VAULT_HEADER_SIZE,
};
use crate::core::evfs::segment::{self, SegmentCryptoParams};
use crate::core::evfs::wal::{VaultLock, WalOp, WriteAheadLog};
use crate::core::format::Algorithm;
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
    let total_size = format::total_vault_size(capacity_bytes)?;

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| CryptoError::IoError(format!("cannot create vault: {e}")))?;

    // Pre-allocate with CSPRNG random fill
    segment::preallocate_vault(&mut file, total_size)?;

    // Write header
    let header = VaultHeader::new(algo.to_byte());
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&header.to_bytes())?;

    // Create empty index and flush to primary + shadow
    let index = SegmentIndex::new(capacity_bytes);
    flush_index(&mut file, &index, &keys, algo, capacity_bytes)?;

    // Create fresh WAL (checkpoint to clear any stale data)
    let mut wal = WriteAheadLog::open(&path)?;
    wal.checkpoint()?;

    Ok(VaultHandle {
        path,
        algorithm: algo,
        keys,
        index,
        file,
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

    // Read header
    let mut header_buf = [0u8; VAULT_HEADER_SIZE];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut header_buf)?;
    let header = VaultHeader::from_bytes(&header_buf)?;
    let algorithm = Algorithm::from_byte(header.algorithm)?;

    // Derive keys
    let keys = segment::derive_vault_keys(&key)?;
    key.zeroize();

    // Compute capacity from file size
    let file_size = file.seek(SeekFrom::End(0))?;
    let capacity = capacity_from_file_size(file_size)?;

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
            // move. Restore segment data to the old position.
            if let Ok(mut backup) = File::open(&defrag_backup_path) {
                let mut hdr = [0u8; 16];
                if backup.read_exact(&mut hdr).is_ok() {
                    // SAFETY: slices are exactly 8 bytes from a 16-byte array
                    let offset = u64::from_le_bytes([
                        hdr[0], hdr[1], hdr[2], hdr[3], hdr[4], hdr[5], hdr[6], hdr[7],
                    ]);
                    let size = u64::from_le_bytes([
                        hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13], hdr[14], hdr[15],
                    ]);
                    // Cap at 256MB to prevent OOM from corrupted backup headers
                    const MAX_BACKUP_SIZE: u64 = 256 * 1024 * 1024;
                    if size > 0 && size <= capacity && size <= MAX_BACKUP_SIZE {
                        let mut data = vec![0u8; size as usize];
                        if backup.read_exact(&mut data).is_ok() {
                            file.seek(SeekFrom::Start(DATA_REGION_OFFSET + offset))?;
                            file.write_all(&data)?;
                            file.sync_all()?;
                        }
                    }
                }
            }
        }
        let _ = std::fs::remove_file(&defrag_backup_path);
    }

    // WAL recovery — only restore primary index. Shadow position depends on
    // capacity which may have changed during an interrupted resize; the
    // post-recovery reconciliation below fixes the shadow.
    if let Some(old_encrypted_index) = wal_snapshot {
        if old_encrypted_index.len() != ENCRYPTED_INDEX_SIZE {
            return Err(CryptoError::VaultCorrupted(format!(
                "WAL snapshot size {} != expected {ENCRYPTED_INDEX_SIZE}",
                old_encrypted_index.len()
            )));
        }
        file.seek(SeekFrom::Start(PRIMARY_INDEX_OFFSET))?;
        file.write_all(&old_encrypted_index)?;
        file.sync_all()?;
    }
    wal.checkpoint()?;

    // Decrypt index (try primary, fall back to shadow)
    let index = {
        let primary_bytes = read_encrypted_index(&mut file, PRIMARY_INDEX_OFFSET)?;
        match decrypt_index_blob(&primary_bytes, &keys, algorithm) {
            Ok(idx) => idx,
            Err(_) => {
                let shadow_off = format::shadow_index_offset(capacity)?;
                let shadow_bytes = read_encrypted_index(&mut file, shadow_off)?;
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

    // Post-recovery reconciliation: if an interrupted resize left the file
    // at the wrong size, fix the file and shadow to match the index.
    let expected_total = format::total_vault_size(index.capacity)?;
    let actual_size = file.seek(SeekFrom::End(0))?;
    if actual_size != expected_total {
        file.set_len(expected_total)?;
        let primary_bytes = read_encrypted_index(&mut file, PRIMARY_INDEX_OFFSET)?;
        let shadow_off = format::shadow_index_offset(index.capacity)?;
        file.seek(SeekFrom::Start(shadow_off))?;
        file.write_all(&primary_bytes)?;
        file.sync_all()?;
    }

    Ok(VaultHandle {
        path,
        algorithm,
        keys,
        index,
        file,
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
    let old_encrypted_index = read_encrypted_index(&mut handle.file, PRIMARY_INDEX_OFFSET)?;
    handle
        .wal
        .begin(WalOp::WriteSegment, &old_encrypted_index)?;

    // 4. If overwrite: secure-erase old region, deallocate
    if let Some(old_entry) = handle.index.remove(&name) {
        segment::secure_erase_region(
            &mut handle.file,
            DATA_REGION_OFFSET + old_entry.offset,
            old_entry.size,
        )?;
        handle.index.deallocate(old_entry.offset, old_entry.size);
    }

    // 5. Allocate space (free list first, then append)
    let offset = handle.index.allocate(encrypted.len() as u64)?;

    // 6. Write encrypted segment at allocated offset + fsync before index update
    handle
        .file
        .seek(SeekFrom::Start(DATA_REGION_OFFSET + offset))?;
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
    )?;
    handle.index.add(entry)?;

    // 8. Flush index (primary + shadow)
    flush_index(
        &mut handle.file,
        &handle.index,
        &handle.keys,
        handle.algorithm,
        handle.index.capacity,
    )?;

    // 9. WAL commit
    handle.wal.commit()?;

    Ok(())
}

/// Read a named segment. Decompression is automatic.
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

    // Read encrypted data from disk
    let read_len = usize::try_from(seg_size).map_err(|_| {
        CryptoError::VaultCorrupted(format!(
            "segment size {seg_size} exceeds platform address space"
        ))
    })?;
    handle
        .file
        .seek(SeekFrom::Start(DATA_REGION_OFFSET + seg_offset))?;
    let mut encrypted = vec![0u8; read_len];
    handle.file.read_exact(&mut encrypted)?;

    // Decrypt-then-decompress
    let params = SegmentCryptoParams {
        cipher_key: handle.keys.cipher_key.as_bytes(),
        nonce_key: handle.keys.nonce_key.as_bytes(),
        algorithm: handle.algorithm,
        segment_index: 0,
        generation: seg_gen,
    };
    let plaintext = segment::decrypt_segment(&params, &encrypted, seg_compression)?;

    // Verify checksum on decompressed plaintext
    if !segment::verify_checksum(&plaintext, &seg_checksum) {
        return Err(CryptoError::VaultCorrupted(format!(
            "integrity check failed for segment '{name}'"
        )));
    }

    Ok(plaintext)
}

/// Delete a named segment. The region is secure-erased and returned to the
/// free list for reuse by future writes.
#[cfg(feature = "compression")]
pub fn vault_delete(handle: &mut VaultHandle, name: String) -> Result<(), CryptoError> {
    // WAL journal old index
    let old_encrypted_index = read_encrypted_index(&mut handle.file, PRIMARY_INDEX_OFFSET)?;
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
        DATA_REGION_OFFSET + entry.offset,
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
    )?;

    // WAL commit
    handle.wal.commit()?;

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
    let old_encrypted_index = read_encrypted_index(&mut handle.file, PRIMARY_INDEX_OFFSET)?;
    handle.wal.begin(WalOp::UpdateIndex, &old_encrypted_index)?;

    // Extend file and CSPRNG-fill new space (also overwrites old shadow position)
    let new_total = format::total_vault_size(new_capacity)?;
    handle.file.set_len(new_total)?;
    let fill_offset = DATA_REGION_OFFSET + old_capacity;
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
    )?;

    handle.wal.commit()?;
    handle.wal.checkpoint()?;

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
    let old_encrypted_index = read_encrypted_index(&mut handle.file, PRIMARY_INDEX_OFFSET)?;
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
    )?;

    // Truncate file to new total size.
    let new_total = format::total_vault_size(new_capacity)?;
    handle.file.set_len(new_total)?;
    handle.file.sync_all()?;

    handle.wal.commit()?;
    handle.wal.checkpoint()?;

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
        handle
            .file
            .seek(SeekFrom::Start(DATA_REGION_OFFSET + m.old_offset))?;
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
        let old_encrypted_index = read_encrypted_index(&mut handle.file, PRIMARY_INDEX_OFFSET)?;
        handle
            .wal
            .begin(WalOp::WriteSegment, &old_encrypted_index)?;

        // Write to new target offset and fsync
        handle
            .file
            .seek(SeekFrom::Start(DATA_REGION_OFFSET + m.new_offset))?;
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
                DATA_REGION_OFFSET + erase_start,
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
    )?;

    // Secure-erase the free tail (CSPRNG overwrite + fsync)
    if packed_end < handle.index.capacity {
        segment::secure_erase_region(
            &mut handle.file,
            DATA_REGION_OFFSET + packed_end,
            handle.index.capacity - packed_end,
        )?;
    }

    // Checkpoint WAL (clear history)
    handle.wal.checkpoint()?;

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
