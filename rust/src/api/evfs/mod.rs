//! Encrypted Virtual File System — .vault container format and operations.

#[allow(dead_code)]
mod format;
#[allow(dead_code)]
mod segment;
#[allow(dead_code)]
mod wal;

use crate::api::compression::{CompressionAlgorithm, CompressionConfig};
use crate::core::error::CryptoError;
use crate::core::format::Algorithm;
use flutter_rust_bridge::frb;
use zeroize::Zeroize;

use self::format::{
    SegmentEntry, SegmentIndex, VaultHeader, DATA_REGION_OFFSET, ENCRYPTED_INDEX_SIZE,
    PRIMARY_INDEX_OFFSET, VAULT_HEADER_SIZE,
};
use self::segment::{SegmentCryptoParams, VaultKeys};
use self::wal::{VaultLock, WalOp, WriteAheadLog};

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

// ---------------------------------------------------------------------------
// VaultHandle
// ---------------------------------------------------------------------------

/// Opaque handle for an open vault.
///
/// Holds the open file, derived sub-keys, cached index, WAL, and file lock.
/// All key material uses SecretBuffer (ZeroizeOnDrop).
#[frb(opaque)]
pub struct VaultHandle {
    #[allow(dead_code)] // used by Dart wrappers
    path: String,
    algorithm: Algorithm,
    keys: VaultKeys,
    index: SegmentIndex,
    file: File,
    wal: WriteAheadLog,
    lock: VaultLock,
}

/// Capacity info returned to callers.
pub struct VaultCapacityInfo {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub free_list_bytes: u64,
    pub unallocated_bytes: u64,
    pub segment_count: usize,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_algorithm(s: &str) -> Result<Algorithm, CryptoError> {
    match s {
        "aes-256-gcm" => Ok(Algorithm::AesGcm),
        "chacha20-poly1305" => Ok(Algorithm::ChaCha20Poly1305),
        _ => Err(CryptoError::InvalidParameter(format!(
            "unsupported algorithm: '{s}' (expected 'aes-256-gcm' or 'chacha20-poly1305')"
        ))),
    }
}

/// Encrypt the in-memory index and write to both primary and shadow locations.
fn flush_index(
    file: &mut File,
    index: &SegmentIndex,
    keys: &VaultKeys,
    algorithm: Algorithm,
    capacity: u64,
) -> Result<(), CryptoError> {
    let plaintext = index.to_bytes()?;
    let encrypted = segment::aead_encrypt_random_nonce(
        keys.index_key.as_bytes(),
        &plaintext,
        &[],
        algorithm,
    )?;

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
fn read_encrypted_index(file: &mut File, offset: u64) -> Result<Vec<u8>, CryptoError> {
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; ENCRYPTED_INDEX_SIZE];
    file.read_exact(&mut buf)?;
    Ok(buf)
}

/// Decrypt an encrypted index blob into a SegmentIndex.
fn decrypt_index_blob(
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
fn capacity_from_file_size(file_size: u64) -> Result<u64, CryptoError> {
    let overhead = VAULT_HEADER_SIZE as u64 + 2 * ENCRYPTED_INDEX_SIZE as u64;
    file_size
        .checked_sub(overhead)
        .ok_or_else(|| CryptoError::VaultCorrupted("vault file too small".into()))
}

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

    // WAL recovery
    let mut wal = WriteAheadLog::open(&path)?;
    if let Some(old_encrypted_index) = wal.recover()? {
        if old_encrypted_index.len() != ENCRYPTED_INDEX_SIZE {
            return Err(CryptoError::VaultCorrupted(format!(
                "WAL snapshot size {} != expected {ENCRYPTED_INDEX_SIZE}",
                old_encrypted_index.len()
            )));
        }
        // Restore old index to primary + shadow
        file.seek(SeekFrom::Start(PRIMARY_INDEX_OFFSET))?;
        file.write_all(&old_encrypted_index)?;
        let shadow_off = format::shadow_index_offset(capacity)?;
        file.seek(SeekFrom::Start(shadow_off))?;
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
    let (encrypted, effective_algo) =
        segment::encrypt_segment(&params, &data, &name, &config)?;
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

    // 6. Write encrypted segment at allocated offset
    handle
        .file
        .seek(SeekFrom::Start(DATA_REGION_OFFSET + offset))?;
    handle.file.write_all(&encrypted)?;

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
pub fn vault_read(
    handle: &mut VaultHandle,
    name: String,
) -> Result<Vec<u8>, CryptoError> {
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
pub fn vault_delete(
    handle: &mut VaultHandle,
    name: String,
) -> Result<(), CryptoError> {
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

/// List all segment names in the vault.
pub fn vault_list(handle: &VaultHandle) -> Vec<String> {
    handle.index.entries.iter().map(|e| e.name.clone()).collect()
}

/// Get vault capacity info.
pub fn vault_capacity(handle: &VaultHandle) -> VaultCapacityInfo {
    let used = handle.index.used_bytes();
    let free_list = handle.index.free_list_bytes();
    let unallocated = handle.index.capacity.saturating_sub(handle.index.next_free_offset);
    VaultCapacityInfo {
        total_bytes: handle.index.capacity,
        used_bytes: used,
        free_list_bytes: free_list,
        unallocated_bytes: unallocated,
        segment_count: handle.index.entries.len(),
    }
}

/// Close the vault — checkpoint WAL, release lock, zeroize keys on drop.
#[cfg(feature = "compression")]
pub fn vault_close(mut handle: VaultHandle) -> Result<(), CryptoError> {
    handle.wal.checkpoint()?;
    handle.lock.release()?;
    // VaultKeys are zeroized on drop (ZeroizeOnDrop)
    Ok(())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(all(test, feature = "compression"))]
mod tests {
    use super::*;

    fn test_key() -> Vec<u8> {
        vec![0xAA; 32]
    }

    fn wrong_key() -> Vec<u8> {
        vec![0xBB; 32]
    }

    fn create_test_vault(dir: &tempfile::TempDir, capacity: u64) -> VaultHandle {
        let path = dir
            .path()
            .join("test.vault")
            .to_str()
            .expect("path")
            .to_string();
        vault_create(path, test_key(), "aes-256-gcm".into(), capacity).expect("create vault")
    }

    fn vault_path(dir: &tempfile::TempDir) -> String {
        dir.path()
            .join("test.vault")
            .to_str()
            .expect("path")
            .to_string()
    }

    // -- Create / Open ------------------------------------------------------

    #[test]
    fn test_create_and_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = vault_path(&dir);

        {
            let handle =
                vault_create(path.clone(), test_key(), "aes-256-gcm".into(), 1_048_576)
                    .expect("create");
            let names = vault_list(&handle);
            assert!(names.is_empty());
            vault_close(handle).expect("close");
        }

        {
            let handle = vault_open(path, test_key()).expect("open");
            let names = vault_list(&handle);
            assert!(names.is_empty());
            vault_close(handle).expect("close");
        }
    }

    #[test]
    fn test_open_wrong_key_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = vault_path(&dir);

        {
            let handle =
                vault_create(path.clone(), test_key(), "aes-256-gcm".into(), 1_048_576)
                    .expect("create");
            vault_close(handle).expect("close");
        }

        let result = vault_open(path, wrong_key());
        assert!(result.is_err());
    }

    #[test]
    fn test_open_runs_wal_recovery() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = vault_path(&dir);

        // Create vault with segment A
        {
            let mut handle =
                vault_create(path.clone(), test_key(), "aes-256-gcm".into(), 1_048_576)
                    .expect("create");
            vault_write(&mut handle, "a.txt".into(), b"data-A".to_vec(), None).expect("write A");
            vault_close(handle).expect("close");
        }

        // Save the "good" encrypted index (containing only A)
        let good_encrypted = {
            let mut f = File::open(&path).expect("open");
            read_encrypted_index(&mut f, PRIMARY_INDEX_OFFSET).expect("read index")
        };

        // Add segment B normally (both index and data on disk)
        {
            let mut handle = vault_open(path.clone(), test_key()).expect("open");
            vault_write(&mut handle, "b.txt".into(), b"data-B".to_vec(), None).expect("write B");
            vault_close(handle).expect("close");
        }

        // Simulate crash: uncommitted WAL entry restoring the A-only index
        {
            let mut wal = WriteAheadLog::open(&path).expect("wal");
            wal.begin(WalOp::WriteSegment, &good_encrypted)
                .expect("begin");
            // Don't commit — simulates crash
        }

        // Reopen — WAL recovery should roll back to A-only index
        let mut handle = vault_open(path, test_key()).expect("open after recovery");
        let data = vault_read(&mut handle, "a.txt".into()).expect("read A");
        assert_eq!(data, b"data-A");

        let result = vault_read(&mut handle, "b.txt".into());
        assert!(matches!(result, Err(CryptoError::SegmentNotFound(_))));

        vault_close(handle).expect("close");
    }

    // -- Write / Read -------------------------------------------------------

    #[test]
    fn test_write_read_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut handle = create_test_vault(&dir, 1_048_576);

        vault_write(
            &mut handle,
            "doc.txt".into(),
            b"hello vault".to_vec(),
            None,
        )
        .expect("write");

        let data = vault_read(&mut handle, "doc.txt".into()).expect("read");
        assert_eq!(data, b"hello vault");

        vault_close(handle).expect("close");
    }

    #[test]
    fn test_write_read_multiple_segments() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut handle = create_test_vault(&dir, 1_048_576);

        for i in 0..5 {
            let name = format!("seg{i}.bin");
            let data = format!("data for segment {i}").into_bytes();
            vault_write(&mut handle, name, data, None).expect("write");
        }

        for i in 0..5 {
            let name = format!("seg{i}.bin");
            let expected = format!("data for segment {i}").into_bytes();
            let data = vault_read(&mut handle, name).expect("read");
            assert_eq!(data, expected);
        }

        assert_eq!(vault_list(&handle).len(), 5);
        vault_close(handle).expect("close");
    }

    #[test]
    fn test_write_overwrite() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut handle = create_test_vault(&dir, 1_048_576);

        vault_write(&mut handle, "doc.txt".into(), b"version 1".to_vec(), None).expect("write v1");
        vault_write(&mut handle, "doc.txt".into(), b"version 2".to_vec(), None).expect("write v2");

        let data = vault_read(&mut handle, "doc.txt".into()).expect("read");
        assert_eq!(data, b"version 2");
        assert_eq!(vault_list(&handle).len(), 1);

        vault_close(handle).expect("close");
    }

    #[test]
    fn test_write_overwrite_increments_generation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut handle = create_test_vault(&dir, 1_048_576);

        vault_write(&mut handle, "doc.txt".into(), b"v1".to_vec(), None).expect("write v1");
        let gen1 = handle.index.find("doc.txt").expect("find").generation;

        vault_write(&mut handle, "doc.txt".into(), b"v2".to_vec(), None).expect("write v2");
        let gen2 = handle.index.find("doc.txt").expect("find").generation;

        assert!(gen2 > gen1);
        vault_close(handle).expect("close");
    }

    #[test]
    fn test_read_nonexistent_segment() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut handle = create_test_vault(&dir, 1_048_576);

        let result = vault_read(&mut handle, "nope.txt".into());
        assert!(matches!(result, Err(CryptoError::SegmentNotFound(_))));

        vault_close(handle).expect("close");
    }

    #[test]
    fn test_read_tampered_segment() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut handle = create_test_vault(&dir, 1_048_576);

        vault_write(
            &mut handle,
            "secret.txt".into(),
            b"important data".to_vec(),
            None,
        )
        .expect("write");

        // Tamper with encrypted data on disk
        let entry = handle.index.find("secret.txt").expect("find");
        let disk_offset = DATA_REGION_OFFSET + entry.offset;
        // Flip a byte in the ciphertext (after the 12-byte nonce)
        handle.file.seek(SeekFrom::Start(disk_offset + 13)).expect("seek");
        handle.file.write_all(&[0xFF]).expect("tamper");
        handle.file.sync_all().expect("sync");

        let result = vault_read(&mut handle, "secret.txt".into());
        assert!(result.is_err());

        vault_close(handle).expect("close");
    }

    // -- Compression integration --------------------------------------------

    #[test]
    fn test_write_read_zstd_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut handle = create_test_vault(&dir, 1_048_576);
        let data = b"compressible data repeated ".repeat(100);

        let config = CompressionConfig {
            algorithm: CompressionAlgorithm::Zstd,
            level: None,
        };
        vault_write(&mut handle, "data.txt".into(), data.clone(), Some(config)).expect("write");
        let read_back = vault_read(&mut handle, "data.txt".into()).expect("read");
        assert_eq!(read_back, data);

        vault_close(handle).expect("close");
    }

    #[test]
    fn test_write_read_brotli_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut handle = create_test_vault(&dir, 1_048_576);
        let data = b"brotli compressible data ".repeat(80);

        let config = CompressionConfig {
            algorithm: CompressionAlgorithm::Brotli,
            level: None,
        };
        vault_write(&mut handle, "notes.md".into(), data.clone(), Some(config)).expect("write");
        let read_back = vault_read(&mut handle, "notes.md".into()).expect("read");
        assert_eq!(read_back, data);

        vault_close(handle).expect("close");
    }

    #[test]
    fn test_write_read_no_compression() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut handle = create_test_vault(&dir, 1_048_576);
        let data = b"uncompressed payload".to_vec();

        let config = CompressionConfig {
            algorithm: CompressionAlgorithm::None,
            level: None,
        };
        vault_write(&mut handle, "raw.bin".into(), data.clone(), Some(config)).expect("write");
        let read_back = vault_read(&mut handle, "raw.bin".into()).expect("read");
        assert_eq!(read_back, data);

        vault_close(handle).expect("close");
    }

    #[test]
    fn test_write_jpg_skips_compression() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut handle = create_test_vault(&dir, 1_048_576);

        let config = CompressionConfig {
            algorithm: CompressionAlgorithm::Zstd,
            level: None,
        };
        vault_write(
            &mut handle,
            "photo.jpg".into(),
            b"fake jpeg".to_vec(),
            Some(config),
        )
        .expect("write");

        let entry = handle.index.find("photo.jpg").expect("find");
        assert_eq!(entry.compression, CompressionAlgorithm::None);

        let data = vault_read(&mut handle, "photo.jpg".into()).expect("read");
        assert_eq!(data, b"fake jpeg");

        vault_close(handle).expect("close");
    }

    #[test]
    fn test_read_decompresses_automatically() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut handle = create_test_vault(&dir, 1_048_576);
        let data = b"auto-decompress test data ".repeat(50);

        let config = CompressionConfig {
            algorithm: CompressionAlgorithm::Zstd,
            level: None,
        };
        vault_write(&mut handle, "auto.txt".into(), data.clone(), Some(config)).expect("write");

        // Read back — decompression is automatic (no config needed)
        let read_back = vault_read(&mut handle, "auto.txt".into()).expect("read");
        assert_eq!(read_back, data);

        vault_close(handle).expect("close");
    }

    #[test]
    fn test_mixed_compression_segments() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut handle = create_test_vault(&dir, 1_048_576);

        let text = b"text data ".repeat(50);
        let binary = vec![0xABu8; 500];
        let raw = b"raw data no compress".to_vec();

        let zstd_conf = CompressionConfig {
            algorithm: CompressionAlgorithm::Zstd,
            level: None,
        };
        let brotli_conf = CompressionConfig {
            algorithm: CompressionAlgorithm::Brotli,
            level: None,
        };

        vault_write(&mut handle, "text.txt".into(), text.clone(), Some(zstd_conf)).expect("zstd");
        vault_write(
            &mut handle,
            "data.bin".into(),
            binary.clone(),
            Some(brotli_conf),
        )
        .expect("brotli");
        vault_write(&mut handle, "raw.dat".into(), raw.clone(), None).expect("none");

        assert_eq!(vault_read(&mut handle, "text.txt".into()).expect("r"), text);
        assert_eq!(
            vault_read(&mut handle, "data.bin".into()).expect("r"),
            binary
        );
        assert_eq!(vault_read(&mut handle, "raw.dat".into()).expect("r"), raw);

        vault_close(handle).expect("close");
    }

    #[test]
    fn test_checksum_on_original_plaintext() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut handle = create_test_vault(&dir, 1_048_576);

        let data = b"checksum covers original ".repeat(50);
        let config = CompressionConfig {
            algorithm: CompressionAlgorithm::Zstd,
            level: None,
        };
        vault_write(
            &mut handle,
            "check.txt".into(),
            data.clone(),
            Some(config),
        )
        .expect("write");

        // Verify the stored checksum matches original plaintext (not compressed form)
        let entry = handle.index.find("check.txt").expect("find");
        assert!(segment::verify_checksum(&data, &entry.checksum));

        vault_close(handle).expect("close");
    }

    // -- Space reclamation (free list) --------------------------------------

    #[test]
    fn test_delete_returns_space_to_free_list() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut handle = create_test_vault(&dir, 1_048_576);

        vault_write(&mut handle, "a.txt".into(), b"some data here".to_vec(), None).expect("write");
        let seg_size = handle.index.find("a.txt").expect("find").size;

        vault_delete(&mut handle, "a.txt".into()).expect("delete");

        let cap = vault_capacity(&handle);
        assert_eq!(cap.free_list_bytes, seg_size);
        assert_eq!(cap.segment_count, 0);

        vault_close(handle).expect("close");
    }

    #[test]
    fn test_write_reuses_deleted_space() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut handle = create_test_vault(&dir, 1_048_576);

        // Write A — note the offset and size
        vault_write(&mut handle, "a.txt".into(), vec![0xAA; 200], None).expect("write A");
        let a_offset = handle.index.find("a.txt").expect("A").offset;
        let a_size = handle.index.find("a.txt").expect("A").size;

        // Delete A
        vault_delete(&mut handle, "a.txt".into()).expect("delete A");

        // Write B (smaller) — should reuse A's space
        vault_write(&mut handle, "b.txt".into(), vec![0xBB; 50], None).expect("write B");
        let b_offset = handle.index.find("b.txt").expect("B").offset;
        let b_size = handle.index.find("b.txt").expect("B").size;

        assert_eq!(b_offset, a_offset);
        assert!(b_size < a_size);

        // Free list should have leftover from A's region
        let cap = vault_capacity(&handle);
        assert_eq!(cap.free_list_bytes, a_size - b_size);

        vault_close(handle).expect("close");
    }

    #[test]
    fn test_write_after_delete_exact_fit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut handle = create_test_vault(&dir, 1_048_576);

        // Write and capture the encrypted size
        vault_write(&mut handle, "a.txt".into(), vec![0xAA; 200], None).expect("write A");
        let a_offset = handle.index.find("a.txt").expect("A").offset;
        let a_size = handle.index.find("a.txt").expect("A").size;
        vault_delete(&mut handle, "a.txt".into()).expect("delete A");

        // Write B with same plaintext size — encrypted size should match exactly
        vault_write(&mut handle, "b.txt".into(), vec![0xBB; 200], None).expect("write B");
        let b_offset = handle.index.find("b.txt").expect("B").offset;
        let b_size = handle.index.find("b.txt").expect("B").size;

        assert_eq!(b_offset, a_offset);
        assert_eq!(b_size, a_size);
        assert_eq!(vault_capacity(&handle).free_list_bytes, 0);

        vault_close(handle).expect("close");
    }

    #[test]
    fn test_overwrite_reclaims_then_allocates() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut handle = create_test_vault(&dir, 1_048_576);

        vault_write(&mut handle, "doc.txt".into(), vec![0xAA; 500], None).expect("write big");
        let old_size = handle.index.find("doc.txt").expect("old").size;

        // Overwrite with smaller data
        vault_write(&mut handle, "doc.txt".into(), vec![0xBB; 100], None)
            .expect("overwrite small");
        let new_size = handle.index.find("doc.txt").expect("new").size;

        assert!(new_size < old_size);
        // Free list should have leftover from reclaimed space
        let cap = vault_capacity(&handle);
        assert!(cap.free_list_bytes > 0 || cap.unallocated_bytes > 0);

        vault_close(handle).expect("close");
    }

    #[test]
    fn test_delete_multiple_merges_adjacent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut handle = create_test_vault(&dir, 1_048_576);

        // Write A, B, C contiguously
        vault_write(&mut handle, "a.txt".into(), vec![0xAA; 100], None).expect("A");
        vault_write(&mut handle, "b.txt".into(), vec![0xBB; 100], None).expect("B");
        vault_write(&mut handle, "c.txt".into(), vec![0xCC; 100], None).expect("C");

        let b_size = handle.index.find("b.txt").expect("B").size;
        let c_size = handle.index.find("c.txt").expect("C").size;

        // Delete B then C — should merge into one free region
        vault_delete(&mut handle, "b.txt".into()).expect("del B");
        vault_delete(&mut handle, "c.txt".into()).expect("del C");

        assert_eq!(handle.index.free_regions.len(), 1);
        assert_eq!(handle.index.free_regions[0].size, b_size + c_size);

        vault_close(handle).expect("close");
    }

    #[test]
    fn test_free_list_falls_back_to_append() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut handle = create_test_vault(&dir, 1_048_576);

        // Write A (small), delete it
        vault_write(&mut handle, "a.txt".into(), vec![0xAA; 50], None).expect("A");
        let a_size = handle.index.find("a.txt").expect("A").size;
        vault_delete(&mut handle, "a.txt".into()).expect("del A");

        // Write B (much larger) — won't fit in A's free region
        vault_write(&mut handle, "b.txt".into(), vec![0xBB; 5000], None).expect("B");
        let b_offset = handle.index.find("b.txt").expect("B").offset;

        // B should be appended (offset > A's region)
        assert!(b_offset >= a_size);

        // Free list should still have A's old region
        let cap = vault_capacity(&handle);
        assert_eq!(cap.free_list_bytes, a_size);

        vault_close(handle).expect("close");
    }

    #[test]
    fn test_capacity_reflects_free_list() {
        let dir = tempfile::tempdir().expect("tempdir");
        let capacity = 1_048_576u64;
        let mut handle = create_test_vault(&dir, capacity);

        vault_write(&mut handle, "a.txt".into(), vec![0xAA; 200], None).expect("A");
        vault_write(&mut handle, "b.txt".into(), vec![0xBB; 300], None).expect("B");

        let cap = vault_capacity(&handle);
        assert_eq!(cap.total_bytes, capacity);
        assert_eq!(cap.segment_count, 2);
        // used + free_list + unallocated should account for total capacity
        assert_eq!(
            cap.used_bytes + cap.free_list_bytes + cap.unallocated_bytes,
            capacity
        );

        vault_close(handle).expect("close");
    }

    // -- Delete -------------------------------------------------------------

    #[test]
    fn test_delete_segment() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut handle = create_test_vault(&dir, 1_048_576);

        vault_write(&mut handle, "tmp.txt".into(), b"temp data".to_vec(), None).expect("write");
        vault_delete(&mut handle, "tmp.txt".into()).expect("delete");

        let result = vault_read(&mut handle, "tmp.txt".into());
        assert!(matches!(result, Err(CryptoError::SegmentNotFound(_))));

        vault_close(handle).expect("close");
    }

    #[test]
    fn test_delete_secure_erase() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut handle = create_test_vault(&dir, 1_048_576);

        vault_write(
            &mut handle,
            "secret.txt".into(),
            b"sensitive data".to_vec(),
            None,
        )
        .expect("write");

        // Capture encrypted bytes at the segment offset
        let entry = handle.index.find("secret.txt").expect("find");
        let disk_offset = DATA_REGION_OFFSET + entry.offset;
        let size = entry.size as usize;
        handle.file.seek(SeekFrom::Start(disk_offset)).expect("seek");
        let mut old_bytes = vec![0u8; size];
        handle.file.read_exact(&mut old_bytes).expect("read");
        let saved_offset = disk_offset;

        vault_delete(&mut handle, "secret.txt".into()).expect("delete");

        // Same region should now contain different bytes (CSPRNG overwrite)
        handle.file.seek(SeekFrom::Start(saved_offset)).expect("seek");
        let mut new_bytes = vec![0u8; size];
        handle.file.read_exact(&mut new_bytes).expect("read");
        assert_ne!(old_bytes, new_bytes);

        vault_close(handle).expect("close");
    }

    // -- Capacity -----------------------------------------------------------

    #[test]
    fn test_vault_full() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Tiny vault: 256 bytes capacity
        let mut handle = create_test_vault(&dir, 256);

        // First write (encrypted data ~ 28 + plaintext bytes)
        vault_write(&mut handle, "a.txt".into(), vec![0xAA; 200], None).expect("A");

        // Second write should fail — not enough space
        let result = vault_write(&mut handle, "b.txt".into(), vec![0xBB; 200], None);
        assert!(matches!(result, Err(CryptoError::VaultFull { .. })));

        vault_close(handle).expect("close");
    }

    #[test]
    fn test_vault_full_with_free_list() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Small vault
        let mut handle = create_test_vault(&dir, 512);

        // Fill vault with A
        vault_write(&mut handle, "a.txt".into(), vec![0xAA; 400], None).expect("A");

        // Delete A (space returned to free list)
        vault_delete(&mut handle, "a.txt".into()).expect("del A");

        // Write B using freed space — should succeed
        vault_write(&mut handle, "b.txt".into(), vec![0xBB; 400], None).expect("B from free list");

        let data = vault_read(&mut handle, "b.txt".into()).expect("read B");
        assert_eq!(data, vec![0xBB; 400]);

        vault_close(handle).expect("close");
    }

    #[test]
    fn test_capacity_info() {
        let dir = tempfile::tempdir().expect("tempdir");
        let capacity = 1_048_576u64;
        let mut handle = create_test_vault(&dir, capacity);

        let cap = vault_capacity(&handle);
        assert_eq!(cap.total_bytes, capacity);
        assert_eq!(cap.used_bytes, 0);
        assert_eq!(cap.free_list_bytes, 0);
        assert_eq!(cap.unallocated_bytes, capacity);
        assert_eq!(cap.segment_count, 0);

        vault_write(&mut handle, "a.txt".into(), b"hello".to_vec(), None).expect("write");

        let cap = vault_capacity(&handle);
        assert_eq!(cap.segment_count, 1);
        assert!(cap.used_bytes > 0);
        assert_eq!(
            cap.used_bytes + cap.free_list_bytes + cap.unallocated_bytes,
            capacity
        );

        vault_close(handle).expect("close");
    }

    // -- Locking ------------------------------------------------------------

    #[test]
    fn test_concurrent_open_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = vault_path(&dir);

        let _handle =
            vault_create(path.clone(), test_key(), "aes-256-gcm".into(), 1_048_576)
                .expect("create");

        let result = vault_open(path, test_key());
        assert!(matches!(result, Err(CryptoError::VaultLocked)));
    }

    // -- Persistence across close/open --------------------------------------

    #[test]
    fn test_write_close_open_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = vault_path(&dir);

        {
            let mut handle =
                vault_create(path.clone(), test_key(), "chacha20-poly1305".into(), 1_048_576)
                    .expect("create");
            vault_write(
                &mut handle,
                "persist.txt".into(),
                b"survives close".to_vec(),
                None,
            )
            .expect("write");
            vault_close(handle).expect("close");
        }

        {
            let mut handle = vault_open(path, test_key()).expect("open");
            let data = vault_read(&mut handle, "persist.txt".into()).expect("read");
            assert_eq!(data, b"survives close");
            vault_close(handle).expect("close");
        }
    }

    // -- Shadow index fallback ----------------------------------------------

    #[test]
    fn test_corrupted_primary_falls_back_to_shadow() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = vault_path(&dir);

        {
            let mut handle =
                vault_create(path.clone(), test_key(), "aes-256-gcm".into(), 1_048_576)
                    .expect("create");
            vault_write(
                &mut handle,
                "doc.txt".into(),
                b"shadow test".to_vec(),
                None,
            )
            .expect("write");
            vault_close(handle).expect("close");
        }

        // Corrupt primary index on disk
        {
            let mut f = OpenOptions::new().write(true).open(&path).expect("open");
            f.seek(SeekFrom::Start(PRIMARY_INDEX_OFFSET)).expect("seek");
            f.write_all(&[0xFF; 100]).expect("corrupt");
        }

        // Open should succeed via shadow
        let mut handle = vault_open(path, test_key()).expect("open via shadow");
        let data = vault_read(&mut handle, "doc.txt".into()).expect("read");
        assert_eq!(data, b"shadow test");

        vault_close(handle).expect("close");
    }
}
