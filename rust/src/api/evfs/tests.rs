
use super::*;
use crate::core::evfs::format::{encrypted_index_size, MIN_INDEX_PAD_SIZE};

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
        let handle = vault_create(path.clone(), test_key(), "aes-256-gcm".into(), 1_048_576)
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
        let handle = vault_create(path.clone(), test_key(), "aes-256-gcm".into(), 1_048_576)
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
        let mut handle = vault_create(path.clone(), test_key(), "aes-256-gcm".into(), 1_048_576)
            .expect("create");
        vault_write(&mut handle, "a.txt".into(), b"data-A".to_vec(), None).expect("write A");
        vault_close(handle).expect("close");
    }

    // Save the "good" encrypted index (containing only A)
    let good_encrypted = {
        let mut f = File::open(&path).expect("open");
        read_encrypted_index(&mut f, PRIMARY_INDEX_OFFSET, encrypted_index_size(MIN_INDEX_PAD_SIZE)).expect("read index")
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

    vault_write(&mut handle, "doc.txt".into(), b"hello vault".to_vec(), None).expect("write");

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
    let disk_offset = format::data_region_offset(MIN_INDEX_PAD_SIZE) + entry.offset;
    // Flip a byte in the ciphertext (after the 12-byte nonce)
    handle
        .file
        .seek(SeekFrom::Start(disk_offset + 13))
        .expect("seek");
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

    vault_write(
        &mut handle,
        "text.txt".into(),
        text.clone(),
        Some(zstd_conf),
    )
    .expect("zstd");
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
    vault_write(&mut handle, "check.txt".into(), data.clone(), Some(config)).expect("write");

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

    vault_write(
        &mut handle,
        "a.txt".into(),
        b"some data here".to_vec(),
        None,
    )
    .expect("write");
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
    vault_write(&mut handle, "doc.txt".into(), vec![0xBB; 100], None).expect("overwrite small");
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
    let disk_offset = format::data_region_offset(MIN_INDEX_PAD_SIZE) + entry.offset;
    let size = entry.size as usize;
    handle
        .file
        .seek(SeekFrom::Start(disk_offset))
        .expect("seek");
    let mut old_bytes = vec![0u8; size];
    handle.file.read_exact(&mut old_bytes).expect("read");
    let saved_offset = disk_offset;

    vault_delete(&mut handle, "secret.txt".into()).expect("delete");

    // Same region should now contain different bytes (CSPRNG overwrite)
    handle
        .file
        .seek(SeekFrom::Start(saved_offset))
        .expect("seek");
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
        vault_create(path.clone(), test_key(), "aes-256-gcm".into(), 1_048_576).expect("create");

    let result = vault_open(path, test_key());
    assert!(matches!(result, Err(CryptoError::VaultLocked)));
}

// -- Persistence across close/open --------------------------------------

#[test]
fn test_write_close_open_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);

    {
        let mut handle = vault_create(
            path.clone(),
            test_key(),
            "chacha20-poly1305".into(),
            1_048_576,
        )
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
        let mut handle = vault_create(path.clone(), test_key(), "aes-256-gcm".into(), 1_048_576)
            .expect("create");
        vault_write(&mut handle, "doc.txt".into(), b"shadow test".to_vec(), None).expect("write");
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

// -- Resize -------------------------------------------------------------
const SIZE_MB: u64 = 0x100000;

#[test]
fn test_resize_grow_then_write_in_new_space() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, SIZE_MB);

    // Fill most of the original 1MB capacity
    let filler = vec![0xAA; 900_000];
    vault_write(&mut handle, "filler.bin".into(), filler.clone(), None).expect("write filler");

    // Grow to 2MB
    vault_resize(&mut handle, 2 * SIZE_MB).expect("grow to 2MB");

    // Write a segment that requires space in the new region
    let big = vec![0xBB; 900_000];
    vault_write(&mut handle, "big.bin".into(), big.clone(), None).expect("write in new space");

    // Read both back
    let filler_read = vault_read(&mut handle, "filler.bin".into()).expect("read filler");
    assert_eq!(filler_read, filler);
    let big_read = vault_read(&mut handle, "big.bin".into()).expect("read big");
    assert_eq!(big_read, big);

    vault_close(handle).expect("close");
}

#[test]
fn test_resize_shrink_after_consolidation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);

    // Create a 2MB vault and write ~500KB of data.
    {
        let mut handle = vault_create(path.clone(), test_key(), "aes-256-gcm".into(), 2 * SIZE_MB)
            .expect("create 2MB");
        let data = vec![0xCC; 500_000];
        vault_write(&mut handle, "doc.bin".into(), data, None).expect("write 500KB");
        vault_close(handle).expect("close");
    }

    // Reopen, shrink to 1MB. Data is at the beginning so it should fit.
    {
        let mut handle = vault_open(path.clone(), test_key()).expect("reopen");
        vault_resize(&mut handle, SIZE_MB).expect("shrink to 1MB");

        // Verify all data is still readable.
        let data = vault_read(&mut handle, "doc.bin".into()).expect("read after shrink");
        assert_eq!(data, vec![0xCC; 500_000]);

        // Verify capacity reflects the new size.
        let cap = vault_capacity(&handle);
        assert_eq!(cap.total_bytes, SIZE_MB);

        vault_close(handle).expect("close");
    }

    // Reopen again to confirm persistence across close/open.
    {
        let mut handle = vault_open(path, test_key()).expect("reopen again");
        let data = vault_read(&mut handle, "doc.bin".into()).expect("read persisted");
        assert_eq!(data, vec![0xCC; 500_000]);
        vault_close(handle).expect("close");
    }
}

#[test]
fn test_resize_shrink_below_used_space_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, SIZE_MB);

    // Write enough data so that shrinking below used space is impossible.
    vault_write(&mut handle, "a.bin".into(), vec![0xDD; 600_000], None).expect("write");

    // Attempt to shrink to 256KB — should fail with VaultFull.
    let result = vault_resize(&mut handle, 256 * 1024);
    assert!(
        matches!(result, Err(CryptoError::VaultFull { .. })),
        "expected VaultFull, got: {result:?}"
    );

    // Vault should still be usable after failed shrink.
    let data = vault_read(&mut handle, "a.bin".into()).expect("read after failed shrink");
    assert_eq!(data, vec![0xDD; 600_000]);

    vault_close(handle).expect("close");
}

#[test]
fn test_resize_grow_updates_capacity() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);

    {
        let mut handle =
            vault_create(path.clone(), test_key(), "aes-256-gcm".into(), SIZE_MB).expect("create");

        let cap_before = vault_capacity(&handle);
        assert_eq!(cap_before.total_bytes, SIZE_MB);

        vault_resize(&mut handle, 2 * SIZE_MB).expect("grow");

        let cap_after = vault_capacity(&handle);
        assert_eq!(cap_after.total_bytes, 2 * SIZE_MB);
        // Unallocated should have grown by ~1MB.
        assert!(cap_after.unallocated_bytes > cap_before.unallocated_bytes);

        vault_close(handle).expect("close");
    }

    // Verify persistence: reopen and check capacity.
    {
        let handle = vault_open(path, test_key()).expect("reopen");
        let cap = vault_capacity(&handle);
        assert_eq!(cap.total_bytes, 2 * SIZE_MB);
        vault_close(handle).expect("close");
    }
}

#[test]
fn test_resize_grow_crash_recovery() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);

    // Create vault with one segment.
    {
        let mut handle =
            vault_create(path.clone(), test_key(), "aes-256-gcm".into(), SIZE_MB).expect("create");
        vault_write(&mut handle, "a.txt".into(), b"before grow".to_vec(), None).expect("write A");
        vault_close(handle).expect("close");
    }

    // Save the "good" encrypted index (1MB capacity, contains A).
    let good_encrypted = {
        let mut f = File::open(&path).expect("open");
        read_encrypted_index(&mut f, PRIMARY_INDEX_OFFSET, encrypted_index_size(MIN_INDEX_PAD_SIZE)).expect("read index")
    };

    // Perform a real grow to 2MB.
    {
        let mut handle = vault_open(path.clone(), test_key()).expect("open");
        vault_resize(&mut handle, 2 * SIZE_MB).expect("grow");
        vault_write(&mut handle, "b.txt".into(), b"after grow".to_vec(), None).expect("write B");
        vault_close(handle).expect("close");
    }

    // Simulate crash: write an uncommitted WAL entry that restores the
    // pre-grow index (1MB capacity, only A). This simulates a crash
    // that occurred mid-grow before commit.
    {
        let mut wal = WriteAheadLog::open(&path).expect("wal");
        wal.begin(WalOp::UpdateIndex, &good_encrypted)
            .expect("begin");
        // Don't commit — simulates crash.
    }

    // Reopen — WAL recovery should roll back to the A-only / 1MB index.
    let mut handle = vault_open(path, test_key()).expect("open after recovery");

    // A should be readable.
    let data = vault_read(&mut handle, "a.txt".into()).expect("read A");
    assert_eq!(data, b"before grow");

    // B should NOT be in the recovered index.
    let result = vault_read(&mut handle, "b.txt".into());
    assert!(matches!(result, Err(CryptoError::SegmentNotFound(_))));

    vault_close(handle).expect("close");
}

#[test]
fn test_resize_same_capacity_is_noop() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, SIZE_MB);

    vault_write(&mut handle, "a.txt".into(), b"hello".to_vec(), None).expect("write");
    let cap_before = vault_capacity(&handle);

    // Resize to same capacity — should return Ok without I/O
    vault_resize(&mut handle, SIZE_MB).expect("noop resize");

    let cap_after = vault_capacity(&handle);
    assert_eq!(cap_before.total_bytes, cap_after.total_bytes);
    assert_eq!(cap_before.used_bytes, cap_after.used_bytes);

    let data = vault_read(&mut handle, "a.txt".into()).expect("read");
    assert_eq!(data, b"hello");

    vault_close(handle).expect("close");
}

#[test]
fn test_resize_shrink_after_defrag_reclaims_max_space() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 2 * SIZE_MB);

    // Write three segments, delete the first two to create gaps
    vault_write(&mut handle, "a.bin".into(), vec![0xAA; 200_000], None).expect("A");
    vault_write(&mut handle, "b.bin".into(), vec![0xBB; 200_000], None).expect("B");
    vault_write(&mut handle, "keep.bin".into(), vec![0xCC; 100_000], None).expect("keep");

    vault_delete(&mut handle, "a.bin".into()).expect("del A");
    vault_delete(&mut handle, "b.bin".into()).expect("del B");

    // Before defrag: free regions exist, shrink is limited
    assert!(handle.index.needs_defrag());

    // Defrag compacts keep.bin to offset 0
    vault_defragment(&mut handle).expect("defrag");
    assert!(!handle.index.needs_defrag());

    // After defrag: used space is only keep.bin's encrypted size
    let used = handle.index.used_bytes();
    assert!(used < 200_000, "used {used} should be less than 200KB");

    // Shrink to just above used space (round up to 256KB boundary)
    let new_cap = ((used / (256 * 1024)) + 1) * (256 * 1024);
    vault_resize(&mut handle, new_cap).expect("shrink after defrag");

    let cap = vault_capacity(&handle);
    assert_eq!(cap.total_bytes, new_cap);

    // Data intact after shrink
    let data = vault_read(&mut handle, "keep.bin".into()).expect("read keep");
    assert_eq!(data, vec![0xCC; 100_000]);

    vault_close(handle).expect("close");
}

#[test]
fn test_resize_grow_crash_midway_recovers() {
    use crate::core::evfs::segment;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);

    // Create vault and write a segment.
    let good_encrypted;
    {
        let mut handle =
            vault_create(path.clone(), test_key(), "aes-256-gcm".into(), SIZE_MB).expect("create");
        vault_write(&mut handle, "a.txt".into(), b"safe data".to_vec(), None).expect("write A");
        vault_close(handle).expect("close");
    }

    // Capture the good encrypted index before simulating a partial grow.
    {
        let mut f = File::open(&path).expect("open");
        good_encrypted = read_encrypted_index(&mut f, PRIMARY_INDEX_OFFSET, encrypted_index_size(MIN_INDEX_PAD_SIZE)).expect("read idx");
    }

    // Simulate a crash mid-grow: extend the file and CSPRNG-fill
    // (destroying the old shadow), but leave an uncommitted WAL entry.
    {
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open rw");
        let new_total = format::total_vault_size(2 * SIZE_MB, MIN_INDEX_PAD_SIZE).expect("size");
        f.set_len(new_total).expect("extend");
        // CSPRNG-fill overwrites old shadow position at format::data_region_offset(MIN_INDEX_PAD_SIZE) + SIZE_MB
        segment::secure_erase_region(&mut f, format::data_region_offset(MIN_INDEX_PAD_SIZE) + SIZE_MB, SIZE_MB).expect("fill");

        let mut wal = WriteAheadLog::open(&path).expect("wal");
        wal.begin(WalOp::UpdateIndex, &good_encrypted)
            .expect("begin");
        // Don't commit — simulates crash
    }

    // Reopen — recovery should restore 1MB index, fix file size, fix shadow
    let mut handle = vault_open(path.clone(), test_key()).expect("open after crash");

    // Capacity should be restored to 1MB
    assert_eq!(vault_capacity(&handle).total_bytes, SIZE_MB);

    // File size should match restored capacity
    let actual_size = handle.file.seek(SeekFrom::End(0)).expect("seek");
    let expected_size = format::total_vault_size(SIZE_MB, MIN_INDEX_PAD_SIZE).expect("size");
    assert_eq!(actual_size, expected_size);

    // Data intact
    let data = vault_read(&mut handle, "a.txt".into()).expect("read A");
    assert_eq!(data, b"safe data");

    // Vault usable after recovery — write + read works
    vault_write(&mut handle, "b.txt".into(), b"post recovery".to_vec(), None).expect("write B");
    let b_data = vault_read(&mut handle, "b.txt".into()).expect("read B");
    assert_eq!(b_data, b"post recovery");

    vault_close(handle).expect("close");
}

// -- Defragmentation ----------------------------------------------------

#[test]
fn test_defragment_basic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "a.txt".into(), vec![0xAA; 200], None).expect("A");
    vault_write(&mut handle, "b.txt".into(), vec![0xBB; 200], None).expect("B");
    vault_write(&mut handle, "c.txt".into(), vec![0xCC; 200], None).expect("C");

    let c_offset_before = handle.index.find("c.txt").expect("C").offset;

    // Delete B — creates free region between A and C
    vault_delete(&mut handle, "b.txt".into()).expect("del B");
    assert_eq!(handle.index.free_regions.len(), 1);

    let result = vault_defragment(&mut handle).expect("defrag");
    assert_eq!(result.segments_moved, 1); // C moved left
    assert_eq!(result.free_regions_before, 1);
    assert!(result.bytes_reclaimed > 0);

    // Free list should be empty, all free space is unallocated
    let cap = vault_capacity(&handle);
    assert_eq!(cap.free_list_bytes, 0);
    assert!(cap.unallocated_bytes > 0);
    assert_eq!(cap.segment_count, 2);

    // next_free_offset == sum of all segment sizes
    let total_used: u64 = handle.index.entries.iter().map(|e| e.size).sum();
    assert_eq!(handle.index.next_free_offset, total_used);
    assert_eq!(handle.index.free_regions.len(), 0);

    // C moved left
    let c_offset_after = handle.index.find("c.txt").expect("C").offset;
    assert!(c_offset_after < c_offset_before);

    // Data integrity preserved
    assert_eq!(
        vault_read(&mut handle, "a.txt".into()).expect("read A"),
        vec![0xAA; 200]
    );
    assert_eq!(
        vault_read(&mut handle, "c.txt".into()).expect("read C"),
        vec![0xCC; 200]
    );

    vault_close(handle).expect("close");
}

#[test]
fn test_defragment_multiple_gaps() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "a.txt".into(), vec![0xAA; 100], None).expect("A");
    vault_write(&mut handle, "b.txt".into(), vec![0xBB; 100], None).expect("B");
    vault_write(&mut handle, "c.txt".into(), vec![0xCC; 100], None).expect("C");
    vault_write(&mut handle, "d.txt".into(), vec![0xDD; 100], None).expect("D");
    vault_write(&mut handle, "e.txt".into(), vec![0xEE; 100], None).expect("E");

    // Delete B and D — two gaps
    vault_delete(&mut handle, "b.txt".into()).expect("del B");
    vault_delete(&mut handle, "d.txt".into()).expect("del D");
    assert_eq!(handle.index.free_regions.len(), 2);

    let result = vault_defragment(&mut handle).expect("defrag");
    assert_eq!(result.segments_moved, 2); // C and E moved
    assert_eq!(result.free_regions_before, 2);

    // All surviving segments readable
    assert_eq!(
        vault_read(&mut handle, "a.txt".into()).expect("A"),
        vec![0xAA; 100]
    );
    assert_eq!(
        vault_read(&mut handle, "c.txt".into()).expect("C"),
        vec![0xCC; 100]
    );
    assert_eq!(
        vault_read(&mut handle, "e.txt".into()).expect("E"),
        vec![0xEE; 100]
    );

    assert_eq!(vault_capacity(&handle).free_list_bytes, 0);
    vault_close(handle).expect("close");
}

#[test]
fn test_defragment_already_compact() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "a.txt".into(), vec![0xAA; 100], None).expect("A");
    vault_write(&mut handle, "b.txt".into(), vec![0xBB; 100], None).expect("B");
    vault_write(&mut handle, "c.txt".into(), vec![0xCC; 100], None).expect("C");

    let result = vault_defragment(&mut handle).expect("defrag");
    assert_eq!(result.segments_moved, 0);
    assert_eq!(result.bytes_reclaimed, 0);
    assert_eq!(result.free_regions_before, 0);

    // All segments still readable
    assert_eq!(
        vault_read(&mut handle, "a.txt".into()).expect("A"),
        vec![0xAA; 100]
    );
    assert_eq!(
        vault_read(&mut handle, "b.txt".into()).expect("B"),
        vec![0xBB; 100]
    );
    assert_eq!(
        vault_read(&mut handle, "c.txt".into()).expect("C"),
        vec![0xCC; 100]
    );

    vault_close(handle).expect("close");
}

#[test]
fn test_defragment_empty_vault() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    let result = vault_defragment(&mut handle).expect("defrag");
    assert_eq!(result.segments_moved, 0);
    assert_eq!(result.bytes_reclaimed, 0);
    assert_eq!(result.free_regions_before, 0);

    vault_close(handle).expect("close");
}

#[test]
fn test_defragment_single_segment_at_gap() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "a.txt".into(), vec![0xAA; 200], None).expect("A");
    vault_write(&mut handle, "b.txt".into(), vec![0xBB; 200], None).expect("B");

    // Delete A — gap at start, B remains at higher offset
    vault_delete(&mut handle, "a.txt".into()).expect("del A");

    let result = vault_defragment(&mut handle).expect("defrag");
    assert_eq!(result.segments_moved, 1);
    assert_eq!(result.free_regions_before, 1);

    // B moved to offset 0
    assert_eq!(handle.index.find("b.txt").expect("B").offset, 0);
    assert_eq!(
        vault_read(&mut handle, "b.txt".into()).expect("read B"),
        vec![0xBB; 200]
    );

    vault_close(handle).expect("close");
}

#[test]
fn test_defragment_crash_recovery() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);

    // Create vault with A, B, C. Delete B to create a gap.
    {
        let mut handle = vault_create(path.clone(), test_key(), "aes-256-gcm".into(), 1_048_576)
            .expect("create");
        vault_write(&mut handle, "a.txt".into(), vec![0xAA; 100], None).expect("A");
        vault_write(&mut handle, "b.txt".into(), vec![0xBB; 100], None).expect("B");
        vault_write(&mut handle, "c.txt".into(), vec![0xCC; 100], None).expect("C");
        vault_delete(&mut handle, "b.txt".into()).expect("del B");
        vault_close(handle).expect("close");
    }

    // Save pre-defrag encrypted index (the "good" state)
    let pre_defrag_index = {
        let mut f = File::open(&path).expect("open");
        read_encrypted_index(&mut f, PRIMARY_INDEX_OFFSET, encrypted_index_size(MIN_INDEX_PAD_SIZE)).expect("read index")
    };

    // Simulate crash mid-defrag: write uncommitted WAL entry
    {
        let mut wal = WriteAheadLog::open(&path).expect("wal");
        wal.begin(WalOp::WriteSegment, &pre_defrag_index)
            .expect("begin");
        // Don't commit — simulates crash during defrag
    }

    // Reopen — WAL recovery should restore pre-defrag index
    let mut handle = vault_open(path, test_key()).expect("open after crash");

    // C should still be at its original (pre-defrag) offset, readable
    assert_eq!(
        vault_read(&mut handle, "c.txt".into()).expect("read C"),
        vec![0xCC; 100]
    );
    assert_eq!(
        vault_read(&mut handle, "a.txt".into()).expect("read A"),
        vec![0xAA; 100]
    );

    // Free region from deleted B should still exist
    assert!(!handle.index.free_regions.is_empty());

    // Now run actual defrag — should succeed normally
    let result = vault_defragment(&mut handle).expect("defrag");
    assert!(result.segments_moved > 0);

    assert_eq!(
        vault_read(&mut handle, "a.txt".into()).expect("A"),
        vec![0xAA; 100]
    );
    assert_eq!(
        vault_read(&mut handle, "c.txt".into()).expect("C"),
        vec![0xCC; 100]
    );

    vault_close(handle).expect("close");
}

#[test]
fn test_defragment_crash_overlapping_move_recovers() {
    // Exercises the overlapping-move crash path: segment B is larger than
    // the gap created by deleting A, so moving B left overwrites part of
    // B's old position. A crash before WAL commit should still recover.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);

    // Create: [A: 100B] [B: 10KB] — deleting A creates a small gap
    // so B's move from offset(A.size) to 0 overlaps.
    {
        let mut handle =
            vault_create(path.clone(), test_key(), "aes-256-gcm".into(), SIZE_MB).expect("create");
        vault_write(&mut handle, "a.txt".into(), vec![0xAA; 100], None).expect("A");
        vault_write(&mut handle, "b.txt".into(), vec![0xBB; 10_000], None).expect("B");
        vault_delete(&mut handle, "a.txt".into()).expect("del A");
        vault_close(handle).expect("close");
    }

    // Save pre-defrag index and get B's offset/size
    let (pre_defrag_index, b_old_offset, b_size) = {
        let handle = vault_open(path.clone(), test_key()).expect("open");
        let mut f = File::open(&path).expect("open file");
        let idx = read_encrypted_index(&mut f, PRIMARY_INDEX_OFFSET, encrypted_index_size(MIN_INDEX_PAD_SIZE)).expect("read idx");
        let entry = handle.index.find("b.txt").expect("B");
        let off = entry.offset;
        let sz = entry.size;
        vault_close(handle).expect("close");
        (idx, off, sz)
    };

    // Verify this IS an overlapping move: gap < size
    assert!(b_old_offset < b_size, "should be overlapping move");

    // Simulate crash mid-defrag: perform the overlapping write but don't commit WAL
    {
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open rw");

        // Read B from old position
        let mut buf = vec![0u8; b_size as usize];
        f.seek(SeekFrom::Start(format::data_region_offset(MIN_INDEX_PAD_SIZE) + b_old_offset))
            .expect("seek");
        f.read_exact(&mut buf).expect("read B");

        // Write defrag backup (simulating what vault_defragment does)
        let backup_path = format!("{path}.defrag");
        let mut backup = File::create(&backup_path).expect("create backup");
        backup.write_all(&b_old_offset.to_le_bytes()).expect("off");
        backup.write_all(&b_size.to_le_bytes()).expect("sz");
        backup.write_all(&buf).expect("data");
        backup.sync_all().expect("sync backup");

        // Write B to new position (offset 0) — corrupts overlap zone
        f.seek(SeekFrom::Start(format::data_region_offset(MIN_INDEX_PAD_SIZE))).expect("seek 0");
        f.write_all(&buf).expect("write B to 0");
        f.sync_all().expect("sync");

        // Write uncommitted WAL entry
        let mut wal = WriteAheadLog::open(&path).expect("wal");
        wal.begin(WalOp::WriteSegment, &pre_defrag_index)
            .expect("begin");
        // Don't commit — crash
    }

    // Reopen — defrag backup + WAL recovery should restore to consistent state
    let mut handle = vault_open(path, test_key()).expect("open after crash");

    // B should be readable at old position (overlap zone restored)
    let b_data = vault_read(&mut handle, "b.txt".into()).expect("read B");
    assert_eq!(b_data, vec![0xBB; 10_000]);

    // Defrag should still work after recovery
    let result = vault_defragment(&mut handle).expect("defrag after recovery");
    assert!(result.segments_moved > 0);
    let b_data = vault_read(&mut handle, "b.txt".into()).expect("read B post-defrag");
    assert_eq!(b_data, vec![0xBB; 10_000]);

    vault_close(handle).expect("close");
}

#[test]
fn test_defragment_preserves_compression() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    let zstd_data = b"zstd compressible data ".repeat(50);
    let raw_data = b"raw segment no compression".to_vec();

    let zstd_conf = CompressionConfig {
        algorithm: CompressionAlgorithm::Zstd,
        level: None,
    };
    vault_write(
        &mut handle,
        "text.txt".into(),
        zstd_data.clone(),
        Some(zstd_conf),
    )
    .expect("zstd");
    vault_write(&mut handle, "spacer.bin".into(), vec![0xFF; 300], None).expect("spacer");
    vault_write(&mut handle, "raw.dat".into(), raw_data.clone(), None).expect("raw");

    // Delete spacer — gap between text.txt and raw.dat
    vault_delete(&mut handle, "spacer.bin".into()).expect("del spacer");

    let result = vault_defragment(&mut handle).expect("defrag");
    assert_eq!(result.segments_moved, 1); // raw.dat moved

    // Compression metadata preserved
    let text_entry = handle.index.find("text.txt").expect("text");
    assert_eq!(text_entry.compression, CompressionAlgorithm::Zstd);
    let raw_entry = handle.index.find("raw.dat").expect("raw");
    assert_eq!(raw_entry.compression, CompressionAlgorithm::None);

    // Data integrity — decompression works after defrag
    assert_eq!(
        vault_read(&mut handle, "text.txt".into()).expect("text"),
        zstd_data
    );
    assert_eq!(
        vault_read(&mut handle, "raw.dat".into()).expect("raw"),
        raw_data
    );

    vault_close(handle).expect("close");
}

#[test]
fn test_defragment_preserves_generation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "a.txt".into(), vec![0xAA; 100], None).expect("A");
    // Overwrite A to bump its generation
    vault_write(&mut handle, "a.txt".into(), vec![0xAA; 100], None).expect("A v2");
    vault_write(&mut handle, "b.txt".into(), vec![0xBB; 100], None).expect("B");

    let b_gen_before = handle.index.find("b.txt").expect("B").generation;

    // Delete A — B needs to move
    vault_delete(&mut handle, "a.txt".into()).expect("del A");

    let result = vault_defragment(&mut handle).expect("defrag");
    assert_eq!(result.segments_moved, 1);

    // Generation unchanged
    let b_gen_after = handle.index.find("b.txt").expect("B").generation;
    assert_eq!(b_gen_before, b_gen_after);

    // Nonce derivation still works (read succeeds)
    assert_eq!(
        vault_read(&mut handle, "b.txt".into()).expect("read B"),
        vec![0xBB; 100]
    );

    vault_close(handle).expect("close");
}

#[test]
fn test_defragment_large_gap_at_start() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "a.txt".into(), vec![0xAA; 300], None).expect("A");
    vault_write(&mut handle, "b.txt".into(), vec![0xBB; 300], None).expect("B");
    vault_write(&mut handle, "c.txt".into(), vec![0xCC; 300], None).expect("C");

    let ab_size =
        handle.index.find("a.txt").expect("A").size + handle.index.find("b.txt").expect("B").size;

    // Delete A and B — large gap at start, C alone at end
    vault_delete(&mut handle, "a.txt".into()).expect("del A");
    vault_delete(&mut handle, "b.txt".into()).expect("del B");

    let result = vault_defragment(&mut handle).expect("defrag");
    assert_eq!(result.segments_moved, 1); // C moved to 0
    assert_eq!(result.bytes_reclaimed, ab_size);

    assert_eq!(handle.index.find("c.txt").expect("C").offset, 0);
    assert_eq!(
        vault_read(&mut handle, "c.txt".into()).expect("C"),
        vec![0xCC; 300]
    );
    assert_eq!(vault_capacity(&handle).free_list_bytes, 0);

    vault_close(handle).expect("close");
}

#[test]
fn test_defragment_write_after_defrag() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "a.txt".into(), vec![0xAA; 200], None).expect("A");
    vault_write(&mut handle, "b.txt".into(), vec![0xBB; 200], None).expect("B");
    vault_write(&mut handle, "c.txt".into(), vec![0xCC; 200], None).expect("C");

    vault_delete(&mut handle, "b.txt".into()).expect("del B");
    vault_defragment(&mut handle).expect("defrag");

    // Allocator should work: new writes go after the packed segments
    vault_write(&mut handle, "d.txt".into(), vec![0xDD; 500], None).expect("D after defrag");

    // All segments readable
    assert_eq!(
        vault_read(&mut handle, "a.txt".into()).expect("A"),
        vec![0xAA; 200]
    );
    assert_eq!(
        vault_read(&mut handle, "c.txt".into()).expect("C"),
        vec![0xCC; 200]
    );
    assert_eq!(
        vault_read(&mut handle, "d.txt".into()).expect("D"),
        vec![0xDD; 500]
    );

    // D should be allocated at the end (after A and C)
    let a_end =
        handle.index.find("a.txt").expect("A").offset + handle.index.find("a.txt").expect("A").size;
    let c_end =
        handle.index.find("c.txt").expect("C").offset + handle.index.find("c.txt").expect("C").size;
    let d_offset = handle.index.find("d.txt").expect("D").offset;
    let packed_end = std::cmp::max(a_end, c_end);
    assert!(d_offset >= packed_end);

    vault_close(handle).expect("close");
}

#[test]
fn test_defragment_ten_segments_delete_odd() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    // Write 10 segments (1KB each)
    for i in 0..10 {
        let name = format!("seg{i}.bin");
        let data = vec![(i as u8) | 0x10; 1024];
        vault_write(&mut handle, name, data, None).expect("write");
    }

    // Delete odd-numbered segments (1, 3, 5, 7, 9) — 5 gaps
    for i in (1..10).step_by(2) {
        let name = format!("seg{i}.bin");
        vault_delete(&mut handle, name).expect("delete");
    }
    assert_eq!(handle.index.entries.len(), 5);
    assert!(!handle.index.free_regions.is_empty());

    let result = vault_defragment(&mut handle).expect("defrag");

    // 4 of 5 even segments need to move (seg0 stays at 0)
    assert_eq!(result.segments_moved, 4);
    assert_eq!(handle.index.free_regions.len(), 0);

    // next_free_offset == sum of all segment sizes
    let total_used: u64 = handle.index.entries.iter().map(|e| e.size).sum();
    assert_eq!(handle.index.next_free_offset, total_used);

    // Segments are contiguous: sorted offsets form a gapless sequence
    let mut offsets: Vec<(u64, u64)> = handle
        .index
        .entries
        .iter()
        .map(|e| (e.offset, e.size))
        .collect();
    offsets.sort_by_key(|&(off, _)| off);
    assert_eq!(offsets[0].0, 0);
    for w in offsets.windows(2) {
        assert_eq!(w[0].0 + w[0].1, w[1].0, "gap between segments");
    }

    // All 5 surviving segments readable with correct data
    for i in (0..10).step_by(2) {
        let name = format!("seg{i}.bin");
        let expected = vec![(i as u8) | 0x10; 1024];
        let data = vault_read(&mut handle, name).expect("read");
        assert_eq!(data, expected);
    }

    vault_close(handle).expect("close");
}

#[test]
fn test_vault_health_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let handle = create_test_vault(&dir, 1_048_576);

    let h = vault_health(&handle);
    assert_eq!(h.segment_count, 0);
    assert_eq!(h.free_region_count, 0);
    assert_eq!(h.fragmentation_ratio, 0.0);
    assert_eq!(h.total_bytes, handle.index.capacity);
    assert_eq!(h.used_bytes, 0);
    assert_eq!(h.unallocated_bytes, handle.index.capacity);
}

#[test]
fn test_vault_health_after_write_delete_and_defrag() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "a".into(), vec![0xAA; 200], None).expect("A");
    vault_write(&mut handle, "b".into(), vec![0xBB; 500], None).expect("B");
    vault_write(&mut handle, "c".into(), vec![0xCC; 300], None).expect("C");

    let before = vault_health(&handle);
    assert!(before.used_bytes > 0);
    assert_eq!(
        before.unallocated_bytes + before.free_list_bytes + before.used_bytes,
        handle.index.capacity
    );

    vault_delete(&mut handle, "b".into()).expect("delete B");

    let after_delete = vault_health(&handle);
    assert_eq!(after_delete.free_region_count, 1);
    assert!(after_delete.fragmentation_ratio > 0.0);
    assert!(after_delete.largest_free_block > 0);
    assert_eq!(
        after_delete.used_bytes + after_delete.free_list_bytes + after_delete.unallocated_bytes,
        handle.index.capacity
    );

    vault_defragment(&mut handle).expect("defrag");

    let after_defrag = vault_health(&handle);
    assert_eq!(after_defrag.free_region_count, 0);
    assert_eq!(after_defrag.fragmentation_ratio, 0.0);
    assert_eq!(after_defrag.largest_free_block, after_defrag.unallocated_bytes);
    assert_eq!(
        after_defrag.used_bytes + after_defrag.free_list_bytes + after_defrag.unallocated_bytes,
        handle.index.capacity
    );
}

#[test]
fn test_largest_free_block_accounts_for_tail() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1024u64);

    vault_write(&mut handle, "s".into(), vec![0xAA; 100], None).expect("write");

    let h = vault_health(&handle);
    let free_list_max = handle
        .index
        .free_regions
        .iter()
        .map(|r| r.size)
        .max()
        .unwrap_or(0);
    let tail = handle
        .index
        .capacity
        .saturating_sub(handle.index.next_free_offset);

    assert_eq!(h.largest_free_block, std::cmp::max(free_list_max, tail));
}

#[test]
fn test_vault_health_full_capacity() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    // Fill vault until full
    let mut i = 0;
    loop {
        let name = format!("seg_{i}");
        if vault_write(&mut handle, name, vec![0xAA; 8192], None).is_err() {
            break;
        }
        i += 1;
    }

    let h = vault_health(&handle);
    assert_eq!(h.free_region_count, 0);
    assert_eq!(h.fragmentation_ratio, 0.0);
    assert_eq!(h.used_bytes + h.free_list_bytes + h.unallocated_bytes, h.total_bytes);
}
