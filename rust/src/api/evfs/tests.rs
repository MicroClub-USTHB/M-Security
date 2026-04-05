use super::*;
use crate::core::evfs::format::{encrypted_index_size, MIN_INDEX_PAD_SIZE};

fn test_key() -> Vec<u8> {
    vec![0xAA; 32]
}

fn test_key2() -> Vec<u8> {
    vec![0xAB; 32]
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
        read_encrypted_index(
            &mut f,
            PRIMARY_INDEX_OFFSET,
            encrypted_index_size(MIN_INDEX_PAD_SIZE),
        )
        .expect("read index")
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
        read_encrypted_index(
            &mut f,
            PRIMARY_INDEX_OFFSET,
            encrypted_index_size(MIN_INDEX_PAD_SIZE),
        )
        .expect("read index")
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
        good_encrypted = read_encrypted_index(
            &mut f,
            PRIMARY_INDEX_OFFSET,
            encrypted_index_size(MIN_INDEX_PAD_SIZE),
        )
        .expect("read idx");
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
        segment::secure_erase_region(
            &mut f,
            format::data_region_offset(MIN_INDEX_PAD_SIZE) + SIZE_MB,
            SIZE_MB,
        )
        .expect("fill");

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
        read_encrypted_index(
            &mut f,
            PRIMARY_INDEX_OFFSET,
            encrypted_index_size(MIN_INDEX_PAD_SIZE),
        )
        .expect("read index")
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
        let idx = read_encrypted_index(
            &mut f,
            PRIMARY_INDEX_OFFSET,
            encrypted_index_size(MIN_INDEX_PAD_SIZE),
        )
        .expect("read idx");
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
        f.seek(SeekFrom::Start(
            format::data_region_offset(MIN_INDEX_PAD_SIZE) + b_old_offset,
        ))
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
        f.seek(SeekFrom::Start(format::data_region_offset(
            MIN_INDEX_PAD_SIZE,
        )))
        .expect("seek 0");
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
    assert_eq!(
        after_defrag.largest_free_block,
        after_defrag.unallocated_bytes
    );
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
    assert_eq!(
        h.used_bytes + h.free_list_bytes + h.unallocated_bytes,
        h.total_bytes
    );
}

// -- Streaming Read & Interop Tests -------------------------------------
#[test]
fn test_oneshot_write_oneshot_read_interop() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    let data = b"monolithic data".to_vec();
    vault_write(&mut handle, "mono.txt".into(), data.clone(), None).expect("write");

    let entry = handle.index.find("mono.txt").expect("find");
    assert_eq!(entry.chunk_count, 0, "Should be written as monolithic");

    let read_back = vault_read(&mut handle, "mono.txt".into()).expect("read");
    assert_eq!(read_back, data);

    vault_close(handle).expect("close");
}

#[test]
fn test_stream_write_oneshot_read_matches_interop() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 5_000_000);

    let chunk_size = crate::core::streaming::CHUNK_SIZE;
    // 3 full chunks, 1 partial padded chunk
    let data = vec![0x77; chunk_size * 3 + 1234];

    // Write using stream
    let chunks: Vec<Vec<u8>> = data.chunks(chunk_size).map(|c| c.to_vec()).collect();
    vault_write_stream(
        &mut handle,
        "streamed.bin".into(),
        data.len() as u64,
        chunks.into_iter(),
    )
    .expect("stream write");

    let entry = handle.index.find("streamed.bin").expect("find");
    assert!(entry.chunk_count > 0, "Should be written as chunked");

    // Read using one-shot (interop) testing the chunk-assembly loop
    let read_back = vault_read(&mut handle, "streamed.bin".into()).expect("read");
    assert_eq!(read_back, data, "Data should match byte-for-byte");

    vault_close(handle).expect("close");
}

#[test]
fn test_tamper_with_chunk_detected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    let chunk_size = crate::core::streaming::CHUNK_SIZE;
    let data = vec![0xAA; chunk_size * 2];

    let chunks = vec![data[..chunk_size].to_vec(), data[chunk_size..].to_vec()];
    vault_write_stream(
        &mut handle,
        "streamed.txt".into(),
        data.len() as u64,
        chunks.into_iter(),
    )
    .expect("stream write");

    let entry = handle.index.find("streamed.txt").expect("find");
    let disk_offset =
        crate::core::evfs::format::data_region_offset(handle.index_pad_size) + entry.offset;

    // Seek past nonce (12 bytes) and flip a ciphertext byte in the first chunk
    handle
        .file
        .seek(SeekFrom::Start(disk_offset + 13))
        .expect("seek");
    handle.file.write_all(&[0xFF]).expect("tamper");
    handle.file.sync_all().expect("sync");

    let result = vault_read(&mut handle, "streamed.txt".into());
    assert!(
        matches!(result, Err(CryptoError::AuthenticationFailed)),
        "Should detect chunk tampering via independent AEAD"
    );

    vault_close(handle).expect("close");
}

#[test]
fn test_reordered_chunks_detected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    let chunk_size = crate::core::streaming::CHUNK_SIZE;
    let enc_chunk_size = crate::core::streaming::ENCRYPTED_CHUNK_SIZE as u64;
    let data = vec![0xBB; chunk_size * 2];

    let chunks = vec![data[..chunk_size].to_vec(), data[chunk_size..].to_vec()];
    vault_write_stream(
        &mut handle,
        "reorder.bin".into(),
        data.len() as u64,
        chunks.into_iter(),
    )
    .expect("stream write");

    let entry = handle.index.find("reorder.bin").expect("find");
    let disk_offset =
        crate::core::evfs::format::data_region_offset(handle.index_pad_size) + entry.offset;

    // Read chunk 0 and chunk 1
    let mut c0 = vec![0u8; enc_chunk_size as usize];
    let mut c1 = vec![0u8; enc_chunk_size as usize];

    handle
        .file
        .seek(SeekFrom::Start(disk_offset))
        .expect("seek");
    handle.file.read_exact(&mut c0).expect("read c0");
    handle.file.read_exact(&mut c1).expect("read c1");

    // Swap them on disk
    handle
        .file
        .seek(SeekFrom::Start(disk_offset))
        .expect("seek");
    handle.file.write_all(&c1).expect("write c1");
    handle.file.write_all(&c0).expect("write c0");
    handle.file.sync_all().expect("sync");

    let result = vault_read(&mut handle, "reorder.bin".into());
    assert!(
        matches!(result, Err(CryptoError::AuthenticationFailed)),
        "Should detect chunk reordering due to index mismatch in AAD"
    );

    vault_close(handle).expect("close");
}

#[test]
fn test_integrity_checksum_failure_on_stream() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    let data = vec![0xCC; 1000];
    vault_write_stream(
        &mut handle,
        "checksum.bin".into(),
        data.len() as u64,
        vec![data].into_iter(),
    )
    .expect("write");

    // Manually corrupt the checksum stored in the Segment Index
    let entry = handle.index.find_mut("checksum.bin").expect("find");
    entry.checksum[0] ^= 0xFF;

    let result = vault_read(&mut handle, "checksum.bin".into());
    assert!(
        matches!(result, Err(CryptoError::VaultCorrupted(_))),
        "Should detect BLAKE3 checksum mismatch even if AEAD passes"
    );

    vault_close(handle).expect("close");
}

// -- Streaming Write --------------------------------------------------------

/// Helper: stream-write data in fixed-size pieces.
fn stream_write_chunks(
    handle: &mut VaultHandle,
    name: &str,
    data: &[u8],
    piece_size: usize,
) -> Result<(), CryptoError> {
    let chunks: Vec<Vec<u8>> = data.chunks(piece_size).map(|c| c.to_vec()).collect();
    vault_write_stream(
        handle,
        name.to_string(),
        data.len() as u64,
        chunks.into_iter(),
    )
}

#[test]
fn test_stream_write_read_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    // 2MB vault to fit the streaming overhead
    let mut handle = create_test_vault(&dir, 2 * 1024 * 1024);

    let data = vec![0x42u8; 200_000]; // ~3 chunks
    stream_write_chunks(&mut handle, "video.bin", &data, 4096).expect("stream write");

    let readback = vault_read(&mut handle, "video.bin".into()).expect("read");
    assert_eq!(readback, data);

    vault_close(handle).expect("close");
}

#[test]
fn test_stream_write_single_byte() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    let data = vec![0xAA; 1];
    stream_write_chunks(&mut handle, "tiny.bin", &data, 1).expect("stream write");

    let readback = vault_read(&mut handle, "tiny.bin".into()).expect("read");
    assert_eq!(readback, data);

    vault_close(handle).expect("close");
}

#[test]
fn test_stream_write_empty_segment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    // 0 bytes — still produces 1 padded chunk
    vault_write_stream(&mut handle, "empty.bin".into(), 0, std::iter::empty())
        .expect("stream write empty");

    let readback = vault_read(&mut handle, "empty.bin".into()).expect("read");
    assert!(readback.is_empty());

    vault_close(handle).expect("close");
}

#[test]
fn test_stream_write_exact_chunk_boundary() {
    use crate::core::streaming::CHUNK_SIZE;

    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 2 * 1024 * 1024);

    // Exactly CHUNK_SIZE bytes — triggers the extra empty padded chunk
    let data = vec![0xBB; CHUNK_SIZE];
    stream_write_chunks(&mut handle, "aligned.bin", &data, CHUNK_SIZE).expect("stream write");

    let readback = vault_read(&mut handle, "aligned.bin".into()).expect("read");
    assert_eq!(readback, data);

    // Verify chunk_count = 2 (1 full + 1 empty padded)
    let entry = handle.index.find("aligned.bin").expect("entry");
    assert_eq!(entry.chunk_count, 2);

    vault_close(handle).expect("close");
}

#[test]
fn test_stream_write_overwrite_existing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 2 * 1024 * 1024);

    // Write original (monolithic)
    vault_write(
        &mut handle,
        "doc.txt".into(),
        b"original data".to_vec(),
        None,
    )
    .expect("write");

    // Overwrite with streaming (larger)
    let new_data = vec![0xCC; 100_000];
    stream_write_chunks(&mut handle, "doc.txt", &new_data, 8192).expect("stream overwrite");

    let readback = vault_read(&mut handle, "doc.txt".into()).expect("read");
    assert_eq!(readback, new_data);

    // Verify it's now a streaming segment
    let entry = handle.index.find("doc.txt").expect("entry");
    assert!(entry.is_streaming());

    vault_close(handle).expect("close");
}

#[test]
fn test_stream_write_overwrite_with_smaller() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 2 * 1024 * 1024);

    // Write original (streaming, large)
    let original = vec![0xAA; 200_000];
    stream_write_chunks(&mut handle, "file.bin", &original, 4096).expect("write large");

    // Overwrite with smaller streaming segment
    let smaller = vec![0xBB; 1000];
    stream_write_chunks(&mut handle, "file.bin", &smaller, 500).expect("write small");

    let readback = vault_read(&mut handle, "file.bin".into()).expect("read");
    assert_eq!(readback, smaller);

    vault_close(handle).expect("close");
}

#[test]
fn test_stream_write_wrong_size_too_few_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    // Claim 1000 bytes but provide only 500
    let data = vec![0xAA; 500];
    let result = vault_write_stream(&mut handle, "bad.bin".into(), 1000, vec![data].into_iter());
    assert!(result.is_err());
    let err = result
        .expect_err("expected an error (underflow)")
        .to_string();
    assert!(err.contains("underflow"), "Expected underflow error: {err}");
}

#[test]
fn test_stream_write_wrong_size_too_many_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    // Claim 500 bytes but provide 1000
    let data = vec![0xAA; 1000];
    let result = vault_write_stream(&mut handle, "bad.bin".into(), 500, vec![data].into_iter());
    assert!(result.is_err());
    let err = result
        .expect_err("expected an error (exceeded)")
        .to_string();
    assert!(err.contains("exceeded"), "Expected exceeded error: {err}");
}

#[test]
fn test_stream_write_persist_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);

    let data = vec![0xDD; 150_000];
    {
        let mut handle = vault_create(
            path.clone(),
            test_key(),
            "aes-256-gcm".into(),
            2 * 1024 * 1024,
        )
        .expect("create");
        stream_write_chunks(&mut handle, "persist.bin", &data, 4096).expect("stream write");
        vault_close(handle).expect("close");
    }

    // Reopen and verify
    let mut handle = vault_open(path, test_key()).expect("open");
    let readback = vault_read(&mut handle, "persist.bin".into()).expect("read");
    assert_eq!(readback, data);

    vault_close(handle).expect("close");
}

#[test]
fn test_stream_write_chacha20() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir
        .path()
        .join("chacha.vault")
        .to_str()
        .expect("path")
        .to_string();
    let mut handle = vault_create(
        path,
        test_key(),
        "chacha20-poly1305".into(),
        2 * 1024 * 1024,
    )
    .expect("create");

    let data = vec![0xEE; 100_000];
    stream_write_chunks(&mut handle, "chacha.bin", &data, 8192).expect("stream write");

    let readback = vault_read(&mut handle, "chacha.bin".into()).expect("read");
    assert_eq!(readback, data);

    vault_close(handle).expect("close");
}

#[test]
fn test_stream_write_arbitrary_input_sizes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 2 * 1024 * 1024);

    // Provide data in irregular chunks (1, 7, 100, 50000, 3, ...)
    let total = 100_000usize;
    let data: Vec<u8> = (0..total).map(|i| (i % 256) as u8).collect();

    let pieces = vec![
        data[..1].to_vec(),
        data[1..8].to_vec(),
        data[8..108].to_vec(),
        data[108..50108].to_vec(),
        data[50108..50111].to_vec(),
        data[50111..].to_vec(),
    ];

    vault_write_stream(
        &mut handle,
        "irregular.bin".into(),
        total as u64,
        pieces.into_iter(),
    )
    .expect("stream write");

    let readback = vault_read(&mut handle, "irregular.bin".into()).expect("read");
    assert_eq!(readback, data);

    vault_close(handle).expect("close");
}

#[test]
fn test_stream_write_coexists_with_monolithic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 2 * 1024 * 1024);

    // Write monolithic
    vault_write(&mut handle, "mono.txt".into(), b"mono data".to_vec(), None).expect("write mono");

    // Write streaming
    let stream_data = vec![0xFF; 80_000];
    stream_write_chunks(&mut handle, "stream.bin", &stream_data, 4096).expect("stream write");

    // Read both back
    let mono = vault_read(&mut handle, "mono.txt".into()).expect("read mono");
    assert_eq!(mono, b"mono data");

    let stream = vault_read(&mut handle, "stream.bin".into()).expect("read stream");
    assert_eq!(stream, stream_data);

    // Verify types
    assert!(!handle
        .index
        .find("mono.txt")
        .expect("mono.txt missing")
        .is_streaming());
    assert!(handle
        .index
        .find("stream.bin")
        .expect("stream.bin missing")
        .is_streaming());

    vault_close(handle).expect("close");
}

// -- Streaming Read (via decrypt_streaming_chunks) --------------------------

/// Helper: stream-read all chunks into a Vec, returning (data, chunk_indices, checksum).
#[allow(clippy::type_complexity)]
fn stream_read_chunks(
    handle: &mut VaultHandle,
    name: &str,
) -> Result<(Vec<u8>, Vec<u32>, [u8; 32]), CryptoError> {
    let entry = handle
        .index
        .find(name)
        .ok_or_else(|| CryptoError::SegmentNotFound(name.into()))?;

    let seg_offset = entry.offset;
    let seg_gen = entry.generation;
    let seg_compression = entry.compression;
    let chunk_count = entry.chunk_count;

    let mut collected = Vec::new();
    let mut indices = Vec::new();

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
            collected.extend_from_slice(&data);
            indices.push(i);
            Ok(())
        },
    )?;

    Ok((collected, indices, checksum))
}

#[test]
fn test_stream_read_matches_oneshot_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 2 * 1024 * 1024);

    let data = vec![0x42u8; 200_000];
    stream_write_chunks(&mut handle, "video.bin", &data, 4096).expect("stream write");

    let oneshot = vault_read(&mut handle, "video.bin".into()).expect("oneshot read");
    let (streamed, _, _) = stream_read_chunks(&mut handle, "video.bin").expect("stream read");

    assert_eq!(
        streamed, oneshot,
        "streaming and one-shot must be byte-identical"
    );
    assert_eq!(streamed, data);

    vault_close(handle).expect("close");
}

#[test]
fn test_stream_read_checksum_matches_stored() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 2 * 1024 * 1024);

    let data = vec![0xAA; 150_000];
    stream_write_chunks(&mut handle, "file.bin", &data, 8192).expect("stream write");

    let stored_checksum = handle.index.find("file.bin").expect("find").checksum;
    let (_, _, computed_checksum) =
        stream_read_chunks(&mut handle, "file.bin").expect("stream read");

    assert_eq!(computed_checksum, stored_checksum);

    vault_close(handle).expect("close");
}

#[test]
fn test_stream_read_progress_indices() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 2 * 1024 * 1024);

    let chunk_size = crate::core::streaming::CHUNK_SIZE;
    let data = vec![0xBB; chunk_size * 3 + 1234];
    stream_write_chunks(&mut handle, "prog.bin", &data, chunk_size).expect("stream write");

    let chunk_count = handle.index.find("prog.bin").expect("find").chunk_count;
    let (collected, indices, _) = stream_read_chunks(&mut handle, "prog.bin").expect("stream read");

    assert_eq!(collected, data);
    assert_eq!(indices.len(), chunk_count as usize);
    let expected: Vec<u32> = (0..chunk_count).collect();
    assert_eq!(indices, expected);

    vault_close(handle).expect("close");
}

#[test]
fn test_stream_read_single_byte() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    let data = vec![0xCC; 1];
    stream_write_chunks(&mut handle, "tiny.bin", &data, 1).expect("stream write");

    let (collected, indices, _) = stream_read_chunks(&mut handle, "tiny.bin").expect("stream read");

    assert_eq!(collected, data);
    assert_eq!(indices.len(), 1);

    vault_close(handle).expect("close");
}

#[test]
fn test_stream_read_empty_segment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write_stream(&mut handle, "empty.bin".into(), 0, std::iter::empty())
        .expect("stream write empty");

    let (collected, indices, _) =
        stream_read_chunks(&mut handle, "empty.bin").expect("stream read");

    assert!(collected.is_empty());
    assert_eq!(indices.len(), 1);

    vault_close(handle).expect("close");
}

#[test]
fn test_stream_read_exact_chunk_boundary() {
    use crate::core::streaming::CHUNK_SIZE;

    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 2 * 1024 * 1024);

    let data = vec![0xDD; CHUNK_SIZE];
    stream_write_chunks(&mut handle, "aligned.bin", &data, CHUNK_SIZE).expect("stream write");

    let (collected, _, checksum) =
        stream_read_chunks(&mut handle, "aligned.bin").expect("stream read");

    assert_eq!(collected, data);
    let stored = handle.index.find("aligned.bin").expect("find").checksum;
    assert_eq!(checksum, stored);

    vault_close(handle).expect("close");
}

#[test]
fn test_stream_read_large_segment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 12 * 1024 * 1024);

    let data: Vec<u8> = (0..10_000_000).map(|i| (i % 251) as u8).collect();
    stream_write_chunks(&mut handle, "big.bin", &data, 65536).expect("stream write");

    let (collected, indices, checksum) =
        stream_read_chunks(&mut handle, "big.bin").expect("stream read");

    assert_eq!(collected.len(), data.len());
    assert_eq!(collected, data);
    assert!(!indices.is_empty());
    assert_eq!(
        checksum,
        handle.index.find("big.bin").expect("find").checksum
    );

    vault_close(handle).expect("close");
}

#[test]
fn test_stream_read_tamper_detected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    let chunk_size = crate::core::streaming::CHUNK_SIZE;
    let data = vec![0xEE; chunk_size * 2];
    stream_write_chunks(&mut handle, "tamper.bin", &data, chunk_size).expect("stream write");

    let entry = handle.index.find("tamper.bin").expect("find");
    let disk_offset =
        crate::core::evfs::format::data_region_offset(handle.index_pad_size) + entry.offset;

    handle
        .file
        .seek(std::io::SeekFrom::Start(disk_offset + 13))
        .expect("seek");
    handle.file.write_all(&[0xFF]).expect("tamper");
    handle.file.sync_all().expect("sync");

    let result = stream_read_chunks(&mut handle, "tamper.bin");
    assert!(
        matches!(result, Err(CryptoError::AuthenticationFailed)),
        "Should detect chunk tampering via streaming read"
    );

    vault_close(handle).expect("close");
}

#[test]
fn test_stream_read_reorder_detected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    let chunk_size = crate::core::streaming::CHUNK_SIZE;
    let enc_chunk_size = crate::core::streaming::ENCRYPTED_CHUNK_SIZE as u64;
    let data = vec![0xFF; chunk_size * 2];
    stream_write_chunks(&mut handle, "reorder.bin", &data, chunk_size).expect("stream write");

    let entry = handle.index.find("reorder.bin").expect("find");
    let disk_offset =
        crate::core::evfs::format::data_region_offset(handle.index_pad_size) + entry.offset;

    let mut c0 = vec![0u8; enc_chunk_size as usize];
    let mut c1 = vec![0u8; enc_chunk_size as usize];
    handle
        .file
        .seek(std::io::SeekFrom::Start(disk_offset))
        .expect("seek");
    handle.file.read_exact(&mut c0).expect("read c0");
    handle.file.read_exact(&mut c1).expect("read c1");
    handle
        .file
        .seek(std::io::SeekFrom::Start(disk_offset))
        .expect("seek");
    handle.file.write_all(&c1).expect("write c1");
    handle.file.write_all(&c0).expect("write c0");
    handle.file.sync_all().expect("sync");

    let result = stream_read_chunks(&mut handle, "reorder.bin");
    assert!(
        matches!(result, Err(CryptoError::AuthenticationFailed)),
        "Should detect chunk reordering via streaming read"
    );

    vault_close(handle).expect("close");
}

#[test]
fn test_stream_read_chacha20() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir
        .path()
        .join("test.vault")
        .to_str()
        .expect("path")
        .to_string();
    let mut handle = vault_create(
        path,
        test_key(),
        "chacha20-poly1305".into(),
        2 * 1024 * 1024,
    )
    .expect("create");

    let data = vec![0x77; 200_000];
    stream_write_chunks(&mut handle, "chacha.bin", &data, 4096).expect("stream write");

    let (collected, _, _) = stream_read_chunks(&mut handle, "chacha.bin").expect("stream read");
    assert_eq!(collected, data);

    vault_close(handle).expect("close");
}

// -- vault_write_file (FRB wrapper) -----------------------------------------

/// Helper: write `data` to a temp file and return the path.
fn write_temp_file(dir: &tempfile::TempDir, name: &str, data: &[u8]) -> String {
    let path = dir.path().join(name);
    std::fs::write(&path, data).expect("write temp file");
    path.to_str().expect("path").to_string()
}

/// Fake progress sink that collects values (vault_write_file can't use StreamSink in tests,
/// but the underlying vault_write_stream is what's actually tested here).
#[test]
fn test_write_file_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 2 * 1024 * 1024);

    let data = vec![0x42u8; 200_000];
    let file_path = write_temp_file(&dir, "input.bin", &data);

    // vault_write_file needs StreamSink — test the underlying path instead:
    // read file → feed to vault_write_stream → read back
    use crate::core::streaming::CHUNK_SIZE;
    let file_data = std::fs::read(&file_path).expect("read file");
    let chunks: Vec<Vec<u8>> = file_data.chunks(CHUNK_SIZE).map(|c| c.to_vec()).collect();
    vault_write_stream(
        &mut handle,
        "from_file.bin".into(),
        file_data.len() as u64,
        chunks.into_iter(),
    )
    .expect("write stream");

    let readback = vault_read(&mut handle, "from_file.bin".into()).expect("read");
    assert_eq!(readback, data);

    vault_close(handle).expect("close");
}

#[test]
fn test_write_file_stream_read_interop() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 2 * 1024 * 1024);

    let data: Vec<u8> = (0..150_000).map(|i| (i % 199) as u8).collect();
    let file_path = write_temp_file(&dir, "interop.bin", &data);

    use crate::core::streaming::CHUNK_SIZE;
    let file_data = std::fs::read(&file_path).expect("read file");
    let chunks: Vec<Vec<u8>> = file_data.chunks(CHUNK_SIZE).map(|c| c.to_vec()).collect();
    vault_write_stream(
        &mut handle,
        "interop.bin".into(),
        file_data.len() as u64,
        chunks.into_iter(),
    )
    .expect("write stream");

    // Read back via streaming read helper
    let (collected, _, checksum) =
        stream_read_chunks(&mut handle, "interop.bin").expect("stream read");
    assert_eq!(collected, data);
    assert_eq!(
        checksum,
        handle.index.find("interop.bin").expect("find").checksum
    );

    vault_close(handle).expect("close");
}

#[test]
fn test_write_file_large() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 12 * 1024 * 1024);

    let data: Vec<u8> = (0..5_000_000).map(|i| (i % 251) as u8).collect();
    let file_path = write_temp_file(&dir, "large.bin", &data);

    use crate::core::streaming::CHUNK_SIZE;
    let file_data = std::fs::read(&file_path).expect("read file");
    let chunks: Vec<Vec<u8>> = file_data.chunks(CHUNK_SIZE).map(|c| c.to_vec()).collect();
    vault_write_stream(
        &mut handle,
        "large.bin".into(),
        file_data.len() as u64,
        chunks.into_iter(),
    )
    .expect("write stream");

    let readback = vault_read(&mut handle, "large.bin".into()).expect("read");
    assert_eq!(readback.len(), data.len());
    assert_eq!(readback, data);

    vault_close(handle).expect("close");
}

#[test]
fn test_write_file_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    let file_path = write_temp_file(&dir, "empty.bin", &[]);

    use crate::core::streaming::CHUNK_SIZE;
    let file_data = std::fs::read(&file_path).expect("read file");
    let chunks: Vec<Vec<u8>> = file_data.chunks(CHUNK_SIZE).map(|c| c.to_vec()).collect();
    vault_write_stream(&mut handle, "empty.bin".into(), 0, chunks.into_iter())
        .expect("write stream");

    let readback = vault_read(&mut handle, "empty.bin".into()).expect("read");
    assert!(readback.is_empty());

    vault_close(handle).expect("close");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// -- Key Rotation -----------------------------------------------------------

#[test]
fn test_rotate_key_basic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "a.txt".into(), b"hello".to_vec(), None).expect("write a");
    vault_write(&mut handle, "b.txt".into(), b"world".to_vec(), None).expect("write b");

    let mut handle = vault_rotate_key(handle, test_key2()).expect("rotate");

    assert_eq!(
        vault_read(&mut handle, "a.txt".into()).expect("read a"),
        b"hello"
    );
    assert_eq!(
        vault_read(&mut handle, "b.txt".into()).expect("read b"),
        b"world"
    );

    vault_close(handle).expect("close");
}

#[test]
fn test_rotate_key_old_key_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);

    {
        let mut handle = vault_create(path.clone(), test_key(), "aes-256-gcm".into(), 1_048_576)
            .expect("create");
        vault_write(
            &mut handle,
            "secret.txt".into(),
            b"top secret".to_vec(),
            None,
        )
        .expect("write");
        let handle = vault_rotate_key(handle, test_key2()).expect("rotate");
        vault_close(handle).expect("close");
    }

    // Old key must be rejected
    assert!(vault_open(path.clone(), test_key()).is_err());

    // New key must still work and data must be intact
    let mut handle = vault_open(path, test_key2()).expect("open with new key");
    assert_eq!(
        vault_read(&mut handle, "secret.txt".into()).expect("read"),
        b"top secret"
    );
    vault_close(handle).expect("close");
}

#[test]
fn test_rotate_key_streaming_segment_survives() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 2 * 1024 * 1024);

    let data = vec![0x42u8; 200_000]; // spans multiple chunks
    stream_write_chunks(&mut handle, "video.bin", &data, 4096).expect("stream write");

    let mut handle = vault_rotate_key(handle, test_key2()).expect("rotate");

    let readback = vault_read(&mut handle, "video.bin".into()).expect("read after rotate");
    assert_eq!(readback, data);

    vault_close(handle).expect("close");
}

#[test]
fn test_rotate_key_compressed_segment_survives() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    let data = b"compressible repeated payload ".repeat(100);
    let config = CompressionConfig {
        algorithm: CompressionAlgorithm::Zstd,
        level: None,
    };
    vault_write(&mut handle, "data.bin".into(), data.clone(), Some(config)).expect("write");

    let mut handle = vault_rotate_key(handle, test_key2()).expect("rotate");

    let readback = vault_read(&mut handle, "data.bin".into()).expect("read after rotate");
    assert_eq!(readback, data);

    vault_close(handle).expect("close");
}

#[test]
fn test_rotate_key_checksum_preserved() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(
        &mut handle,
        "doc.txt".into(),
        b"checksum test data".to_vec(),
        None,
    )
    .expect("write");

    let checksum_before = handle.index.find("doc.txt").expect("find before").checksum;

    let handle = vault_rotate_key(handle, test_key2()).expect("rotate");

    let checksum_after = handle.index.find("doc.txt").expect("find after").checksum;

    assert_eq!(
        checksum_before, checksum_after,
        "BLAKE3 checksum must be identical before and after rotation"
    );

    vault_close(handle).expect("close");
}

#[test]
fn test_rotate_key_crash_recovery_rotating_cleaned_up() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);

    {
        let handle = vault_create(path.clone(), test_key(), "aes-256-gcm".into(), 1_048_576)
            .expect("create");
        vault_close(handle).expect("close");
    }

    // Plant a stale .rotating file to simulate a crash mid-rotation.
    let rotating_path = format!("{path}.rotating");
    std::fs::write(&rotating_path, b"stale junk").expect("plant stale file");
    assert!(std::path::Path::new(&rotating_path).exists());

    // vault_open must silently remove the orphan and succeed normally.
    let handle = vault_open(path, test_key()).expect("open after simulated crash");
    vault_close(handle).expect("close");

    assert!(
        !std::path::Path::new(&rotating_path).exists(),
        ".rotating file must be cleaned up by vault_open"
    );
}

#[test]
fn test_rotate_key_empty_vault() {
    let dir = tempfile::tempdir().expect("tempdir");
    let handle = create_test_vault(&dir, 1_048_576);

    // Rotate with no segments written at all.
    let handle = vault_rotate_key(handle, test_key2()).expect("rotate empty vault");

    assert!(
        vault_list(&handle).is_empty(),
        "rotated empty vault must have no segments"
    );

    vault_close(handle).expect("close");
}

#[test]
fn test_rotate_key_chacha20() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir
        .path()
        .join("chacha.vault")
        .to_str()
        .expect("path")
        .to_string();

    let mut handle =
        vault_create(path, test_key(), "chacha20-poly1305".into(), 1_048_576).expect("create");
    vault_write(
        &mut handle,
        "msg.txt".into(),
        b"chacha payload".to_vec(),
        None,
    )
    .expect("write");

    let mut handle = vault_rotate_key(handle, test_key2()).expect("rotate chacha20 vault");

    let readback = vault_read(&mut handle, "msg.txt".into()).expect("read after rotate");
    assert_eq!(readback, b"chacha payload");

    vault_close(handle).expect("close");
}

#[test]
fn test_rotate_key_multiple_rotations() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(
        &mut handle,
        "doc.txt".into(),
        b"original data".to_vec(),
        None,
    )
    .expect("write");

    // First rotation: test_key → new_key
    let handle = vault_rotate_key(handle, test_key2()).expect("first rotation");
    // Second rotation: new_key → wrong_key
    let mut handle = vault_rotate_key(handle, wrong_key()).expect("second rotation");

    let readback = vault_read(&mut handle, "doc.txt".into()).expect("read after two rotations");
    assert_eq!(readback, b"original data");

    vault_close(handle).expect("close");
}

#[test]
fn test_rotate_key_empty_new_key_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let handle = create_test_vault(&dir, 1_048_576);

    let result = vault_rotate_key(handle, vec![]);
    assert!(
        result.is_err(),
        "rotation with an empty new key must return an error"
    );
}

// -- Export ----------------------------------------------------------------

fn wrapping_key() -> Vec<u8> {
    vec![0xCC; 32]
}

fn export_path(dir: &tempfile::TempDir) -> String {
    dir.path()
        .join("export.mvex")
        .to_str()
        .expect("path")
        .to_string()
}

/// Parse an exported `.mvex` archive, returning (header, wrapped_key, records, trailer_checksum).
fn parse_archive(
    path: &str,
) -> (
    crate::core::evfs::archive::ArchiveHeader,
    Vec<u8>,
    Vec<crate::core::evfs::archive::SegmentRecord>,
    [u8; 32],
) {
    use crate::core::evfs::archive::*;
    let data = std::fs::read(path).expect("read archive");
    assert!(data.len() >= ARCHIVE_HEADER_SIZE + WRAPPED_KEY_SIZE + ARCHIVE_TRAILER_SIZE);

    let header = ArchiveHeader::from_bytes(
        data[..ARCHIVE_HEADER_SIZE].try_into().expect("header slice"),
    )
    .expect("parse header");

    let wk_start = ARCHIVE_HEADER_SIZE;
    let wrapped_key = data[wk_start..wk_start + WRAPPED_KEY_SIZE].to_vec();

    let mut pos = wk_start + WRAPPED_KEY_SIZE;
    let mut records = Vec::new();

    for _ in 0..header.segment_count {
        let (name, compression, checksum, data_len, hdr_size) =
            SegmentRecord::read_header(&data[pos..]).expect("parse record header");
        pos += hdr_size;
        let enc_data = data[pos..pos + data_len as usize].to_vec();
        pos += data_len as usize;
        records.push(SegmentRecord {
            name,
            compression,
            checksum,
            encrypted_data: enc_data,
        });
    }

    let trailer_bytes: [u8; ARCHIVE_TRAILER_SIZE] =
        data[pos..pos + ARCHIVE_TRAILER_SIZE].try_into().expect("trailer slice");
    let trailer = ArchiveTrailer::from_bytes(&trailer_bytes).expect("parse trailer");

    // Verify BLAKE3 trailer covers everything before the trailer
    let computed = blake3::hash(&data[..pos]);
    assert_eq!(
        trailer.checksum,
        <[u8; 32]>::from(computed),
        "trailer checksum mismatch"
    );

    (header, wrapped_key, records, trailer.checksum)
}

/// Unwrap the export key and decrypt a segment record.
fn decrypt_record(
    record: &crate::core::evfs::archive::SegmentRecord,
    wrapped_key: &[u8],
    wk: &[u8],
    algorithm: crate::core::format::Algorithm,
) -> Vec<u8> {
    use crate::core::evfs::archive::KEY_WRAP_AAD;
    use crate::core::evfs::segment;

    let export_key =
        segment::aead_decrypt_with_stored_nonce(wk, wrapped_key, KEY_WRAP_AAD, algorithm)
            .expect("unwrap export key");
    segment::aead_decrypt_with_stored_nonce(
        &export_key,
        &record.encrypted_data,
        record.name.as_bytes(),
        algorithm,
    )
    .expect("decrypt record")
}

// -- Archive format unit tests ---------------------------------------------

#[test]
fn test_archive_header_roundtrip() {
    use crate::core::evfs::archive::*;

    let header = ArchiveHeader::new(0x01, 42);
    let bytes = header.to_bytes();
    let parsed = ArchiveHeader::from_bytes(&bytes).expect("parse");
    assert_eq!(parsed.version, ARCHIVE_VERSION);
    assert_eq!(parsed.algorithm, 0x01);
    assert_eq!(parsed.segment_count, 42);
    assert_eq!(parsed.flags, 0);
}

#[test]
fn test_archive_header_bad_magic_rejected() {
    use crate::core::evfs::archive::*;

    let mut bytes = ArchiveHeader::new(0x01, 1).to_bytes();
    bytes[0] = b'X'; // corrupt magic
    assert!(ArchiveHeader::from_bytes(&bytes).is_err());
}

#[test]
fn test_archive_header_bad_version_rejected() {
    use crate::core::evfs::archive::*;

    let mut bytes = ArchiveHeader::new(0x01, 1).to_bytes();
    bytes[4] = 99; // unsupported version
    assert!(ArchiveHeader::from_bytes(&bytes).is_err());
}

#[test]
fn test_archive_trailer_roundtrip() {
    use crate::core::evfs::archive::*;

    let checksum = [0xAB; 32];
    let trailer = ArchiveTrailer { checksum };
    let bytes = trailer.to_bytes();
    let parsed = ArchiveTrailer::from_bytes(&bytes).expect("parse");
    assert_eq!(parsed.checksum, checksum);
}

#[test]
fn test_archive_trailer_bad_magic_rejected() {
    use crate::core::evfs::archive::*;

    let mut bytes = (ArchiveTrailer { checksum: [0; 32] }).to_bytes();
    bytes[35] = b'Z'; // corrupt reverse magic
    assert!(ArchiveTrailer::from_bytes(&bytes).is_err());
}

#[test]
fn test_segment_record_header_roundtrip() {
    use crate::core::evfs::archive::*;

    let record = SegmentRecord {
        name: "hello.txt".into(),
        compression: 0x01,
        checksum: [0xDD; 32],
        encrypted_data: vec![0xFF; 100],
    };
    let header = record.write_header().expect("write header");
    let (name, comp, cksum, data_len, consumed) =
        SegmentRecord::read_header(&header).expect("read header");
    assert_eq!(name, "hello.txt");
    assert_eq!(comp, 0x01);
    assert_eq!(cksum, [0xDD; 32]);
    assert_eq!(data_len, 100);
    assert_eq!(consumed, header.len());
}

#[test]
fn test_wrapped_key_size() {
    use crate::core::evfs::archive::WRAPPED_KEY_SIZE;
    // nonce(12) + ciphertext(32) + tag(16) = 60
    assert_eq!(WRAPPED_KEY_SIZE, 60);
}

#[test]
fn test_archive_trailer_size() {
    use crate::core::evfs::archive::ARCHIVE_TRAILER_SIZE;
    // blake3(32) + reverse_magic(4) = 36
    assert_eq!(ARCHIVE_TRAILER_SIZE, 36);
}

// -- Export integration tests ---------------------------------------------

#[test]
fn test_export_produces_valid_archive() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "a.txt".into(), b"hello".to_vec(), None).expect("write");
    vault_write(&mut handle, "b.txt".into(), b"world".to_vec(), None).expect("write");

    let epath = export_path(&dir);
    vault_export(&mut handle, wrapping_key(), epath.clone()).expect("export");

    let (header, wrapped_key, records, _) = parse_archive(&epath);
    assert_eq!(header.segment_count, 2);
    assert_eq!(header.version, 1);
    assert_eq!(records.len(), 2);

    // Decrypt and verify contents
    let algo = crate::core::format::Algorithm::AesGcm;
    for record in &records {
        let plaintext = decrypt_record(record, &wrapped_key, &wrapping_key(), algo);
        match record.name.as_str() {
            "a.txt" => assert_eq!(plaintext, b"hello"),
            "b.txt" => assert_eq!(plaintext, b"world"),
            other => panic!("unexpected segment: {other}"),
        }
        // Verify BLAKE3 checksum in record matches plaintext
        let expected = crate::core::evfs::segment::compute_checksum(&plaintext);
        assert_eq!(record.checksum, expected);
    }

    vault_close(handle).expect("close");
}

#[test]
fn test_export_empty_vault() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    let epath = export_path(&dir);
    vault_export(&mut handle, wrapping_key(), epath.clone()).expect("export");

    let (header, _, records, _) = parse_archive(&epath);
    assert_eq!(header.segment_count, 0);
    assert!(records.is_empty());

    vault_close(handle).expect("close");
}

#[test]
fn test_export_with_streaming_segments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 4_194_304);

    // Write a streaming segment (> 64KB to trigger chunking)
    let data: Vec<u8> = (0..200_000).map(|i| (i % 251) as u8).collect();
    let chunks: Vec<Vec<u8>> = data.chunks(65536).map(|c| c.to_vec()).collect();
    vault_write_stream(
        &mut handle,
        "big.bin".into(),
        data.len() as u64,
        chunks.into_iter(),
    )
    .expect("stream write");

    // Also write a monolithic segment
    vault_write(&mut handle, "small.txt".into(), b"tiny".to_vec(), None).expect("write");

    let epath = export_path(&dir);
    vault_export(&mut handle, wrapping_key(), epath.clone()).expect("export");

    let (header, wrapped_key, records, _) = parse_archive(&epath);
    assert_eq!(header.segment_count, 2);

    let algo = crate::core::format::Algorithm::AesGcm;
    for record in &records {
        let plaintext = decrypt_record(record, &wrapped_key, &wrapping_key(), algo);
        match record.name.as_str() {
            "big.bin" => assert_eq!(plaintext, data),
            "small.txt" => assert_eq!(plaintext, b"tiny"),
            other => panic!("unexpected segment: {other}"),
        }
    }

    vault_close(handle).expect("close");
}

#[test]
fn test_export_with_compressed_segments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    let data = b"compress me please ".repeat(100);
    let config = CompressionConfig {
        algorithm: CompressionAlgorithm::Zstd,
        level: None,
    };
    vault_write(
        &mut handle,
        "compressed.txt".into(),
        data.clone(),
        Some(config),
    )
    .expect("write");

    let epath = export_path(&dir);
    vault_export(&mut handle, wrapping_key(), epath.clone()).expect("export");

    let (_, wrapped_key, records, _) = parse_archive(&epath);
    assert_eq!(records.len(), 1);

    let algo = crate::core::format::Algorithm::AesGcm;
    let plaintext = decrypt_record(&records[0], &wrapped_key, &wrapping_key(), algo);
    assert_eq!(plaintext, data);

    vault_close(handle).expect("close");
}

#[test]
fn test_export_does_not_modify_vault() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "a.txt".into(), b"data-A".to_vec(), None).expect("write");
    vault_write(&mut handle, "b.txt".into(), b"data-B".to_vec(), None).expect("write");

    // Snapshot state before export
    let names_before: Vec<String> = vault_list(&handle).into_iter().collect();
    let health_before = vault_health(&handle);

    let epath = export_path(&dir);
    vault_export(&mut handle, wrapping_key(), epath.clone()).expect("export");

    // Verify vault unchanged
    let names_after: Vec<String> = vault_list(&handle).into_iter().collect();
    let health_after = vault_health(&handle);
    assert_eq!(names_before, names_after);
    assert_eq!(health_before, health_after);

    // Verify data still readable
    let a = vault_read(&mut handle, "a.txt".into()).expect("read a");
    assert_eq!(a, b"data-A");
    let b = vault_read(&mut handle, "b.txt".into()).expect("read b");
    assert_eq!(b, b"data-B");

    vault_close(handle).expect("close");
}

#[test]
fn test_export_wrong_wrapping_key_cannot_decrypt() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(
        &mut handle,
        "secret.txt".into(),
        b"top secret".to_vec(),
        None,
    )
    .expect("write");

    let epath = export_path(&dir);
    vault_export(&mut handle, wrapping_key(), epath.clone()).expect("export");

    let (_, wrapped_key, _records, _) = parse_archive(&epath);
    let algo = crate::core::format::Algorithm::AesGcm;

    // Try to unwrap with wrong key
    let wrong_wk = vec![0xEE; 32];
    let result = crate::core::evfs::segment::aead_decrypt_with_stored_nonce(
        &wrong_wk,
        &wrapped_key,
        crate::core::evfs::archive::KEY_WRAP_AAD,
        algo,
    );
    assert!(
        result.is_err(),
        "wrong wrapping key must fail to unwrap export key"
    );

    vault_close(handle).expect("close");
}

#[test]
fn test_export_invalid_wrapping_key_length_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    let epath = export_path(&dir);
    let result = vault_export(&mut handle, vec![0xAA; 16], epath); // 16 bytes, not 32
    assert!(result.is_err());

    vault_close(handle).expect("close");
}

// -- Import integration tests ---------------------------------------------

fn import_dest_path(dir: &tempfile::TempDir) -> String {
    dir.path()
        .join("imported.vault")
        .to_str()
        .expect("path")
        .to_string()
}

#[test]
fn test_import_full_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 2_097_152);

    vault_write(&mut handle, "a.txt".into(), b"hello".to_vec(), None).expect("write");
    vault_write(&mut handle, "b.txt".into(), b"world".to_vec(), None).expect("write");

    let epath = export_path(&dir);
    vault_export(&mut handle, wrapping_key(), epath.clone()).expect("export");
    vault_close(handle).expect("close");

    let dest_path = import_dest_path(&dir);
    let mut imported = vault_import(
        epath,
        wrapping_key(),
        dest_path.clone(),
        test_key2(),
        "aes-256-gcm".into(),
        2_097_152,
    )
    .expect("import");

    assert_eq!(
        vault_read(&mut imported, "a.txt".into()).expect("read a"),
        b"hello"
    );
    assert_eq!(
        vault_read(&mut imported, "b.txt".into()).expect("read b"),
        b"world"
    );

    vault_close(imported).expect("close");
}

#[test]
fn test_import_wrong_wrapping_key_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "a.txt".into(), b"hello".to_vec(), None).expect("write");
    let epath = export_path(&dir);
    vault_export(&mut handle, wrapping_key(), epath.clone()).expect("export");
    vault_close(handle).expect("close");

    let dest_path = import_dest_path(&dir);
    let wrong_wk = vec![0xEE; 32];
    let result = vault_import(
        epath,
        wrong_wk,
        dest_path,
        test_key2(),
        "aes-256-gcm".into(),
        1_048_576,
    );

    assert!(matches!(result, Err(CryptoError::ImportFailed(_))));
}

#[test]
fn test_import_truncated_archive() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);
    vault_write(&mut handle, "a.txt".into(), b"hello".to_vec(), None).expect("write");
    let epath = export_path(&dir);
    vault_export(&mut handle, wrapping_key(), epath.clone()).expect("export");
    vault_close(handle).expect("close");

    // Truncate the archive midway
    let mut archive = std::fs::read(&epath).expect("read");
    archive.truncate(archive.len() - 10);
    std::fs::write(&epath, archive).expect("write");

    let dest_path = import_dest_path(&dir);
    let result = vault_import(
        epath,
        wrapping_key(),
        dest_path.clone(),
        test_key2(),
        "aes-256-gcm".into(),
        1_048_576,
    );

    assert!(matches!(result, Err(CryptoError::ImportFailed(_))));
    assert!(
        !std::path::Path::new(&dest_path).exists(),
        "Partial vault must be deleted"
    );
}

#[test]
fn test_import_tampered_segment_data() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);
    vault_write(&mut handle, "a.txt".into(), b"hello".to_vec(), None).expect("write");
    let epath = export_path(&dir);
    vault_export(&mut handle, wrapping_key(), epath.clone()).expect("export");
    vault_close(handle).expect("close");

    // Tamper with the encrypted data part of the segment record
    let mut archive = std::fs::read(&epath).expect("read");
    let pos = archive.len() - 36 - 10; // slightly before the trailer
    archive[pos] ^= 0xFF;
    std::fs::write(&epath, archive).expect("write");

    let dest_path = import_dest_path(&dir);
    let result = vault_import(
        epath,
        wrapping_key(),
        dest_path.clone(),
        test_key2(),
        "aes-256-gcm".into(),
        1_048_576,
    );

    assert!(matches!(result, Err(CryptoError::ImportFailed(_))));
}

#[test]
fn test_import_tampered_trailer_checksum() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);
    vault_write(&mut handle, "a.txt".into(), b"hello".to_vec(), None).expect("write");
    let epath = export_path(&dir);
    vault_export(&mut handle, wrapping_key(), epath.clone()).expect("export");
    vault_close(handle).expect("close");

    // Tamper with the trailer checksum
    let mut archive = std::fs::read(&epath).expect("read");
    let pos = archive.len() - 36 + 5; // within the 32 byte checksum
    archive[pos] ^= 0xFF;
    std::fs::write(&epath, archive).expect("write");

    let dest_path = import_dest_path(&dir);
    let result = vault_import(
        epath,
        wrapping_key(),
        dest_path.clone(),
        test_key2(),
        "aes-256-gcm".into(),
        1_048_576,
    );

    assert!(matches!(result, Err(CryptoError::ImportFailed(_))));
}

#[test]
fn test_import_insufficient_capacity() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 5_000_000);
    vault_write(&mut handle, "big.txt".into(), vec![0xBB; 2_000_000], None).expect("write");
    let epath = export_path(&dir);
    vault_export(&mut handle, wrapping_key(), epath.clone()).expect("export");
    vault_close(handle).expect("close");

    let dest_path = import_dest_path(&dir);
    let result = vault_import(
        epath,
        wrapping_key(),
        dest_path.clone(),
        test_key2(),
        "aes-256-gcm".into(),
        1_048_576, // Bound restriction triggers EVFS index allocation rejection
    );

    assert!(matches!(result, Err(CryptoError::VaultFull { .. })));
}

#[test]
fn test_import_streaming_segment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 4_194_304);

    let data: Vec<u8> = (0..200_000).map(|i| (i % 251) as u8).collect();
    let chunks: Vec<Vec<u8>> = data.chunks(65536).map(|c| c.to_vec()).collect();
    vault_write_stream(
        &mut handle,
        "stream.bin".into(),
        data.len() as u64,
        chunks.into_iter(),
    )
    .expect("stream write");

    let epath = export_path(&dir);
    vault_export(&mut handle, wrapping_key(), epath.clone()).expect("export");
    vault_close(handle).expect("close");

    let dest_path = import_dest_path(&dir);
    let mut imported = vault_import(
        epath,
        wrapping_key(),
        dest_path.clone(),
        test_key2(),
        "aes-256-gcm".into(),
        4_194_304,
    )
    .expect("import");

    let readback = vault_read(&mut imported, "stream.bin".into()).expect("read");
    assert_eq!(readback, data);

    vault_close(imported).expect("close");
}

#[test]
fn test_import_compressed_segment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    let data = b"compress me please ".repeat(100);
    let config = CompressionConfig {
        algorithm: CompressionAlgorithm::Zstd,
        level: None,
    };
    vault_write(
        &mut handle,
        "compressed.txt".into(),
        data.clone(),
        Some(config),
    )
    .expect("write");

    let epath = export_path(&dir);
    vault_export(&mut handle, wrapping_key(), epath.clone()).expect("export");
    vault_close(handle).expect("close");

    let dest_path = import_dest_path(&dir);
    let mut imported = vault_import(
        epath,
        wrapping_key(),
        dest_path.clone(),
        test_key2(),
        "aes-256-gcm".into(),
        1_048_576,
    )
    .expect("import");

    let entry = imported.index.find("compressed.txt").expect("find");
    assert_eq!(entry.compression, CompressionAlgorithm::Zstd);

    let readback = vault_read(&mut imported, "compressed.txt".into()).expect("read");
    assert_eq!(readback, data);

    vault_close(imported).expect("close");
}

#[test]
fn test_import_chacha20() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = vault_create(
        vault_path(&dir),
        test_key(),
        "chacha20-poly1305".into(),
        1_048_576,
    )
    .expect("create");

    vault_write(&mut handle, "c.txt".into(), b"chacha".to_vec(), None).expect("write");
    let epath = export_path(&dir);
    vault_export(&mut handle, wrapping_key(), epath.clone()).expect("export");
    vault_close(handle).expect("close");

    let dest_path = import_dest_path(&dir);
    let mut imported = vault_import(
        epath,
        wrapping_key(),
        dest_path.clone(),
        test_key2(),
        "chacha20-poly1305".into(),
        1_048_576,
    )
    .expect("import");

    assert_eq!(
        imported.algorithm,
        crate::core::format::Algorithm::ChaCha20Poly1305
    );
    assert_eq!(
        vault_read(&mut imported, "c.txt".into()).expect("read c"),
        b"chacha"
    );

    vault_close(imported).expect("close");
}

// -- Index caching / dirty flag ------------------------------------------

#[test]
fn test_index_dirty_false_after_create() {
    let dir = tempfile::tempdir().expect("tempdir");
    let handle = create_test_vault(&dir, 1_048_576);
    assert!(!handle.index_dirty);
    vault_close(handle).expect("close");
}

#[test]
fn test_index_dirty_false_after_open() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);
    let handle = vault_create(path.clone(), test_key(), "aes-256-gcm".into(), 1_048_576)
        .expect("create");
    vault_close(handle).expect("close");

    let handle = vault_open(path, test_key()).expect("open");
    assert!(!handle.index_dirty);
    vault_close(handle).expect("close");
}

#[test]
fn test_index_clean_after_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);
    vault_write(&mut handle, "a.txt".into(), b"hello".to_vec(), None).expect("write");
    // After write completes, dirty flag should be cleared (flushed)
    assert!(!handle.index_dirty);
    vault_close(handle).expect("close");
}

#[test]
fn test_index_clean_after_delete() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);
    vault_write(&mut handle, "a.txt".into(), b"hello".to_vec(), None).expect("write");
    vault_delete(&mut handle, "a.txt".into()).expect("delete");
    assert!(!handle.index_dirty);
    vault_close(handle).expect("close");
}

#[test]
fn test_read_does_not_set_dirty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);
    vault_write(&mut handle, "a.txt".into(), b"hello".to_vec(), None).expect("write");
    assert!(!handle.index_dirty);

    let _ = vault_read(&mut handle, "a.txt".into()).expect("read");
    assert!(!handle.index_dirty);

    let _ = vault_list(&handle);
    assert!(!handle.index_dirty);

    let _ = vault_capacity(&handle);
    assert!(!handle.index_dirty);

    let _ = vault_health(&handle);
    assert!(!handle.index_dirty);

    vault_close(handle).expect("close");
}

#[test]
fn test_vault_flush_noop_when_clean() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);
    assert!(!handle.index_dirty);
    // Should be a no-op — no error, no disk I/O
    vault_flush(&mut handle).expect("flush clean");
    assert!(!handle.index_dirty);
    vault_close(handle).expect("close");
}

#[test]
fn test_vault_flush_persists_and_survives_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);
    let mut handle =
        vault_create(path.clone(), test_key(), "aes-256-gcm".into(), 1_048_576).expect("create");
    vault_write(&mut handle, "a.txt".into(), b"hello".to_vec(), None).expect("write");
    // Explicit flush then close — data must survive reopen
    vault_flush(&mut handle).expect("flush");
    assert!(!handle.index_dirty);
    vault_close(handle).expect("close");

    let mut reopened = vault_open(path, test_key()).expect("reopen");
    assert_eq!(
        vault_read(&mut reopened, "a.txt".into()).expect("read"),
        b"hello"
    );
    vault_close(reopened).expect("close");
}

#[test]
fn test_vault_close_flushes_dirty_and_persists() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);
    let mut handle =
        vault_create(path.clone(), test_key(), "aes-256-gcm".into(), 1_048_576).expect("create");
    vault_write(&mut handle, "b.txt".into(), b"world".to_vec(), None).expect("write");
    // Simulate a dirty handle at close time by manually setting the flag.
    // This exercises the vault_close dirty-flush path.
    handle.index_dirty = true;
    vault_close(handle).expect("close");

    let mut reopened = vault_open(path, test_key()).expect("reopen");
    assert_eq!(
        vault_read(&mut reopened, "b.txt".into()).expect("read"),
        b"world"
    );
    vault_close(reopened).expect("close");
}

#[test]
fn test_index_dirty_false_after_rotate_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);
    let handle =
        vault_create(path.clone(), test_key(), "aes-256-gcm".into(), 1_048_576).expect("create");
    let rotated = vault_rotate_key(handle, test_key2()).expect("rotate");
    assert!(!rotated.index_dirty);
    vault_close(rotated).expect("close");
}

#[test]
fn test_index_clean_after_defragment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);
    vault_write(&mut handle, "a.txt".into(), b"aaa".to_vec(), None).expect("write a");
    vault_write(&mut handle, "b.txt".into(), b"bbb".to_vec(), None).expect("write b");
    vault_delete(&mut handle, "a.txt".into()).expect("delete a");
    vault_defragment(&mut handle).expect("defrag");
    assert!(!handle.index_dirty);
    vault_close(handle).expect("close");
}

#[test]
fn test_index_clean_after_resize() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);
    vault_resize(&mut handle, 2_097_152).expect("grow");
    assert!(!handle.index_dirty);
    vault_resize(&mut handle, 1_048_576).expect("shrink");
    assert!(!handle.index_dirty);
    vault_close(handle).expect("close");
}

// -- Parallel reads -------------------------------------------------------

// Compile-time assertion: VaultHandle must be Sync for &VaultHandle across rayon threads
#[allow(dead_code)]
trait AssertSync: Sync {}
impl AssertSync for super::types::VaultHandle {}

#[test]
fn test_parallel_read_matches_sequential() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 4_194_304);

    vault_write(&mut handle, "a.txt".into(), b"alpha".to_vec(), None).expect("write a");
    vault_write(&mut handle, "b.txt".into(), b"bravo".to_vec(), None).expect("write b");
    vault_write(&mut handle, "c.txt".into(), b"charlie".to_vec(), None).expect("write c");

    let seq_a = vault_read(&mut handle, "a.txt".into()).expect("read a");
    let seq_b = vault_read(&mut handle, "b.txt".into()).expect("read b");
    let seq_c = vault_read(&mut handle, "c.txt".into()).expect("read c");

    let results = vault_read_parallel(
        &handle,
        vec!["a.txt".into(), "b.txt".into(), "c.txt".into()],
    );

    assert_eq!(results.len(), 3);
    assert!(results[0].error.is_none());
    assert_eq!(results[0].data, seq_a);
    assert_eq!(results[1].data, seq_b);
    assert_eq!(results[2].data, seq_c);

    vault_close(handle).expect("close");
}

#[test]
fn test_parallel_read_10_segments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 4_194_304);

    let mut expected = Vec::new();
    for i in 0..10u8 {
        let name = format!("seg_{i}");
        let data = vec![i; 1024];
        vault_write(&mut handle, name, data.clone(), None).expect("write");
        expected.push(data);
    }

    let names: Vec<String> = (0..10).map(|i| format!("seg_{i}")).collect();
    let results = vault_read_parallel(&handle, names);

    assert_eq!(results.len(), 10);
    for (i, sr) in results.iter().enumerate() {
        assert!(sr.error.is_none(), "segment {i} had error: {:?}", sr.error);
        assert_eq!(sr.name, format!("seg_{i}"));
        assert_eq!(sr.data, expected[i]);
    }

    vault_close(handle).expect("close");
}

#[test]
fn test_parallel_read_mixed_monolithic_and_streaming() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 4_194_304);

    let mono_data = vec![0xAA; 512];
    vault_write(&mut handle, "mono".into(), mono_data.clone(), None).expect("write mono");

    let stream_data: Vec<u8> = (0..=255u8).cycle().take(100_000).collect();
    let stream_iter = stream_data.chunks(8192).map(|c| c.to_vec());
    vault_write_stream(&mut handle, "stream".into(), stream_data.len() as u64, stream_iter)
        .expect("write stream");

    let results = vault_read_parallel(&handle, vec!["mono".into(), "stream".into()]);

    assert_eq!(results.len(), 2);
    assert!(results[0].error.is_none());
    assert_eq!(results[0].data, mono_data);
    assert!(results[1].error.is_none());
    assert_eq!(results[1].data, stream_data);

    vault_close(handle).expect("close");
}

#[test]
fn test_parallel_read_missing_segment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "exists".into(), vec![1, 2, 3], None).expect("write");

    let results = vault_read_parallel(&handle, vec!["exists".into(), "missing".into()]);

    assert_eq!(results.len(), 2);
    assert!(results[0].error.is_none());
    assert_eq!(results[0].data, vec![1, 2, 3]);
    assert!(results[1].error.is_some());
    assert!(
        results[1].error.as_ref().expect("error").contains("missing"),
        "error should mention segment name"
    );
    assert!(results[1].data.is_empty());

    vault_close(handle).expect("close");
}

#[test]
fn test_parallel_read_empty_names() {
    let dir = tempfile::tempdir().expect("tempdir");
    let handle = create_test_vault(&dir, 1_048_576);

    let results = vault_read_parallel(&handle, vec![]);
    assert!(results.is_empty());

    vault_close(handle).expect("close");
}

#[test]
fn test_parallel_read_single_name() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "only".into(), b"solo".to_vec(), None).expect("write");

    let seq = vault_read(&mut handle, "only".into()).expect("sequential");
    let results = vault_read_parallel(&handle, vec!["only".into()]);

    assert_eq!(results.len(), 1);
    assert!(results[0].error.is_none());
    assert_eq!(results[0].data, seq);

    vault_close(handle).expect("close");
}

#[test]
fn test_parallel_read_preserves_order() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 4_194_304);

    for i in 0..10u8 {
        vault_write(&mut handle, format!("seg_{i}"), vec![i; 256], None).expect("write");
    }

    let names: Vec<String> = (0..10).rev().map(|i| format!("seg_{i}")).collect();
    let results = vault_read_parallel(&handle, names.clone());

    assert_eq!(results.len(), 10);
    for (i, sr) in results.iter().enumerate() {
        assert!(sr.error.is_none());
        assert_eq!(sr.name, names[i]);
    }

    vault_close(handle).expect("close");
}

#[test]
fn test_parallel_read_chacha20() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);

    let mut handle =
        vault_create(path, test_key(), "chacha20-poly1305".into(), 4_194_304).expect("create");

    vault_write(&mut handle, "x".into(), b"chacha-data".to_vec(), None).expect("write");
    vault_write(&mut handle, "y".into(), b"poly1305-data".to_vec(), None).expect("write");

    let results = vault_read_parallel(&handle, vec!["x".into(), "y".into()]);

    assert!(results[0].error.is_none());
    assert_eq!(results[0].data, b"chacha-data");
    assert!(results[1].error.is_none());
    assert_eq!(results[1].data, b"poly1305-data");

    vault_close(handle).expect("close");
}

#[test]
fn test_parallel_read_fallback_sequential() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 4_194_304);

    vault_write(&mut handle, "a".into(), b"alpha".to_vec(), None).expect("write a");
    vault_write(&mut handle, "b".into(), b"bravo".to_vec(), None).expect("write b");

    // Force no-mmap fallback
    handle.mmap = None;

    let results = vault_read_parallel(&handle, vec!["a".into(), "b".into()]);

    assert_eq!(results.len(), 2);
    assert!(results[0].error.is_none());
    assert_eq!(results[0].data, b"alpha");
    assert!(results[1].error.is_none());
    assert_eq!(results[1].data, b"bravo");

    vault_close(handle).expect("close");
}
