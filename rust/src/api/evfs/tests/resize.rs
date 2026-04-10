use super::*;

// -- Resize -------------------------------------------------------------

#[test]
fn test_resize_grow_then_write_in_new_space() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, SIZE_MB);

    // Fill most of the original 1MB capacity
    let filler = vec![0xAA; 900_000];
    vault_write(&mut handle, "filler.bin".into(), filler.clone(), None, None).expect("write filler");

    // Grow to 2MB
    vault_resize(&mut handle, 2 * SIZE_MB).expect("grow to 2MB");

    // Write a segment that requires space in the new region
    let big = vec![0xBB; 900_000];
    vault_write(&mut handle, "big.bin".into(), big.clone(), None, None).expect("write in new space");

    // Read both back
    let filler_read = vault_read(&mut handle, "filler.bin".into()).expect("read filler").data;
    assert_eq!(filler_read, filler);
    let big_read = vault_read(&mut handle, "big.bin".into()).expect("read big").data;
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
        vault_write(&mut handle, "doc.bin".into(), data, None, None).expect("write 500KB");
        vault_close(handle).expect("close");
    }

    // Reopen, shrink to 1MB. Data is at the beginning so it should fit.
    {
        let mut handle = vault_open(path.clone(), test_key()).expect("reopen");
        vault_resize(&mut handle, SIZE_MB).expect("shrink to 1MB");

        // Verify all data is still readable.
        let data = vault_read(&mut handle, "doc.bin".into()).expect("read after shrink").data;
        assert_eq!(data, vec![0xCC; 500_000]);

        // Verify capacity reflects the new size.
        let cap = vault_capacity(&handle);
        assert_eq!(cap.total_bytes, SIZE_MB);

        vault_close(handle).expect("close");
    }

    // Reopen again to confirm persistence across close/open.
    {
        let mut handle = vault_open(path, test_key()).expect("reopen again");
        let data = vault_read(&mut handle, "doc.bin".into()).expect("read persisted").data;
        assert_eq!(data, vec![0xCC; 500_000]);
        vault_close(handle).expect("close");
    }
}

#[test]
fn test_resize_shrink_below_used_space_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, SIZE_MB);

    // Write enough data so that shrinking below used space is impossible.
    vault_write(&mut handle, "a.bin".into(), vec![0xDD; 600_000], None, None).expect("write");

    // Attempt to shrink to 256KB — should fail with VaultFull.
    let result = vault_resize(&mut handle, 256 * 1024);
    assert!(
        matches!(result, Err(CryptoError::VaultFull { .. })),
        "expected VaultFull, got: {result:?}"
    );

    // Vault should still be usable after failed shrink.
    let data = vault_read(&mut handle, "a.bin".into()).expect("read after failed shrink").data;
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
        vault_write(&mut handle, "a.txt".into(), b"before grow".to_vec(), None, None).expect("write A");
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
        vault_write(&mut handle, "b.txt".into(), b"after grow".to_vec(), None, None).expect("write B");
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
    let data = vault_read(&mut handle, "a.txt".into()).expect("read A").data;
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

    vault_write(&mut handle, "a.txt".into(), b"hello".to_vec(), None, None).expect("write");
    let cap_before = vault_capacity(&handle);

    // Resize to same capacity — should return Ok without I/O
    vault_resize(&mut handle, SIZE_MB).expect("noop resize");

    let cap_after = vault_capacity(&handle);
    assert_eq!(cap_before.total_bytes, cap_after.total_bytes);
    assert_eq!(cap_before.used_bytes, cap_after.used_bytes);

    let data = vault_read(&mut handle, "a.txt".into()).expect("read").data;
    assert_eq!(data, b"hello");

    vault_close(handle).expect("close");
}

#[test]
fn test_resize_shrink_after_defrag_reclaims_max_space() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 2 * SIZE_MB);

    // Write three segments, delete the first two to create gaps
    vault_write(&mut handle, "a.bin".into(), vec![0xAA; 200_000], None, None).expect("A");
    vault_write(&mut handle, "b.bin".into(), vec![0xBB; 200_000], None, None).expect("B");
    vault_write(&mut handle, "keep.bin".into(), vec![0xCC; 100_000], None, None).expect("keep");

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
    let data = vault_read(&mut handle, "keep.bin".into()).expect("read keep").data;
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
        vault_write(&mut handle, "a.txt".into(), b"safe data".to_vec(), None, None).expect("write A");
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
    let data = vault_read(&mut handle, "a.txt".into()).expect("read A").data;
    assert_eq!(data, b"safe data");

    // Vault usable after recovery — write + read works
    vault_write(&mut handle, "b.txt".into(), b"post recovery".to_vec(), None, None).expect("write B");
    let b_data = vault_read(&mut handle, "b.txt".into()).expect("read B").data;
    assert_eq!(b_data, b"post recovery");

    vault_close(handle).expect("close");
}

