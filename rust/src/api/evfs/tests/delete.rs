use super::*;

// -- Delete -------------------------------------------------------------

#[test]
fn test_delete_segment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "tmp.txt".into(), b"temp data".to_vec(), None, None).expect("write");
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
    vault_write(&mut handle, "a.txt".into(), vec![0xAA; 200], None, None).expect("A");

    // Second write should fail — not enough space
    let result = vault_write(&mut handle, "b.txt".into(), vec![0xBB; 200], None, None);
    assert!(matches!(result, Err(CryptoError::VaultFull { .. })));

    vault_close(handle).expect("close");
}

#[test]
fn test_vault_full_with_free_list() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Small vault
    let mut handle = create_test_vault(&dir, 512);

    // Fill vault with A
    vault_write(&mut handle, "a.txt".into(), vec![0xAA; 400], None, None).expect("A");

    // Delete A (space returned to free list)
    vault_delete(&mut handle, "a.txt".into()).expect("del A");

    // Write B using freed space — should succeed
    vault_write(&mut handle, "b.txt".into(), vec![0xBB; 400], None, None).expect("B from free list");

    let data = vault_read(&mut handle, "b.txt".into()).expect("read B").data;
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

    vault_write(&mut handle, "a.txt".into(), b"hello".to_vec(), None, None).expect("write");

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
            None,
        )
        .expect("write");
        vault_close(handle).expect("close");
    }

    {
        let mut handle = vault_open(path, test_key()).expect("open");
        let data = vault_read(&mut handle, "persist.txt".into()).expect("read").data;
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
        vault_write(&mut handle, "doc.txt".into(), b"shadow test".to_vec(), None, None).expect("write");
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
    let data = vault_read(&mut handle, "doc.txt".into()).expect("read").data;
    assert_eq!(data, b"shadow test");

    vault_close(handle).expect("close");
}

