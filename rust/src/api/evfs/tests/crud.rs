use super::*;

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
        vault_write(&mut handle, "a.txt".into(), b"data-A".to_vec(), None, None).expect("write A");
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
        vault_write(&mut handle, "b.txt".into(), b"data-B".to_vec(), None, None).expect("write B");
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
    let data = vault_read(&mut handle, "a.txt".into()).expect("read A").data;
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

    vault_write(&mut handle, "doc.txt".into(), b"hello vault".to_vec(), None, None).expect("write");

    let data = vault_read(&mut handle, "doc.txt".into()).expect("read").data;
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
        vault_write(&mut handle, name, data, None, None).expect("write");
    }

    for i in 0..5 {
        let name = format!("seg{i}.bin");
        let expected = format!("data for segment {i}").into_bytes();
        let data = vault_read(&mut handle, name).expect("read").data;
        assert_eq!(data, expected);
    }

    assert_eq!(vault_list(&handle).len(), 5);
    vault_close(handle).expect("close");
}

#[test]
fn test_write_overwrite() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "doc.txt".into(), b"version 1".to_vec(), None, None).expect("write v1");
    vault_write(&mut handle, "doc.txt".into(), b"version 2".to_vec(), None, None).expect("write v2");

    let data = vault_read(&mut handle, "doc.txt".into()).expect("read").data;
    assert_eq!(data, b"version 2");
    assert_eq!(vault_list(&handle).len(), 1);

    vault_close(handle).expect("close");
}

#[test]
fn test_write_overwrite_increments_generation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "doc.txt".into(), b"v1".to_vec(), None, None).expect("write v1");
    let gen1 = handle.index.find("doc.txt").expect("find").generation;

    vault_write(&mut handle, "doc.txt".into(), b"v2".to_vec(), None, None).expect("write v2");
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

