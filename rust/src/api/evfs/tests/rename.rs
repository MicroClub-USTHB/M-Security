use super::*;

// -- Rename Segment Tests -----------------------------------------------

#[test]
fn test_rename_read_success() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "old.txt".into(), b"data".to_vec(), None, None).expect("write");
    vault_rename_segment(&mut handle, "old.txt".into(), "new.txt".into()).expect("rename");

    let data = vault_read(&mut handle, "new.txt".into()).expect("read new").data;
    assert_eq!(data, b"data");

    let result = vault_read(&mut handle, "old.txt".into());
    assert!(matches!(result, Err(CryptoError::SegmentNotFound(_))));

    vault_close(handle).expect("close");
}

#[test]
fn test_rename_duplicate_name_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "a.txt".into(), b"a".to_vec(), None, None).expect("write a");
    vault_write(&mut handle, "b.txt".into(), b"b".to_vec(), None, None).expect("write b");

    let result = vault_rename_segment(&mut handle, "a.txt".into(), "b.txt".into());
    assert!(matches!(result, Err(CryptoError::DuplicateSegment(_))));

    vault_close(handle).expect("close");
}

#[test]
fn test_rename_nonexistent_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    let result = vault_rename_segment(&mut handle, "missing.txt".into(), "new.txt".into());
    assert!(matches!(result, Err(CryptoError::SegmentNotFound(_))));

    vault_close(handle).expect("close");
}

#[test]
fn test_rename_preserves_metadata() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "old.txt".into(), b"data".to_vec(), None, None).expect("write");
    let old_entry = handle.index.find("old.txt").expect("find").clone();

    vault_rename_segment(&mut handle, "old.txt".into(), "new.txt".into()).expect("rename");
    let new_entry = handle.index.find("new.txt").expect("find");

    assert_eq!(old_entry.offset, new_entry.offset);
    assert_eq!(old_entry.size, new_entry.size);
    assert_eq!(old_entry.generation, new_entry.generation);
    assert_eq!(old_entry.checksum, new_entry.checksum);
    assert_eq!(old_entry.compression, new_entry.compression);
    assert_eq!(old_entry.chunk_count, new_entry.chunk_count);

    vault_close(handle).expect("close");
}

#[test]
fn test_rename_multiple_sequence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "1.txt".into(), b"sequence".to_vec(), None, None).expect("write");
    vault_rename_segment(&mut handle, "1.txt".into(), "2.txt".into()).expect("r1");
    vault_rename_segment(&mut handle, "2.txt".into(), "3.txt".into()).expect("r2");

    assert!(handle.index.find("1.txt").is_none());
    assert!(handle.index.find("2.txt").is_none());

    let data = vault_read(&mut handle, "3.txt".into()).expect("read").data;
    assert_eq!(data, b"sequence");

    vault_close(handle).expect("close");
}

#[test]
fn test_rename_streaming_segment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 2_097_152);

    let data = vec![0x77; 150_000];
    let chunks: Vec<Vec<u8>> = data.chunks(65536).map(|c| c.to_vec()).collect();
    vault_write_stream(
        &mut handle,
        "stream.bin".into(),
        data.len() as u64,
        chunks.into_iter(),
        None,
    )
    .expect("write stream");

    vault_rename_segment(
        &mut handle,
        "stream.bin".into(),
        "renamed_stream.bin".into(),
    )
    .expect("rename");

    // Interop read on streaming segment
    let readback = vault_read(&mut handle, "renamed_stream.bin".into()).expect("read").data;
    assert_eq!(readback, data);

    vault_close(handle).expect("close");
}

#[test]
fn test_rename_and_defragment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "a.txt".into(), vec![0xAA; 100], None, None).expect("A");
    vault_write(&mut handle, "b.txt".into(), vec![0xBB; 100], None, None).expect("B");
    vault_write(&mut handle, "c.txt".into(), vec![0xCC; 100], None, None).expect("C");

    vault_delete(&mut handle, "b.txt".into()).expect("del B");
    vault_rename_segment(&mut handle, "c.txt".into(), "c_renamed.txt".into()).expect("rename");

    vault_defragment(&mut handle).expect("defrag");

    let data = vault_read(&mut handle, "c_renamed.txt".into()).expect("read").data;
    assert_eq!(data, vec![0xCC; 100]);

    vault_close(handle).expect("close");
}

#[test]
fn test_rename_chacha20() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);
    let mut handle =
        vault_create(path, test_key(), "chacha20-poly1305".into(), 1_048_576).expect("create");

    vault_write(
        &mut handle,
        "old_chacha.txt".into(),
        b"chacha".to_vec(),
        None,
        None,
    )
    .expect("write");
    vault_rename_segment(
        &mut handle,
        "old_chacha.txt".into(),
        "new_chacha.txt".into(),
    )
    .expect("rename");

    let data = vault_read(&mut handle, "new_chacha.txt".into()).expect("read").data;
    assert_eq!(data, b"chacha");

    vault_close(handle).expect("close");
}

#[test]
fn test_rename_to_same_name_is_noop() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "same.txt".into(), b"data".to_vec(), None, None).expect("write");
    vault_rename_segment(&mut handle, "same.txt".into(), "same.txt".into()).expect("noop rename");

    let data = vault_read(&mut handle, "same.txt".into()).expect("read").data;
    assert_eq!(data, b"data");

    vault_close(handle).expect("close");
}

