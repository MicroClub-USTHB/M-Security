use super::*;

// -- Segment Metadata ------------------------------------------------------

#[test]
fn test_metadata_write_read_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    let mut meta = std::collections::HashMap::new();
    meta.insert("mime".to_string(), "text/plain".to_string());
    meta.insert("created".to_string(), "2026-04-08".to_string());

    vault_write(
        &mut handle,
        "doc.txt".into(),
        b"hello metadata".to_vec(),
        None,
        Some(meta.clone()),
    )
    .expect("write");

    let result = vault_read(&mut handle, "doc.txt".into()).expect("read");
    assert_eq!(result.data, b"hello metadata");
    assert_eq!(result.metadata, meta);

    vault_close(handle).expect("close");
}

#[test]
fn test_metadata_none_returns_empty_map() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "plain.txt".into(), b"no meta".to_vec(), None, None).expect("write");

    let result = vault_read(&mut handle, "plain.txt".into()).expect("read");
    assert_eq!(result.data, b"no meta");
    assert!(result.metadata.is_empty());

    vault_close(handle).expect("close");
}

#[test]
fn test_metadata_overwrite_replaces_old() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    let mut meta_v1 = std::collections::HashMap::new();
    meta_v1.insert("version".to_string(), "1".to_string());

    vault_write(
        &mut handle,
        "doc.txt".into(),
        b"v1".to_vec(),
        None,
        Some(meta_v1),
    )
    .expect("write v1");

    let mut meta_v2 = std::collections::HashMap::new();
    meta_v2.insert("version".to_string(), "2".to_string());
    meta_v2.insert("author".to_string(), "test".to_string());

    vault_write(
        &mut handle,
        "doc.txt".into(),
        b"v2".to_vec(),
        None,
        Some(meta_v2.clone()),
    )
    .expect("write v2");

    let result = vault_read(&mut handle, "doc.txt".into()).expect("read");
    assert_eq!(result.data, b"v2");
    assert_eq!(result.metadata, meta_v2);

    vault_close(handle).expect("close");
}

#[test]
fn test_metadata_independent_per_segment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    let mut meta_a = std::collections::HashMap::new();
    meta_a.insert("type".to_string(), "image".to_string());
    let mut meta_b = std::collections::HashMap::new();
    meta_b.insert("type".to_string(), "document".to_string());

    vault_write(&mut handle, "a.png".into(), b"img".to_vec(), None, Some(meta_a.clone()))
        .expect("write a");
    vault_write(&mut handle, "b.pdf".into(), b"pdf".to_vec(), None, Some(meta_b.clone()))
        .expect("write b");

    let result_a = vault_read(&mut handle, "a.png".into()).expect("read a");
    let result_b = vault_read(&mut handle, "b.pdf".into()).expect("read b");

    assert_eq!(result_a.metadata, meta_a);
    assert_eq!(result_b.metadata, meta_b);

    vault_close(handle).expect("close");
}

#[test]
fn test_metadata_empty_keys_and_values() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    let mut meta = std::collections::HashMap::new();
    meta.insert("".to_string(), "empty key".to_string());
    meta.insert("empty_val".to_string(), "".to_string());

    vault_write(
        &mut handle,
        "edge.bin".into(),
        b"data".to_vec(),
        None,
        Some(meta.clone()),
    )
    .expect("write");

    let result = vault_read(&mut handle, "edge.bin".into()).expect("read");
    assert_eq!(result.metadata, meta);

    vault_close(handle).expect("close");
}

#[test]
fn test_metadata_survives_close_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = vault_path(&dir);

    let mut meta = std::collections::HashMap::new();
    meta.insert("persist".to_string(), "yes".to_string());

    {
        let mut handle =
            vault_create(path.clone(), test_key(), "aes-256-gcm".into(), 1_048_576).expect("create");
        vault_write(
            &mut handle,
            "persist.txt".into(),
            b"durable".to_vec(),
            None,
            Some(meta.clone()),
        )
        .expect("write");
        vault_close(handle).expect("close");
    }

    let mut handle = vault_open(path, test_key()).expect("reopen");
    let result = vault_read(&mut handle, "persist.txt".into()).expect("read");
    assert_eq!(result.data, b"durable");
    assert_eq!(result.metadata, meta);

    vault_close(handle).expect("close");
}

#[test]
fn test_metadata_survives_defragment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    let mut meta = std::collections::HashMap::new();
    meta.insert("tag".to_string(), "keep".to_string());

    vault_write(&mut handle, "a.txt".into(), vec![0xAA; 200], None, None).expect("write a");
    vault_write(
        &mut handle,
        "b.txt".into(),
        vec![0xBB; 200],
        None,
        Some(meta.clone()),
    )
    .expect("write b");

    vault_delete(&mut handle, "a.txt".into()).expect("delete a");
    vault_defragment(&mut handle).expect("defrag");

    let result = vault_read(&mut handle, "b.txt".into()).expect("read b");
    assert_eq!(result.data, vec![0xBB; 200]);
    assert_eq!(result.metadata, meta);

    vault_close(handle).expect("close");
}

#[test]
fn test_metadata_survives_resize() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    let mut meta = std::collections::HashMap::new();
    meta.insert("resize".to_string(), "test".to_string());

    vault_write(
        &mut handle,
        "doc.txt".into(),
        b"data".to_vec(),
        None,
        Some(meta.clone()),
    )
    .expect("write");

    vault_resize(&mut handle, 2_097_152).expect("grow");

    let result = vault_read(&mut handle, "doc.txt".into()).expect("read");
    assert_eq!(result.data, b"data");
    assert_eq!(result.metadata, meta);

    vault_close(handle).expect("close");
}

#[test]
fn test_metadata_survives_key_rotation() {
    let dir = tempfile::tempdir().expect("tempdir");

    let mut meta = std::collections::HashMap::new();
    meta.insert("mime".to_string(), "application/pdf".to_string());

    let mut handle = create_test_vault(&dir, 1_048_576);
    vault_write(
        &mut handle,
        "file.pdf".into(),
        b"pdf content".to_vec(),
        None,
        Some(meta.clone()),
    )
    .expect("write");

    let mut handle = vault_rotate_key(handle, test_key2()).expect("rotate");

    let result = vault_read(&mut handle, "file.pdf".into()).expect("read");
    assert_eq!(result.data, b"pdf content");
    assert_eq!(result.metadata, meta);

    vault_close(handle).expect("close");
}

#[test]
fn test_metadata_large_near_index_limit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    let mut meta = std::collections::HashMap::new();
    for i in 0..100 {
        meta.insert(format!("key_{i:03}"), format!("value_{i:03}_padding"));
    }

    vault_write(
        &mut handle,
        "big_meta.bin".into(),
        b"data".to_vec(),
        None,
        Some(meta.clone()),
    )
    .expect("write");

    let result = vault_read(&mut handle, "big_meta.bin".into()).expect("read");
    assert_eq!(result.data, b"data");
    assert_eq!(result.metadata, meta);

    vault_close(handle).expect("close");
}

#[test]
fn test_metadata_rename_preserves() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    let mut meta = std::collections::HashMap::new();
    meta.insert("tag".to_string(), "renamed".to_string());

    vault_write(
        &mut handle,
        "old_name.txt".into(),
        b"data".to_vec(),
        None,
        Some(meta.clone()),
    )
    .expect("write");

    vault_rename_segment(&mut handle, "old_name.txt".into(), "new_name.txt".into())
        .expect("rename");

    let result = vault_read(&mut handle, "new_name.txt".into()).expect("read");
    assert_eq!(result.data, b"data");
    assert_eq!(result.metadata, meta);

    vault_close(handle).expect("close");
}
