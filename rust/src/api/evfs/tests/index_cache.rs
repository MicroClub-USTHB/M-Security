use super::*;

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
    let handle =
        vault_create(path.clone(), test_key(), "aes-256-gcm".into(), 1_048_576).expect("create");
    vault_close(handle).expect("close");

    let handle = vault_open(path, test_key()).expect("open");
    assert!(!handle.index_dirty);
    vault_close(handle).expect("close");
}

#[test]
fn test_index_clean_after_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);
    vault_write(&mut handle, "a.txt".into(), b"hello".to_vec(), None, None).expect("write");
    // After write completes, dirty flag should be cleared (flushed)
    assert!(!handle.index_dirty);
    vault_close(handle).expect("close");
}

#[test]
fn test_index_clean_after_delete() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);
    vault_write(&mut handle, "a.txt".into(), b"hello".to_vec(), None, None).expect("write");
    vault_delete(&mut handle, "a.txt".into()).expect("delete");
    assert!(!handle.index_dirty);
    vault_close(handle).expect("close");
}

#[test]
fn test_read_does_not_set_dirty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);
    vault_write(&mut handle, "a.txt".into(), b"hello".to_vec(), None, None).expect("write");
    assert!(!handle.index_dirty);

    let _ = vault_read(&mut handle, "a.txt".into()).expect("read").data;
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
    vault_write(&mut handle, "a.txt".into(), b"hello".to_vec(), None, None).expect("write");
    // Explicit flush then close — data must survive reopen
    vault_flush(&mut handle).expect("flush");
    assert!(!handle.index_dirty);
    vault_close(handle).expect("close");

    let mut reopened = vault_open(path, test_key()).expect("reopen");
    assert_eq!(
        vault_read(&mut reopened, "a.txt".into()).expect("read").data,
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
    vault_write(&mut handle, "b.txt".into(), b"world".to_vec(), None, None).expect("write");
    // Simulate a dirty handle at close time by manually setting the flag.
    // This exercises the vault_close dirty-flush path.
    handle.index_dirty = true;
    vault_close(handle).expect("close");

    let mut reopened = vault_open(path, test_key()).expect("reopen");
    assert_eq!(
        vault_read(&mut reopened, "b.txt".into()).expect("read").data,
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
    vault_write(&mut handle, "a.txt".into(), b"aaa".to_vec(), None, None).expect("write a");
    vault_write(&mut handle, "b.txt".into(), b"bbb".to_vec(), None, None).expect("write b");
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

