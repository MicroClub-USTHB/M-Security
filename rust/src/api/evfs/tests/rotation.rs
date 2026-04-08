use super::*;

// -- Key Rotation -----------------------------------------------------------

#[test]
fn test_rotate_key_basic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "a.txt".into(), b"hello".to_vec(), None, None).expect("write a");
    vault_write(&mut handle, "b.txt".into(), b"world".to_vec(), None, None).expect("write b");

    let mut handle = vault_rotate_key(handle, test_key2()).expect("rotate");

    assert_eq!(
        vault_read(&mut handle, "a.txt".into()).expect("read a").data,
        b"hello"
    );
    assert_eq!(
        vault_read(&mut handle, "b.txt".into()).expect("read b").data,
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
        vault_read(&mut handle, "secret.txt".into()).expect("read").data,
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

    let readback = vault_read(&mut handle, "video.bin".into()).expect("read after rotate").data;
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
    vault_write(&mut handle, "data.bin".into(), data.clone(), Some(config), None).expect("write");

    let mut handle = vault_rotate_key(handle, test_key2()).expect("rotate");

    let readback = vault_read(&mut handle, "data.bin".into()).expect("read after rotate").data;
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
        None,
    )
    .expect("write");

    let mut handle = vault_rotate_key(handle, test_key2()).expect("rotate chacha20 vault");

    let readback = vault_read(&mut handle, "msg.txt".into()).expect("read after rotate").data;
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
        None,
    )
    .expect("write");

    // First rotation: test_key → new_key
    let handle = vault_rotate_key(handle, test_key2()).expect("first rotation");
    // Second rotation: new_key → wrong_key
    let mut handle = vault_rotate_key(handle, wrong_key()).expect("second rotation");

    let readback = vault_read(&mut handle, "doc.txt".into()).expect("read after two rotations").data;
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

