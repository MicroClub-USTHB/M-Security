use super::*;

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
    vault_write(&mut handle, "data.txt".into(), data.clone(), Some(config), None).expect("write");
    let read_back = vault_read(&mut handle, "data.txt".into()).expect("read").data;
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
    vault_write(&mut handle, "notes.md".into(), data.clone(), Some(config), None).expect("write");
    let read_back = vault_read(&mut handle, "notes.md".into()).expect("read").data;
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
    vault_write(&mut handle, "raw.bin".into(), data.clone(), Some(config), None).expect("write");
    let read_back = vault_read(&mut handle, "raw.bin".into()).expect("read").data;
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
        None,
    )
    .expect("write");

    let entry = handle.index.find("photo.jpg").expect("find");
    assert_eq!(entry.compression, CompressionAlgorithm::None);

    let data = vault_read(&mut handle, "photo.jpg".into()).expect("read").data;
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
    vault_write(&mut handle, "auto.txt".into(), data.clone(), Some(config), None).expect("write");

    // Read back — decompression is automatic (no config needed)
    let read_back = vault_read(&mut handle, "auto.txt".into()).expect("read").data;
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
        None,
    )
    .expect("zstd");
    vault_write(
        &mut handle,
        "data.bin".into(),
        binary.clone(),
        Some(brotli_conf),
        None,
    )
    .expect("brotli");
    vault_write(&mut handle, "raw.dat".into(), raw.clone(), None, None).expect("none");

    assert_eq!(vault_read(&mut handle, "text.txt".into()).expect("r").data, text);
    assert_eq!(
        vault_read(&mut handle, "data.bin".into()).expect("r").data,
        binary
    );
    assert_eq!(vault_read(&mut handle, "raw.dat".into()).expect("r").data, raw);

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
    vault_write(&mut handle, "check.txt".into(), data.clone(), Some(config), None).expect("write");

    // Verify the stored checksum matches original plaintext (not compressed form)
    let entry = handle.index.find("check.txt").expect("find");
    assert!(segment::verify_checksum(&data, &entry.checksum));

    vault_close(handle).expect("close");
}

