use super::*;

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
        data[..ARCHIVE_HEADER_SIZE]
            .try_into()
            .expect("header slice"),
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
        // v2: read metadata after encrypted_data
        let (seg_meta, meta_consumed) = if header.version >= 2 {
            SegmentRecord::read_metadata(&data[pos..]).expect("parse metadata")
        } else {
            (std::collections::HashMap::new(), 0)
        };
        pos += meta_consumed;
        records.push(SegmentRecord {
            name,
            compression,
            checksum,
            encrypted_data: enc_data,
            metadata: seg_meta,
        });
    }

    let trailer_bytes: [u8; ARCHIVE_TRAILER_SIZE] = data[pos..pos + ARCHIVE_TRAILER_SIZE]
        .try_into()
        .expect("trailer slice");
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
        metadata: std::collections::HashMap::new(),
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

    vault_write(&mut handle, "a.txt".into(), b"hello".to_vec(), None, None).expect("write");
    vault_write(&mut handle, "b.txt".into(), b"world".to_vec(), None, None).expect("write");

    let epath = export_path(&dir);
    vault_export(&mut handle, wrapping_key(), epath.clone()).expect("export");

    let (header, wrapped_key, records, _) = parse_archive(&epath);
    assert_eq!(header.segment_count, 2);
    assert_eq!(header.version, 2);
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
        None,
    )
    .expect("stream write");

    // Also write a monolithic segment
    vault_write(&mut handle, "small.txt".into(), b"tiny".to_vec(), None, None).expect("write");

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
        None,
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

    vault_write(&mut handle, "a.txt".into(), b"data-A".to_vec(), None, None).expect("write");
    vault_write(&mut handle, "b.txt".into(), b"data-B".to_vec(), None, None).expect("write");

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
    let a = vault_read(&mut handle, "a.txt".into()).expect("read a").data;
    assert_eq!(a, b"data-A");
    let b = vault_read(&mut handle, "b.txt".into()).expect("read b").data;
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

    vault_write(&mut handle, "a.txt".into(), b"hello".to_vec(), None, None).expect("write");
    vault_write(&mut handle, "b.txt".into(), b"world".to_vec(), None, None).expect("write");

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
        vault_read(&mut imported, "a.txt".into()).expect("read a").data,
        b"hello"
    );
    assert_eq!(
        vault_read(&mut imported, "b.txt".into()).expect("read b").data,
        b"world"
    );

    vault_close(imported).expect("close");
}

#[test]
fn test_import_wrong_wrapping_key_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    vault_write(&mut handle, "a.txt".into(), b"hello".to_vec(), None, None).expect("write");
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
    vault_write(&mut handle, "a.txt".into(), b"hello".to_vec(), None, None).expect("write");
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
    vault_write(&mut handle, "a.txt".into(), b"hello".to_vec(), None, None).expect("write");
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
    vault_write(&mut handle, "a.txt".into(), b"hello".to_vec(), None, None).expect("write");
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
    vault_write(&mut handle, "big.txt".into(), vec![0xBB; 2_000_000], None, None).expect("write");
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
        None,
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

    let readback = vault_read(&mut imported, "stream.bin".into()).expect("read").data;
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
        None,
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

    let readback = vault_read(&mut imported, "compressed.txt".into()).expect("read").data;
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

    vault_write(&mut handle, "c.txt".into(), b"chacha".to_vec(), None, None).expect("write");
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
        vault_read(&mut imported, "c.txt".into()).expect("read c").data,
        b"chacha"
    );

    vault_close(imported).expect("close");
}

#[test]
fn test_export_import_preserves_metadata() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    let mut meta = std::collections::HashMap::new();
    meta.insert("mime".to_string(), "text/plain".to_string());
    meta.insert("author".to_string(), "test".to_string());

    vault_write(
        &mut handle,
        "doc.txt".into(),
        b"hello".to_vec(),
        None,
        Some(meta.clone()),
    )
    .expect("write");
    vault_write(&mut handle, "bare.txt".into(), b"no meta".to_vec(), None, None).expect("write");

    let epath = export_path(&dir);
    vault_export(&mut handle, wrapping_key(), epath.clone()).expect("export");
    vault_close(handle).expect("close");

    let dest = dir
        .path()
        .join("imported.vault")
        .to_str()
        .expect("path")
        .to_string();

    vault_import(epath, wrapping_key(), dest.clone(), test_key2(), "aes-256-gcm".into(), 1_048_576).expect("import");

    let mut imported = vault_open(dest, test_key2()).expect("open");

    let result = vault_read(&mut imported, "doc.txt".into()).expect("read doc");
    assert_eq!(result.data, b"hello");
    assert_eq!(result.metadata, meta);

    let bare = vault_read(&mut imported, "bare.txt".into()).expect("read bare");
    assert!(bare.metadata.is_empty());

    vault_close(imported).expect("close");
}

