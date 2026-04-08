use super::*;

// -- Streaming Read & Interop Tests -------------------------------------
#[test]
fn test_oneshot_write_oneshot_read_interop() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    let data = b"monolithic data".to_vec();
    vault_write(&mut handle, "mono.txt".into(), data.clone(), None, None).expect("write");

    let entry = handle.index.find("mono.txt").expect("find");
    assert_eq!(entry.chunk_count, 0, "Should be written as monolithic");

    let read_back = vault_read(&mut handle, "mono.txt".into()).expect("read").data;
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
        None,
    )
    .expect("stream write");

    let entry = handle.index.find("streamed.bin").expect("find");
    assert!(entry.chunk_count > 0, "Should be written as chunked");

    // Read using one-shot (interop) testing the chunk-assembly loop
    let read_back = vault_read(&mut handle, "streamed.bin".into()).expect("read").data;
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
        None,
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
        None,
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
        None,
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

#[test]
fn test_stream_write_read_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    // 2MB vault to fit the streaming overhead
    let mut handle = create_test_vault(&dir, 2 * 1024 * 1024);

    let data = vec![0x42u8; 200_000]; // ~3 chunks
    stream_write_chunks(&mut handle, "video.bin", &data, 4096).expect("stream write");

    let readback = vault_read(&mut handle, "video.bin".into()).expect("read").data;
    assert_eq!(readback, data);

    vault_close(handle).expect("close");
}

#[test]
fn test_stream_write_single_byte() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    let data = vec![0xAA; 1];
    stream_write_chunks(&mut handle, "tiny.bin", &data, 1).expect("stream write");

    let readback = vault_read(&mut handle, "tiny.bin".into()).expect("read").data;
    assert_eq!(readback, data);

    vault_close(handle).expect("close");
}

#[test]
fn test_stream_write_empty_segment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    // 0 bytes — still produces 1 padded chunk
    vault_write_stream(&mut handle, "empty.bin".into(), 0, std::iter::empty(), None)
        .expect("stream write empty");

    let readback = vault_read(&mut handle, "empty.bin".into()).expect("read").data;
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

    let readback = vault_read(&mut handle, "aligned.bin".into()).expect("read").data;
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
        None,
    )
    .expect("write");

    // Overwrite with streaming (larger)
    let new_data = vec![0xCC; 100_000];
    stream_write_chunks(&mut handle, "doc.txt", &new_data, 8192).expect("stream overwrite");

    let readback = vault_read(&mut handle, "doc.txt".into()).expect("read").data;
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

    let readback = vault_read(&mut handle, "file.bin".into()).expect("read").data;
    assert_eq!(readback, smaller);

    vault_close(handle).expect("close");
}

#[test]
fn test_stream_write_wrong_size_too_few_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 1_048_576);

    // Claim 1000 bytes but provide only 500
    let data = vec![0xAA; 500];
    let result = vault_write_stream(&mut handle, "bad.bin".into(), 1000, vec![data].into_iter(), None);
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
    let result = vault_write_stream(&mut handle, "bad.bin".into(), 500, vec![data].into_iter(), None);
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
    let readback = vault_read(&mut handle, "persist.bin".into()).expect("read").data;
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

    let readback = vault_read(&mut handle, "chacha.bin".into()).expect("read").data;
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
        None,
    )
    .expect("stream write");

    let readback = vault_read(&mut handle, "irregular.bin".into()).expect("read").data;
    assert_eq!(readback, data);

    vault_close(handle).expect("close");
}

#[test]
fn test_stream_write_coexists_with_monolithic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut handle = create_test_vault(&dir, 2 * 1024 * 1024);

    // Write monolithic
    vault_write(&mut handle, "mono.txt".into(), b"mono data".to_vec(), None, None).expect("write mono");

    // Write streaming
    let stream_data = vec![0xFF; 80_000];
    stream_write_chunks(&mut handle, "stream.bin", &stream_data, 4096).expect("stream write");

    // Read both back
    let mono = vault_read(&mut handle, "mono.txt".into()).expect("read mono").data;
    assert_eq!(mono, b"mono data");

    let stream = vault_read(&mut handle, "stream.bin".into()).expect("read stream").data;
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

    let oneshot = vault_read(&mut handle, "video.bin".into()).expect("oneshot read").data;
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

    vault_write_stream(&mut handle, "empty.bin".into(), 0, std::iter::empty(), None)
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
        None,
    )
    .expect("write stream");

    let readback = vault_read(&mut handle, "from_file.bin".into()).expect("read").data;
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
        None,
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
        None,
    )
    .expect("write stream");

    let readback = vault_read(&mut handle, "large.bin".into()).expect("read").data;
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
    vault_write_stream(&mut handle, "empty.bin".into(), 0, chunks.into_iter(), None)
        .expect("write stream");

    let readback = vault_read(&mut handle, "empty.bin".into()).expect("read").data;
    assert!(readback.is_empty());

    vault_close(handle).expect("close");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

