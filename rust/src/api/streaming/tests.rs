//! Tests for the streaming encryption/decryption/compression/hashing pipeline.

use super::*;
#[cfg(feature = "compression")]
use crate::api::compression::CompressionAlgorithm;
use crate::api::encryption::{create_aes256_gcm, generate_aes256_gcm_key};
use crate::api::encryption::{create_chacha20_poly1305, generate_chacha20_poly1305_key};
use crate::core::streaming::{
    ChunkReader, EncryptedChunk, CHUNK_SIZE, ENCRYPTED_CHUNK_SIZE, STREAM_HEADER_SIZE,
};
use std::fs;
use std::fs::File;
use std::io::BufReader;

fn make_aes_cipher() -> CipherHandle {
    let key = generate_aes256_gcm_key().expect("keygen");
    create_aes256_gcm(key).expect("cipher")
}

fn make_chacha_cipher() -> CipherHandle {
    let key = generate_chacha20_poly1305_key().expect("keygen");
    create_chacha20_poly1305(key).expect("cipher")
}

fn noop_progress(_: f64) {}

/// Encrypt -> decrypt -> compare bytes.
fn roundtrip_test(cipher: &CipherHandle, original: &[u8]) {
    let dir = tempfile::tempdir().expect("tmpdir");
    let input = dir.path().join("input.bin");
    let encrypted = dir.path().join("encrypted.bin");
    let decrypted = dir.path().join("decrypted.bin");

    fs::write(&input, original).expect("write input");

    encrypt_file_impl(
        cipher,
        input.to_str().expect("path"),
        encrypted.to_str().expect("path"),
        &noop_progress,
    )
    .expect("encrypt");

    // Verify uniform chunk sizes
    let enc_size = fs::metadata(&encrypted).expect("stat").len() as usize;
    let data_portion = enc_size - STREAM_HEADER_SIZE;
    assert_eq!(data_portion % ENCRYPTED_CHUNK_SIZE, 0, "Chunks not uniform");

    decrypt_file_impl(
        cipher,
        encrypted.to_str().expect("path"),
        decrypted.to_str().expect("path"),
        &noop_progress,
    )
    .expect("decrypt");

    let result = fs::read(&decrypted).expect("read output");
    assert_eq!(result, original, "Roundtrip mismatch");
}

#[test]
fn test_encrypt_decrypt_roundtrip() {
    roundtrip_test(&make_aes_cipher(), b"Hello, streaming encryption!");
}

#[test]
fn test_small_file() {
    roundtrip_test(&make_aes_cipher(), &[0x42; 100]);
}

#[test]
fn test_exact_chunk_boundary() {
    roundtrip_test(&make_aes_cipher(), &vec![0xAB; CHUNK_SIZE]);
}

#[test]
fn test_multi_chunk() {
    roundtrip_test(&make_aes_cipher(), &vec![0xCD; 200 * 1024]);
}

#[test]
fn test_empty_file() {
    roundtrip_test(&make_aes_cipher(), &[]);
}

#[test]
fn test_chacha20_roundtrip() {
    roundtrip_test(&make_chacha_cipher(), b"ChaCha20 streaming test data");
}

#[test]
fn test_wrong_key_fails() {
    let cipher1 = make_aes_cipher();
    let cipher2 = make_aes_cipher();

    let dir = tempfile::tempdir().expect("tmpdir");
    let input = dir.path().join("input.bin");
    let encrypted = dir.path().join("encrypted.bin");
    let decrypted = dir.path().join("decrypted.bin");

    fs::write(&input, b"secret data").expect("write");
    encrypt_file_impl(
        &cipher1,
        input.to_str().expect("p"),
        encrypted.to_str().expect("p"),
        &noop_progress,
    )
    .expect("encrypt");

    let result = decrypt_file_impl(
        &cipher2,
        encrypted.to_str().expect("p"),
        decrypted.to_str().expect("p"),
        &noop_progress,
    );
    assert!(result.is_err(), "Should fail with wrong key");
}

#[test]
fn test_wrong_key_leaves_no_output() {
    let cipher1 = make_aes_cipher();
    let cipher2 = make_aes_cipher();

    let dir = tempfile::tempdir().expect("tmpdir");
    let input = dir.path().join("input.bin");
    let encrypted = dir.path().join("encrypted.bin");
    let decrypted = dir.path().join("decrypted.bin");

    fs::write(&input, b"secret data").expect("write");
    encrypt_file_impl(
        &cipher1,
        input.to_str().expect("p"),
        encrypted.to_str().expect("p"),
        &noop_progress,
    )
    .expect("encrypt");

    let _ = decrypt_file_impl(
        &cipher2,
        encrypted.to_str().expect("p"),
        decrypted.to_str().expect("p"),
        &noop_progress,
    );

    assert!(
        !decrypted.exists(),
        "Output file should not exist after failed decrypt"
    );
    let tmp = format!("{}.tmp", decrypted.to_str().expect("p"));
    assert!(
        !std::path::Path::new(&tmp).exists(),
        "Temp file should be cleaned up"
    );
}

#[test]
fn test_chunk_reorder_detected() {
    let cipher = make_aes_cipher();
    let dir = tempfile::tempdir().expect("tmpdir");
    let input = dir.path().join("input.bin");
    let encrypted = dir.path().join("encrypted.bin");
    let tampered = dir.path().join("tampered.bin");
    let decrypted = dir.path().join("decrypted.bin");

    fs::write(&input, vec![0xAA; CHUNK_SIZE * 3]).expect("write");
    encrypt_file_impl(
        &cipher,
        input.to_str().expect("p"),
        encrypted.to_str().expect("p"),
        &noop_progress,
    )
    .expect("encrypt");

    // Swap chunk 0 and chunk 1
    let mut data = fs::read(&encrypted).expect("read");
    let c0 = STREAM_HEADER_SIZE;
    let c1 = c0 + ENCRYPTED_CHUNK_SIZE;
    let chunk0: Vec<u8> = data[c0..c1].to_vec();
    let chunk1: Vec<u8> = data[c1..c1 + ENCRYPTED_CHUNK_SIZE].to_vec();
    data[c0..c1].copy_from_slice(&chunk1);
    data[c1..c1 + ENCRYPTED_CHUNK_SIZE].copy_from_slice(&chunk0);
    fs::write(&tampered, &data).expect("write tampered");

    let result = decrypt_file_impl(
        &cipher,
        tampered.to_str().expect("p"),
        decrypted.to_str().expect("p"),
        &noop_progress,
    );
    assert!(result.is_err(), "Should detect chunk reorder");
}

#[test]
fn test_chunk_deletion_detected() {
    let cipher = make_aes_cipher();
    let dir = tempfile::tempdir().expect("tmpdir");
    let input = dir.path().join("input.bin");
    let encrypted = dir.path().join("encrypted.bin");
    let tampered = dir.path().join("tampered.bin");
    let decrypted = dir.path().join("decrypted.bin");

    fs::write(&input, vec![0xBB; CHUNK_SIZE * 3]).expect("write");
    encrypt_file_impl(
        &cipher,
        input.to_str().expect("p"),
        encrypted.to_str().expect("p"),
        &noop_progress,
    )
    .expect("encrypt");

    // Remove the middle chunk
    let data = fs::read(&encrypted).expect("read");
    let mut deleted = Vec::new();
    deleted.extend_from_slice(&data[..STREAM_HEADER_SIZE + ENCRYPTED_CHUNK_SIZE]);
    deleted.extend_from_slice(&data[STREAM_HEADER_SIZE + 2 * ENCRYPTED_CHUNK_SIZE..]);
    fs::write(&tampered, &deleted).expect("write tampered");

    let result = decrypt_file_impl(
        &cipher,
        tampered.to_str().expect("p"),
        decrypted.to_str().expect("p"),
        &noop_progress,
    );
    assert!(result.is_err(), "Should detect chunk deletion");
}

#[test]
fn test_truncation_detected() {
    let cipher = make_aes_cipher();
    let dir = tempfile::tempdir().expect("tmpdir");
    let input = dir.path().join("input.bin");
    let encrypted = dir.path().join("encrypted.bin");
    let tampered = dir.path().join("tampered.bin");
    let decrypted = dir.path().join("decrypted.bin");

    fs::write(&input, vec![0xCC; CHUNK_SIZE + 100]).expect("write");
    encrypt_file_impl(
        &cipher,
        input.to_str().expect("p"),
        encrypted.to_str().expect("p"),
        &noop_progress,
    )
    .expect("encrypt");

    // Keep only header + first chunk (remove final chunk)
    let data = fs::read(&encrypted).expect("read");
    let truncated = &data[..STREAM_HEADER_SIZE + ENCRYPTED_CHUNK_SIZE];
    fs::write(&tampered, truncated).expect("write tampered");

    let result = decrypt_file_impl(
        &cipher,
        tampered.to_str().expect("p"),
        decrypted.to_str().expect("p"),
        &noop_progress,
    );
    assert!(result.is_err(), "Should detect truncation");
}

#[test]
fn test_uniform_chunk_sizes() {
    let cipher = make_aes_cipher();
    let dir = tempfile::tempdir().expect("tmpdir");
    let input = dir.path().join("input.bin");
    let encrypted = dir.path().join("encrypted.bin");

    fs::write(&input, [0xDD; 100]).expect("write");
    encrypt_file_impl(
        &cipher,
        input.to_str().expect("p"),
        encrypted.to_str().expect("p"),
        &noop_progress,
    )
    .expect("encrypt");

    let enc_size = fs::metadata(&encrypted).expect("stat").len() as usize;
    let data_portion = enc_size - STREAM_HEADER_SIZE;
    assert_eq!(data_portion, ENCRYPTED_CHUNK_SIZE);
}

#[test]
fn test_padding_stripped_correctly() {
    let cipher = make_aes_cipher();
    let original = vec![0xEE; 100];
    let dir = tempfile::tempdir().expect("tmpdir");
    let input = dir.path().join("input.bin");
    let encrypted = dir.path().join("encrypted.bin");
    let decrypted = dir.path().join("decrypted.bin");

    fs::write(&input, &original).expect("write");
    encrypt_file_impl(
        &cipher,
        input.to_str().expect("p"),
        encrypted.to_str().expect("p"),
        &noop_progress,
    )
    .expect("encrypt");
    decrypt_file_impl(
        &cipher,
        encrypted.to_str().expect("p"),
        decrypted.to_str().expect("p"),
        &noop_progress,
    )
    .expect("decrypt");

    let result = fs::read(&decrypted).expect("read");
    assert_eq!(result.len(), 100);
    assert_eq!(result, original);
}

#[test]
fn test_progress_values() {
    let cipher = make_aes_cipher();
    let dir = tempfile::tempdir().expect("tmpdir");
    let input = dir.path().join("input.bin");
    let encrypted = dir.path().join("encrypted.bin");
    let decrypted = dir.path().join("decrypted.bin");

    // 3 full chunks -> 3 intermediate + 1 empty final = 4 total
    fs::write(&input, vec![0xAA; CHUNK_SIZE * 3]).expect("write");

    let enc_progress = std::sync::Mutex::new(Vec::new());
    encrypt_file_impl(
        &cipher,
        input.to_str().expect("p"),
        encrypted.to_str().expect("p"),
        &|p| enc_progress.lock().expect("lock").push(p),
    )
    .expect("encrypt");

    let vals = enc_progress.lock().expect("lock");
    assert!(!vals.is_empty());
    assert!((vals.last().copied().unwrap_or(0.0) - 1.0).abs() < f64::EPSILON);
    for &v in &vals[..vals.len() - 1] {
        assert!(v < 1.0, "Intermediate progress should be < 1.0, got {v}");
    }

    let dec_progress = std::sync::Mutex::new(Vec::new());
    decrypt_file_impl(
        &cipher,
        encrypted.to_str().expect("p"),
        decrypted.to_str().expect("p"),
        &|p| dec_progress.lock().expect("lock").push(p),
    )
    .expect("decrypt");

    let vals = dec_progress.lock().expect("lock");
    assert!(!vals.is_empty());
    assert!((vals.last().copied().unwrap_or(0.0) - 1.0).abs() < f64::EPSILON);
}

#[test]
fn test_chunk_reuse_no_allocation() {
    let cipher = make_aes_cipher();
    let dir = tempfile::tempdir().expect("tmpdir");
    let input = dir.path().join("input.bin");
    let encrypted = dir.path().join("encrypted.bin");

    fs::write(&input, vec![0xFF; CHUNK_SIZE * 3]).expect("write");
    encrypt_file_impl(
        &cipher,
        input.to_str().expect("p"),
        encrypted.to_str().expect("p"),
        &noop_progress,
    )
    .expect("encrypt");

    let file = File::open(&encrypted).expect("open");
    let mut reader = ChunkReader::new(BufReader::new(file));
    let _header = reader.read_header().expect("header");

    let mut chunk = EncryptedChunk::new();
    let chunk_ptr = chunk.ciphertext.as_ptr();

    let mut count = 0;
    while reader.read_chunk(&mut chunk).expect("read") {
        assert_eq!(
            chunk.ciphertext.as_ptr(),
            chunk_ptr,
            "Chunk buffer was reallocated"
        );
        count += 1;
    }
    assert!(count > 0);
}

#[test]
fn test_no_temp_file_left_on_success() {
    let cipher = make_aes_cipher();
    let dir = tempfile::tempdir().expect("tmpdir");
    let input = dir.path().join("input.bin");
    let encrypted = dir.path().join("encrypted.bin");

    fs::write(&input, b"data").expect("write");
    encrypt_file_impl(
        &cipher,
        input.to_str().expect("p"),
        encrypted.to_str().expect("p"),
        &noop_progress,
    )
    .expect("encrypt");

    assert!(encrypted.exists(), "Output should exist");
    let tmp = format!("{}.tmp", encrypted.to_str().expect("p"));
    assert!(
        !std::path::Path::new(&tmp).exists(),
        "Temp file should be gone after success"
    );
}

// -- Streaming hash tests -----------------------------------------------------

fn make_blake3_hasher() -> HasherHandle {
    crate::api::hashing::create_blake3()
}

fn make_sha3_hasher() -> HasherHandle {
    crate::api::hashing::create_sha3()
}

#[test]
fn test_streaming_hash_matches_oneshot_blake3() {
    let data = b"Hello, streaming hash with BLAKE3!";
    let dir = tempfile::tempdir().expect("tmpdir");
    let path = dir.path().join("input.bin");
    fs::write(&path, data).expect("write");

    let hasher = make_blake3_hasher();
    let digest =
        hash::hash_file_impl(&hasher, path.to_str().expect("p"), &noop_progress).expect("hash");

    let oneshot = crate::api::hashing::blake3_hash(data.to_vec());
    assert_eq!(digest, oneshot);
}

#[test]
fn test_streaming_hash_matches_oneshot_sha3() {
    let data = b"Hello, streaming hash with SHA-3!";
    let dir = tempfile::tempdir().expect("tmpdir");
    let path = dir.path().join("input.bin");
    fs::write(&path, data).expect("write");

    let hasher = make_sha3_hasher();
    let digest =
        hash::hash_file_impl(&hasher, path.to_str().expect("p"), &noop_progress).expect("hash");

    let oneshot = crate::api::hashing::sha3_hash(data.to_vec());
    assert_eq!(digest, oneshot);
}

#[test]
fn test_streaming_hash_empty_file() {
    let dir = tempfile::tempdir().expect("tmpdir");
    let path = dir.path().join("empty.bin");
    fs::write(&path, b"").expect("write");

    let hasher = make_blake3_hasher();
    let digest =
        hash::hash_file_impl(&hasher, path.to_str().expect("p"), &noop_progress).expect("hash");

    let oneshot = crate::api::hashing::blake3_hash(Vec::new());
    assert_eq!(digest, oneshot);
}

#[test]
fn test_streaming_hash_large_file() {
    let data = vec![0xAB; 1024 * 1024 + 37];
    let dir = tempfile::tempdir().expect("tmpdir");
    let path = dir.path().join("large.bin");
    fs::write(&path, &data).expect("write");

    let hasher = make_blake3_hasher();
    let digest =
        hash::hash_file_impl(&hasher, path.to_str().expect("p"), &noop_progress).expect("hash");

    let oneshot = crate::api::hashing::blake3_hash(data);
    assert_eq!(digest, oneshot);
}

#[test]
fn test_streaming_hash_exact_boundary() {
    let data = vec![0xCD; CHUNK_SIZE];
    let dir = tempfile::tempdir().expect("tmpdir");
    let path = dir.path().join("boundary.bin");
    fs::write(&path, &data).expect("write");

    let hasher = make_blake3_hasher();
    let progress = std::sync::Mutex::new(Vec::new());
    let digest = hash::hash_file_impl(&hasher, path.to_str().expect("p"), &|p| {
        progress.lock().expect("lock").push(p)
    })
    .expect("hash");

    let oneshot = crate::api::hashing::blake3_hash(data);
    assert_eq!(digest, oneshot);

    let vals = progress.lock().expect("lock");
    assert!(!vals.is_empty());
    assert!((vals.last().copied().unwrap_or(0.0) - 1.0).abs() < f64::EPSILON);
}

// -- Streaming compression tests ----------------------------------------------

#[cfg(feature = "compression")]
use crate::api::compression::CompressionConfig;

#[cfg(feature = "compression")]
fn zstd_config() -> CompressionConfig {
    CompressionConfig {
        algorithm: CompressionAlgorithm::Zstd,
        level: None,
    }
}

#[cfg(feature = "compression")]
fn brotli_config() -> CompressionConfig {
    CompressionConfig {
        algorithm: CompressionAlgorithm::Brotli,
        level: None,
    }
}

#[cfg(feature = "compression")]
fn none_config() -> CompressionConfig {
    CompressionConfig {
        algorithm: CompressionAlgorithm::None,
        level: None,
    }
}

/// Helper: compress-encrypt → decrypt-decompress → compare.
#[cfg(feature = "compression")]
fn compress_roundtrip_test(cipher: &CipherHandle, config: &CompressionConfig, original: &[u8]) {
    let dir = tempfile::tempdir().expect("tmpdir");
    let input = dir.path().join("input.bin");
    let encrypted = dir.path().join("encrypted.bin");
    let decrypted = dir.path().join("decrypted.bin");

    fs::write(&input, original).expect("write input");

    compress_encrypt_file_impl(
        cipher,
        config,
        input.to_str().expect("path"),
        encrypted.to_str().expect("path"),
        &noop_progress,
    )
    .expect("compress+encrypt");

    decrypt_decompress_file_impl(
        cipher,
        encrypted.to_str().expect("path"),
        decrypted.to_str().expect("path"),
        &noop_progress,
    )
    .expect("decrypt+decompress");

    let result = fs::read(&decrypted).expect("read output");
    assert_eq!(result, original, "Roundtrip mismatch");
}

#[cfg(feature = "compression")]
#[test]
fn test_compress_encrypt_decrypt_decompress_roundtrip_zstd() {
    let cipher = make_aes_cipher();
    compress_roundtrip_test(&cipher, &zstd_config(), b"Hello, Zstd streaming roundtrip!");
    compress_roundtrip_test(&cipher, &zstd_config(), &vec![0xAB; 200 * 1024]);
    compress_roundtrip_test(&cipher, &zstd_config(), &[]);
    compress_roundtrip_test(&cipher, &zstd_config(), &vec![0xFE; CHUNK_SIZE]);
    compress_roundtrip_test(&cipher, &zstd_config(), &vec![0xFE; CHUNK_SIZE * 3]);
}

#[cfg(feature = "compression")]
#[test]
fn test_compress_encrypt_decrypt_decompress_roundtrip_brotli() {
    let cipher = make_aes_cipher();
    compress_roundtrip_test(
        &cipher,
        &brotli_config(),
        b"Hello, Brotli streaming roundtrip!",
    );
    compress_roundtrip_test(&cipher, &brotli_config(), &vec![0xCD; 200 * 1024]);
    compress_roundtrip_test(&cipher, &brotli_config(), &[]);
    compress_roundtrip_test(&cipher, &brotli_config(), &vec![0xFE; CHUNK_SIZE]);
}

#[cfg(feature = "compression")]
#[test]
fn test_mime_skip_jpg() {
    let cipher = make_aes_cipher();
    let dir = tempfile::tempdir().expect("tmpdir");
    let input = dir.path().join("photo.jpg");
    let encrypted = dir.path().join("encrypted.bin");
    let decrypted = dir.path().join("decrypted.bin");

    let original = vec![0xFF; 1024];
    fs::write(&input, &original).expect("write input");

    compress_encrypt_file_impl(
        &cipher,
        &zstd_config(),
        input.to_str().expect("path"),
        encrypted.to_str().expect("path"),
        &noop_progress,
    )
    .expect("compress+encrypt");

    let enc_bytes = fs::read(&encrypted).expect("read encrypted");
    assert_eq!(
        enc_bytes[8], 0x00,
        "Header compression byte should be 0x00 (None) for .jpg"
    );

    decrypt_decompress_file_impl(
        &cipher,
        encrypted.to_str().expect("path"),
        decrypted.to_str().expect("path"),
        &noop_progress,
    )
    .expect("decrypt+decompress");

    let result = fs::read(&decrypted).expect("read output");
    assert_eq!(result, original);
}

#[cfg(feature = "compression")]
#[test]
fn test_compression_none_matches_plain_encrypt() {
    let cipher = make_aes_cipher();
    let dir = tempfile::tempdir().expect("tmpdir");
    let input = dir.path().join("input.bin");
    let enc_plain = dir.path().join("enc_plain.bin");
    let enc_comp = dir.path().join("enc_comp.bin");
    let dec_plain = dir.path().join("dec_plain.bin");
    let dec_comp = dir.path().join("dec_comp.bin");

    let original = b"Test data for None comparison";
    fs::write(&input, original).expect("write input");

    encrypt_file_impl(
        &cipher,
        input.to_str().expect("path"),
        enc_plain.to_str().expect("path"),
        &noop_progress,
    )
    .expect("plain encrypt");

    compress_encrypt_file_impl(
        &cipher,
        &none_config(),
        input.to_str().expect("path"),
        enc_comp.to_str().expect("path"),
        &noop_progress,
    )
    .expect("none compress+encrypt");

    let plain_size = fs::metadata(&enc_plain).expect("stat").len();
    let comp_size = fs::metadata(&enc_comp).expect("stat").len();
    assert_eq!(
        plain_size, comp_size,
        "None compression should produce same size as plain encrypt"
    );

    decrypt_file_impl(
        &cipher,
        enc_plain.to_str().expect("path"),
        dec_plain.to_str().expect("path"),
        &noop_progress,
    )
    .expect("plain decrypt");

    decrypt_decompress_file_impl(
        &cipher,
        enc_comp.to_str().expect("path"),
        dec_comp.to_str().expect("path"),
        &noop_progress,
    )
    .expect("none decrypt+decompress");

    assert_eq!(fs::read(&dec_plain).expect("read"), original);
    assert_eq!(fs::read(&dec_comp).expect("read"), original);
}

#[cfg(feature = "compression")]
#[test]
fn test_compressed_file_fewer_chunks() {
    let cipher = make_aes_cipher();
    let dir = tempfile::tempdir().expect("tmpdir");

    let original = vec![b'A'; CHUNK_SIZE * 4];
    let input = dir.path().join("input.bin");
    let enc_plain = dir.path().join("enc_plain.bin");
    let enc_comp = dir.path().join("enc_comp.bin");
    let decrypted = dir.path().join("decrypted.bin");

    fs::write(&input, &original).expect("write");

    encrypt_file_impl(
        &cipher,
        input.to_str().expect("p"),
        enc_plain.to_str().expect("p"),
        &noop_progress,
    )
    .expect("plain encrypt");

    let plain_size = fs::metadata(&enc_plain).expect("stat").len() as usize;
    let plain_chunks = (plain_size - STREAM_HEADER_SIZE) / ENCRYPTED_CHUNK_SIZE;

    compress_encrypt_file_impl(
        &cipher,
        &zstd_config(),
        input.to_str().expect("p"),
        enc_comp.to_str().expect("p"),
        &noop_progress,
    )
    .expect("compress+encrypt");

    let comp_size = fs::metadata(&enc_comp).expect("stat").len() as usize;
    let comp_chunks = (comp_size - STREAM_HEADER_SIZE) / ENCRYPTED_CHUNK_SIZE;

    assert!(
        comp_chunks < plain_chunks,
        "Compressed should use fewer chunks: {comp_chunks} vs {plain_chunks}"
    );

    decrypt_decompress_file_impl(
        &cipher,
        enc_comp.to_str().expect("p"),
        decrypted.to_str().expect("p"),
        &noop_progress,
    )
    .expect("decrypt+decompress");

    assert_eq!(fs::read(&decrypted).expect("read"), original);
}
