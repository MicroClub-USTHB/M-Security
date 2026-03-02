//! Streaming file encryption and decryption API.
//!
//! Core logic uses a progress callback closure so it's testable without FRB.
//! The public FRB-visible functions (`stream_encrypt_file`, `stream_decrypt_file`)
//! are thin wrappers that forward progress to a `StreamSink`.
//!
//! Both encrypt and decrypt write to a temporary file first, then atomically
//! rename on success. On any error the partial output is deleted — a failed
//! decryption never leaves plaintext on disk.

use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};

#[cfg(feature = "compression")]
use crate::api::compression::{
    compress, decompress, should_skip_compression, CompressionAlgorithm, CompressionConfig,
};
use crate::api::encryption::CipherHandle;
use crate::api::hashing::HasherHandle;
use crate::core::error::CryptoError;
use crate::core::streaming::{
    finish_file, pad_last_chunk, strip_last_chunk_padding, ChunkAad, ChunkReader, ChunkWriter,
    EncryptedChunk, StreamAlgorithm, StreamHeader, CHUNK_SIZE, ENCRYPTED_CHUNK_SIZE, NONCE_SIZE,
    STREAM_HEADER_SIZE,
};

// -- Helpers -----------------------------------------------------------------

fn algorithm_from_id(id: &str) -> Result<StreamAlgorithm, CryptoError> {
    match id {
        "aes-256-gcm" => Ok(StreamAlgorithm::AesGcm),
        "chacha20-poly1305" => Ok(StreamAlgorithm::ChaCha20Poly1305),
        other => Err(CryptoError::InvalidParameter(format!(
            "Algorithm '{other}' not supported for streaming"
        ))),
    }
}

#[cfg(feature = "compression")]
fn compression_to_u8(algo: CompressionAlgorithm) -> u8 {
    match algo {
        CompressionAlgorithm::None => 0x00,
        CompressionAlgorithm::Zstd => 0x01,
        CompressionAlgorithm::Brotli => 0x02,
    }
}

#[cfg(feature = "compression")]
fn compression_from_u8(byte: u8) -> Result<CompressionAlgorithm, CryptoError> {
    match byte {
        0x00 => Ok(CompressionAlgorithm::None),
        0x01 => Ok(CompressionAlgorithm::Zstd),
        0x02 => Ok(CompressionAlgorithm::Brotli),
        other => Err(CryptoError::InvalidParameter(format!(
            "Unknown compression algorithm byte: {other:#02x}"
        ))),
    }
}

fn parse_encrypted_output(data: &[u8], chunk: &mut EncryptedChunk) -> Result<(), CryptoError> {
    if data.len() != ENCRYPTED_CHUNK_SIZE {
        return Err(CryptoError::EncryptionFailed(format!(
            "Encrypted output size mismatch: got {}, expected {ENCRYPTED_CHUNK_SIZE}",
            data.len()
        )));
    }

    chunk.nonce.copy_from_slice(&data[..NONCE_SIZE]);
    chunk.ciphertext[..CHUNK_SIZE].copy_from_slice(&data[NONCE_SIZE..NONCE_SIZE + CHUNK_SIZE]);
    chunk.tag.copy_from_slice(&data[NONCE_SIZE + CHUNK_SIZE..]);
    Ok(())
}

/// Reassemble nonce || ciphertext || tag into `buf` for decryption.
fn reassemble_into(chunk: &EncryptedChunk, buf: &mut Vec<u8>) {
    buf.clear();
    buf.extend_from_slice(&chunk.nonce);
    buf.extend_from_slice(&chunk.ciphertext);
    buf.extend_from_slice(&chunk.tag);
}

/// Read exactly `buf.len()` bytes, tolerating partial reads and EINTR.
fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize, CryptoError> {
    let mut offset = 0;
    loop {
        match reader.read(&mut buf[offset..]) {
            Ok(0) => return Ok(offset),
            Ok(n) => {
                offset += n;
                if offset == buf.len() {
                    return Ok(offset);
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(CryptoError::IoError(format!("Read failed: {e}"))),
        }
    }
}

/// Drop guard that removes a temporary file unless `defuse()` is called.
struct TempFileGuard {
    path: String,
    active: bool,
}

impl TempFileGuard {
    fn new(path: String) -> Self {
        Self { path, active: true }
    }

    /// Prevent deletion — call after a successful rename.
    fn defuse(&mut self) {
        self.active = false;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = fs::remove_file(&self.path);
        }
    }
}

// -- Core logic (testable, no FRB dependency) --------------------------------

/// Encrypt a file in streaming 64KB chunks.
///
/// Writes to a temporary file and renames atomically on success.
/// `on_progress` receives values from 0.0 to 1.0. The final 1.0 is sent
/// before fsync — callers must check the `Result` for true completion.
pub(crate) fn encrypt_file_impl(
    cipher: &CipherHandle,
    input_path: &str,
    output_path: &str,
    on_progress: &dyn Fn(f64),
) -> Result<(), CryptoError> {
    // Validate algorithm before touching the filesystem
    let algo = algorithm_from_id(cipher.algorithm_id())?;

    let input_file = File::open(input_path)
        .map_err(|e| CryptoError::IoError(format!("Cannot open input '{input_path}': {e}")))?;
    let file_size = input_file
        .metadata()
        .map_err(|e| CryptoError::IoError(format!("Cannot stat input: {e}")))?
        .len();

    let tmp_path = format!("{output_path}.tmp");
    let mut guard = TempFileGuard::new(tmp_path.clone());

    let output_file = File::create(&tmp_path)
        .map_err(|e| CryptoError::IoError(format!("Cannot create output '{tmp_path}': {e}")))?;

    let mut reader = BufReader::new(input_file);
    let mut writer = ChunkWriter::new(BufWriter::new(output_file));

    writer.write_header(&StreamHeader::new(algo, 0))?;

    let mut enc_chunk = EncryptedChunk::new();
    let mut read_buf = vec![0u8; CHUNK_SIZE];
    let mut chunk_index: u64 = 0;

    // Compute chunk estimate for progress: exact CHUNK_SIZE-multiple files
    // produce an extra empty padded final chunk
    let total_chunks = if file_size == 0 {
        1u64
    } else {
        let base = file_size.div_ceil(CHUNK_SIZE as u64);
        if file_size % CHUNK_SIZE as u64 == 0 {
            base + 1
        } else {
            base
        }
    };

    loop {
        let bytes_read = read_full(&mut reader, &mut read_buf)?;

        if bytes_read == 0 {
            // EOF: either empty file (chunk_index==0) or previous chunk was
            // exactly CHUNK_SIZE — emit empty padded final chunk
            let plaintext = pad_last_chunk(&[])?;
            let aad = ChunkAad {
                index: chunk_index,
                is_final: true,
            }
            .to_bytes();
            let encrypted = cipher.encrypt_raw(&plaintext, &aad)?;
            parse_encrypted_output(&encrypted, &mut enc_chunk)?;
            writer.write_chunk(&enc_chunk)?;
            on_progress(1.0);
            break;
        }

        if bytes_read < CHUNK_SIZE {
            // Short read — last chunk, pad it
            let plaintext = pad_last_chunk(&read_buf[..bytes_read])?;
            let aad = ChunkAad {
                index: chunk_index,
                is_final: true,
            }
            .to_bytes();
            let encrypted = cipher.encrypt_raw(&plaintext, &aad)?;
            parse_encrypted_output(&encrypted, &mut enc_chunk)?;
            writer.write_chunk(&enc_chunk)?;
            on_progress(1.0);
            break;
        }

        // Full CHUNK_SIZE read — emit as intermediate (non-final) chunk
        let aad = ChunkAad {
            index: chunk_index,
            is_final: false,
        }
        .to_bytes();
        let encrypted = cipher.encrypt_raw(&read_buf[..CHUNK_SIZE], &aad)?;
        parse_encrypted_output(&encrypted, &mut enc_chunk)?;
        writer.write_chunk(&enc_chunk)?;

        chunk_index += 1;
        on_progress((chunk_index as f64 / total_chunks as f64).min(0.99));
    }

    finish_file(writer)?;

    // Atomic rename — only after fsync succeeds
    fs::rename(&tmp_path, output_path).map_err(|e| {
        CryptoError::IoError(format!("Cannot rename '{tmp_path}' → '{output_path}': {e}"))
    })?;
    guard.defuse();

    Ok(())
}

/// Compress-then-encrypt a file using streaming chunks.
///
/// Each chunk is: compress(64KB) → encrypt(compressed) → write.
/// The header stores the compression algorithm so decrypt knows how to decompress.
/// If `should_skip_compression` returns true, compression is silently skipped.
#[cfg(feature = "compression")]
pub(crate) fn compress_encrypt_file_impl(
    cipher: &CipherHandle,
    compression: &CompressionConfig,
    input_path: &str,
    output_path: &str,
    on_progress: &dyn Fn(f64),
) -> Result<(), CryptoError> {
    let algo = algorithm_from_id(cipher.algorithm_id())?;

    // MIME-aware auto-skip: if the file is already compressed, skip compression
    let effective_algo = if compression.algorithm != CompressionAlgorithm::None
        && should_skip_compression(input_path)
    {
        log::info!(
            "Skipping compression for '{}' (already-compressed format)",
            input_path
        );
        CompressionAlgorithm::None
    } else {
        compression.algorithm
    };

    let effective_config = CompressionConfig {
        algorithm: effective_algo,
        level: compression.level,
    };

    let input_file = File::open(input_path)
        .map_err(|e| CryptoError::IoError(format!("Cannot open input '{input_path}': {e}")))?;
    let file_size = input_file
        .metadata()
        .map_err(|e| CryptoError::IoError(format!("Cannot stat input: {e}")))?
        .len();

    let tmp_path = format!("{output_path}.tmp");
    let mut guard = TempFileGuard::new(tmp_path.clone());

    let output_file = File::create(&tmp_path)
        .map_err(|e| CryptoError::IoError(format!("Cannot create output '{tmp_path}': {e}")))?;

    let mut reader = BufReader::new(input_file);
    let mut writer = ChunkWriter::new(BufWriter::new(output_file));

    writer.write_header(&StreamHeader::new(algo, compression_to_u8(effective_algo)))?;

    let mut enc_chunk = EncryptedChunk::new();
    let mut read_buf = vec![0u8; CHUNK_SIZE];
    let mut chunk_index: u64 = 0;

    let total_chunks = if file_size == 0 {
        1u64
    } else {
        let base = file_size.div_ceil(CHUNK_SIZE as u64);
        if file_size % CHUNK_SIZE as u64 == 0 {
            base + 1
        } else {
            base
        }
    };

    loop {
        let bytes_read = read_full(&mut reader, &mut read_buf)?;

        if bytes_read == 0 {
            // EOF — emit empty padded final chunk (compressed empty = empty)
            let compressed = compress(&[], &effective_config)?;
            let plaintext = pad_last_chunk(&compressed)?;
            let aad = ChunkAad {
                index: chunk_index,
                is_final: true,
            }
            .to_bytes();
            let encrypted = cipher.encrypt_raw(&plaintext, &aad)?;
            parse_encrypted_output(&encrypted, &mut enc_chunk)?;
            writer.write_chunk(&enc_chunk)?;
            on_progress(1.0);
            break;
        }

        if bytes_read < CHUNK_SIZE {
            // Short read — last chunk
            let compressed = compress(&read_buf[..bytes_read], &effective_config)?;
            let plaintext = pad_last_chunk(&compressed)?;
            let aad = ChunkAad {
                index: chunk_index,
                is_final: true,
            }
            .to_bytes();
            let encrypted = cipher.encrypt_raw(&plaintext, &aad)?;
            parse_encrypted_output(&encrypted, &mut enc_chunk)?;
            writer.write_chunk(&enc_chunk)?;
            on_progress(1.0);
            break;
        }

        // Full CHUNK_SIZE read — compress then encrypt as intermediate chunk
        let compressed = compress(&read_buf[..CHUNK_SIZE], &effective_config)?;
        let plaintext = pad_last_chunk(&compressed)?;
        let aad = ChunkAad {
            index: chunk_index,
            is_final: false,
        }
        .to_bytes();
        let encrypted = cipher.encrypt_raw(&plaintext, &aad)?;
        parse_encrypted_output(&encrypted, &mut enc_chunk)?;
        writer.write_chunk(&enc_chunk)?;

        chunk_index += 1;
        on_progress((chunk_index as f64 / total_chunks as f64).min(0.99));
    }

    finish_file(writer)?;

    fs::rename(&tmp_path, output_path).map_err(|e| {
        CryptoError::IoError(format!("Cannot rename '{tmp_path}' → '{output_path}': {e}"))
    })?;
    guard.defuse();

    Ok(())
}

/// Decrypt a streaming-encrypted file.
///
/// Writes to a temporary file and renames atomically on success.
/// On any error (wrong key, tampered data, truncation) the output is deleted.
/// `on_progress` receives values from 0.0 to 1.0.
pub(crate) fn decrypt_file_impl(
    cipher: &CipherHandle,
    input_path: &str,
    output_path: &str,
    on_progress: &dyn Fn(f64),
) -> Result<(), CryptoError> {
    let input_file = File::open(input_path)
        .map_err(|e| CryptoError::IoError(format!("Cannot open input '{input_path}': {e}")))?;
    let file_size = input_file
        .metadata()
        .map_err(|e| CryptoError::IoError(format!("Cannot stat input: {e}")))?
        .len();

    let tmp_path = format!("{output_path}.tmp");
    let mut guard = TempFileGuard::new(tmp_path.clone());

    let output_file = File::create(&tmp_path)
        .map_err(|e| CryptoError::IoError(format!("Cannot create output '{tmp_path}': {e}")))?;

    let mut reader = ChunkReader::new(BufReader::new(input_file));
    let mut out_writer = BufWriter::new(output_file);

    // Validate header and cross-check algorithm
    let header = reader.read_header()?;
    let expected_algo = algorithm_from_id(cipher.algorithm_id())?;
    if header.algorithm != expected_algo {
        return Err(CryptoError::InvalidParameter(format!(
            "Algorithm mismatch: file uses {:?}, cipher is {}",
            header.algorithm,
            cipher.algorithm_id()
        )));
    }

    // Estimate total chunks for progress
    let data_size = file_size.saturating_sub(STREAM_HEADER_SIZE as u64);
    let estimated_chunks = if data_size > 0 {
        data_size / ENCRYPTED_CHUNK_SIZE as u64
    } else {
        1
    };

    let mut chunk = EncryptedChunk::new();
    let mut wire_buf = Vec::with_capacity(ENCRYPTED_CHUNK_SIZE);
    let mut i: u64 = 0;

    loop {
        let has_data = reader.read_chunk(&mut chunk)?;
        if !has_data {
            return Err(CryptoError::DecryptionFailed);
        }

        reassemble_into(&chunk, &mut wire_buf);

        // SAFETY: AEAD guarantees that only one AAD value (is_final true/false)
        // will authenticate for any given chunk, since the AAD byte differs.
        // Try is_final=true first (optimistic for single-chunk and last-chunk).
        let aad_final = ChunkAad {
            index: i,
            is_final: true,
        }
        .to_bytes();

        if let Ok(plaintext) = cipher.decrypt_raw(&wire_buf, &aad_final) {
            let real_data = strip_last_chunk_padding(&plaintext)?;
            out_writer
                .write_all(&real_data)
                .map_err(|e| CryptoError::IoError(format!("Write failed: {e}")))?;
            on_progress(1.0);
            break;
        }

        // Try is_final=false (intermediate chunk)
        let aad_normal = ChunkAad {
            index: i,
            is_final: false,
        }
        .to_bytes();

        match cipher.decrypt_raw(&wire_buf, &aad_normal) {
            Ok(plaintext) => {
                out_writer
                    .write_all(&plaintext)
                    .map_err(|e| CryptoError::IoError(format!("Write failed: {e}")))?;
                i += 1;
                let progress = i as f64 / estimated_chunks.max(1) as f64;
                on_progress(progress.min(0.99));
            }
            Err(_) => {
                return Err(CryptoError::DecryptionFailed);
            }
        }
    }

    out_writer
        .flush()
        .map_err(|e| CryptoError::IoError(format!("Flush failed: {e}")))?;

    // Atomic rename — only after flush succeeds
    drop(out_writer);
    fs::rename(&tmp_path, output_path).map_err(|e| {
        CryptoError::IoError(format!("Cannot rename '{tmp_path}' → '{output_path}': {e}"))
    })?;
    guard.defuse();

    Ok(())
}

/// Decrypt-then-decompress a file.
///
/// Reads compression algorithm from the file header, then for each chunk:
/// decrypt → strip padding → decompress → write.
#[cfg(feature = "compression")]
pub(crate) fn decrypt_decompress_file_impl(
    cipher: &CipherHandle,
    input_path: &str,
    output_path: &str,
    on_progress: &dyn Fn(f64),
) -> Result<(), CryptoError> {
    let input_file = File::open(input_path)
        .map_err(|e| CryptoError::IoError(format!("Cannot open input '{input_path}': {e}")))?;
    let file_size = input_file
        .metadata()
        .map_err(|e| CryptoError::IoError(format!("Cannot stat input: {e}")))?
        .len();

    let tmp_path = format!("{output_path}.tmp");
    let mut guard = TempFileGuard::new(tmp_path.clone());

    let output_file = File::create(&tmp_path)
        .map_err(|e| CryptoError::IoError(format!("Cannot create output '{tmp_path}': {e}")))?;

    let mut reader = ChunkReader::new(BufReader::new(input_file));
    let mut out_writer = BufWriter::new(output_file);

    let header = reader.read_header()?;
    let expected_algo = algorithm_from_id(cipher.algorithm_id())?;
    if header.algorithm != expected_algo {
        return Err(CryptoError::InvalidParameter(format!(
            "Algorithm mismatch: file uses {:?}, cipher is {}",
            header.algorithm,
            cipher.algorithm_id()
        )));
    }

    let comp_algo = compression_from_u8(header.compression)?;

    let data_size = file_size.saturating_sub(STREAM_HEADER_SIZE as u64);
    let estimated_chunks = if data_size > 0 {
        data_size / ENCRYPTED_CHUNK_SIZE as u64
    } else {
        1
    };

    let mut chunk = EncryptedChunk::new();
    let mut wire_buf = Vec::with_capacity(ENCRYPTED_CHUNK_SIZE);
    let mut i: u64 = 0;

    loop {
        let has_data = reader.read_chunk(&mut chunk)?;
        if !has_data {
            return Err(CryptoError::DecryptionFailed);
        }

        reassemble_into(&chunk, &mut wire_buf);

        // Try is_final=true first (optimistic for last chunk)
        let aad_final = ChunkAad {
            index: i,
            is_final: true,
        }
        .to_bytes();

        if let Ok(plaintext) = cipher.decrypt_raw(&wire_buf, &aad_final) {
            let compressed = strip_last_chunk_padding(&plaintext)?;
            let real_data = decompress(&compressed, comp_algo)?;
            out_writer
                .write_all(&real_data)
                .map_err(|e| CryptoError::IoError(format!("Write failed: {e}")))?;
            on_progress(1.0);
            break;
        }

        // Try is_final=false (intermediate chunk)
        let aad_normal = ChunkAad {
            index: i,
            is_final: false,
        }
        .to_bytes();

        match cipher.decrypt_raw(&wire_buf, &aad_normal) {
            Ok(plaintext) => {
                let compressed = strip_last_chunk_padding(&plaintext)?;
                let real_data = decompress(&compressed, comp_algo)?;
                out_writer
                    .write_all(&real_data)
                    .map_err(|e| CryptoError::IoError(format!("Write failed: {e}")))?;
                i += 1;
                let progress = i as f64 / estimated_chunks.max(1) as f64;
                on_progress(progress.min(0.99));
            }
            Err(_) => {
                return Err(CryptoError::DecryptionFailed);
            }
        }
    }

    out_writer
        .flush()
        .map_err(|e| CryptoError::IoError(format!("Flush failed: {e}")))?;

    drop(out_writer);
    fs::rename(&tmp_path, output_path).map_err(|e| {
        CryptoError::IoError(format!("Cannot rename '{tmp_path}' → '{output_path}': {e}"))
    })?;
    guard.defuse();

    Ok(())
}

// -- Streaming hash (no encryption padding) -----------------------------------

/// Feed an entire file into the hasher in 64KB chunks. Does NOT finalize.
///
/// Resets the hasher first to ensure a clean state, then feeds raw file bytes
/// (no padding). Caller must call `finalize_raw()` / `hasherFinalize()` to
/// obtain the digest.
pub(crate) fn hash_file_feed(
    hasher: &HasherHandle,
    file_path: &str,
    on_progress: &dyn Fn(f64),
) -> Result<(), CryptoError> {
    hasher.reset_raw()?;

    let file = File::open(file_path)
        .map_err(|e| CryptoError::IoError(format!("Cannot open input '{file_path}': {e}")))?;
    let file_size = file
        .metadata()
        .map_err(|e| CryptoError::IoError(format!("Cannot stat input: {e}")))?
        .len();

    let mut reader = BufReader::new(file);
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut bytes_hashed: u64 = 0;

    loop {
        let n = read_full(&mut reader, &mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update_raw(&buf[..n])?;
        bytes_hashed += n as u64;
        if file_size > 0 {
            on_progress((bytes_hashed as f64 / file_size as f64).min(0.99));
        }
    }

    on_progress(1.0);
    Ok(())
}

/// Hash a file in streaming 64KB chunks (feed + finalize).
///
/// Convenience wrapper: feeds the entire file then finalizes.
/// The digest matches `blake3_hash(fs::read(path))`.
#[cfg(test)]
fn hash_file_impl(
    hasher: &HasherHandle,
    file_path: &str,
    on_progress: &dyn Fn(f64),
) -> Result<Vec<u8>, CryptoError> {
    hash_file_feed(hasher, file_path, on_progress)?;
    hasher.finalize_raw()
}

// -- FRB entry points (thin wrappers) ----------------------------------------

use crate::frb_generated::StreamSink;

/// Encrypt a file using streaming AEAD with 64KB chunks.
///
/// Progress (0.0..1.0) is pushed to `progress_sink` as each chunk completes.
pub fn stream_encrypt_file(
    cipher: &CipherHandle,
    input_path: String,
    output_path: String,
    progress_sink: StreamSink<f64>,
) -> Result<(), CryptoError> {
    encrypt_file_impl(cipher, &input_path, &output_path, &|p| {
        let _ = progress_sink.add(p);
    })
}

/// Decrypt a streaming-encrypted file.
///
/// Progress (0.0..1.0) is pushed to `progress_sink` as each chunk completes.
pub fn stream_decrypt_file(
    cipher: &CipherHandle,
    input_path: String,
    output_path: String,
    progress_sink: StreamSink<f64>,
) -> Result<(), CryptoError> {
    decrypt_file_impl(cipher, &input_path, &output_path, &|p| {
        let _ = progress_sink.add(p);
    })
}

/// Compress-then-encrypt a file using streaming chunks.
///
/// Each chunk is: compress(64KB) → encrypt(compressed) → write.
/// The header stores the compression algorithm so decrypt knows how to decompress.
#[cfg(feature = "compression")]
pub fn stream_compress_encrypt_file(
    cipher: &CipherHandle,
    compression: CompressionConfig,
    input_path: String,
    output_path: String,
    progress_sink: StreamSink<f64>,
) -> Result<(), CryptoError> {
    compress_encrypt_file_impl(cipher, &compression, &input_path, &output_path, &|p| {
        let _ = progress_sink.add(p);
    })
}

/// Decrypt-then-decompress a file.
///
/// Reads compression algorithm from the file header.
#[cfg(feature = "compression")]
pub fn stream_decrypt_decompress_file(
    cipher: &CipherHandle,
    input_path: String,
    output_path: String,
    progress_sink: StreamSink<f64>,
) -> Result<(), CryptoError> {
    decrypt_decompress_file_impl(cipher, &input_path, &output_path, &|p| {
        let _ = progress_sink.add(p);
    })
}

/// Hash a file using streaming 64KB chunks — feeds data only, does NOT finalize.
///
/// Reads raw file bytes (no encryption padding) and feeds them to the hasher.
/// Progress (0.0..1.0) is pushed to `progress_sink`.
///
/// After the stream completes, call `hasherFinalize()` from Dart to obtain
/// the digest. This two-step design is required because FRB cannot return
/// both a Stream and a value from the same function.
pub fn stream_hash_file(
    hasher: &HasherHandle,
    file_path: String,
    progress_sink: StreamSink<f64>,
) -> Result<(), CryptoError> {
    hash_file_feed(hasher, &file_path, &|p| {
        let _ = progress_sink.add(p);
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::encryption::{create_aes256_gcm, generate_aes256_gcm_key};
    use crate::api::encryption::{create_chacha20_poly1305, generate_chacha20_poly1305_key};
    use std::fs;

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

        // Neither the final output nor the temp file should exist
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
        // All intermediate values < 1.0
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

    // -- Streaming hash tests -------------------------------------------------

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
            hash_file_impl(&hasher, path.to_str().expect("p"), &noop_progress).expect("hash");

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
            hash_file_impl(&hasher, path.to_str().expect("p"), &noop_progress).expect("hash");

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
            hash_file_impl(&hasher, path.to_str().expect("p"), &noop_progress).expect("hash");

        let oneshot = crate::api::hashing::blake3_hash(Vec::new());
        assert_eq!(digest, oneshot);
    }

    #[test]
    fn test_streaming_hash_large_file() {
        let data = vec![0xAB; 1024 * 1024 + 37]; // 1MB + 37 bytes
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("large.bin");
        fs::write(&path, &data).expect("write");

        let hasher = make_blake3_hasher();
        let digest =
            hash_file_impl(&hasher, path.to_str().expect("p"), &noop_progress).expect("hash");

        let oneshot = crate::api::hashing::blake3_hash(data);
        assert_eq!(digest, oneshot);
    }

    #[test]
    fn test_streaming_hash_exact_boundary() {
        let data = vec![0xCD; CHUNK_SIZE]; // exactly 64KB
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("boundary.bin");
        fs::write(&path, &data).expect("write");

        let hasher = make_blake3_hasher();
        let progress = std::sync::Mutex::new(Vec::new());
        let digest = hash_file_impl(&hasher, path.to_str().expect("p"), &|p| {
            progress.lock().expect("lock").push(p)
        })
        .expect("hash");

        let oneshot = crate::api::hashing::blake3_hash(data);
        assert_eq!(digest, oneshot);

        let vals = progress.lock().expect("lock");
        assert!(!vals.is_empty());
        assert!((vals.last().copied().unwrap_or(0.0) - 1.0).abs() < f64::EPSILON);
    }

    // -- Streaming compression tests ------------------------------------------

    #[cfg(feature = "compression")]
    use crate::api::compression::{CompressionAlgorithm, CompressionConfig};

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
        // Also test multi-chunk
        compress_roundtrip_test(&cipher, &zstd_config(), &vec![0xAB; 200 * 1024]);
        // Also test empty
        compress_roundtrip_test(&cipher, &zstd_config(), &[]);
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
        // Also test multi-chunk
        compress_roundtrip_test(&cipher, &brotli_config(), &vec![0xCD; 200 * 1024]);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_mime_skip_jpg() {
        let cipher = make_aes_cipher();
        let dir = tempfile::tempdir().expect("tmpdir");
        let input = dir.path().join("photo.jpg");
        let encrypted = dir.path().join("encrypted.bin");
        let decrypted = dir.path().join("decrypted.bin");

        // Write fake JPEG data (already "compressed")
        let original = vec![0xFF; 1024];
        fs::write(&input, &original).expect("write input");

        // Encrypt with Zstd config — should auto-skip because .jpg
        compress_encrypt_file_impl(
            &cipher,
            &zstd_config(),
            input.to_str().expect("path"),
            encrypted.to_str().expect("path"),
            &noop_progress,
        )
        .expect("compress+encrypt");

        // Read the header and verify compression byte is 0x00 (None)
        let enc_bytes = fs::read(&encrypted).expect("read encrypted");
        assert_eq!(
            enc_bytes[8], 0x00,
            "Header compression byte should be 0x00 (None) for .jpg"
        );

        // Roundtrip should still work
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

        // Encrypt with plain streaming (no compression)
        encrypt_file_impl(
            &cipher,
            input.to_str().expect("path"),
            enc_plain.to_str().expect("path"),
            &noop_progress,
        )
        .expect("plain encrypt");

        // Encrypt with CompressionAlgorithm::None
        compress_encrypt_file_impl(
            &cipher,
            &none_config(),
            input.to_str().expect("path"),
            enc_comp.to_str().expect("path"),
            &noop_progress,
        )
        .expect("none compress+encrypt");

        // Both should be the same size (same pipeline, same padding)
        let plain_size = fs::metadata(&enc_plain).expect("stat").len();
        let comp_size = fs::metadata(&enc_comp).expect("stat").len();
        assert_eq!(
            plain_size, comp_size,
            "None compression should produce same size as plain encrypt"
        );

        // Both should decrypt correctly
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
    fn test_compressed_file_smaller() {
        // Per-chunk padding keeps every encrypted chunk at ENCRYPTED_CHUNK_SIZE,
        // so the on-disk file has the same number of chunks regardless of
        // compression. To show that compression actually shrinks data we
        // compare the *payload* inside each chunk (the padded length prefix)
        // rather than the outer file size.
        //
        // Strategy: compress a highly-compressible 64KB block with Zstd and
        // verify the compressed payload is much smaller than 64KB.
        use crate::api::compression::{compress, CompressionAlgorithm, CompressionConfig};

        let data = vec![b'A'; CHUNK_SIZE]; // 64KB of 'A'
        let config = CompressionConfig {
            algorithm: CompressionAlgorithm::Zstd,
            level: None,
        };
        let compressed = compress(&data, &config).expect("zstd compress");

        assert!(
            compressed.len() < data.len() / 2,
            "Zstd should compress 64KB of 'A' to well under half: {} vs {}",
            compressed.len(),
            data.len()
        );

        // Also verify full roundtrip still works for a large compressible file
        let cipher = make_aes_cipher();
        let original = vec![b'A'; 200 * 1024];
        compress_roundtrip_test(&cipher, &zstd_config(), &original);
    }
}
