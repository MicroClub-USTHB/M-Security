//! Stream-compress-then-chunk encryption and decrypt-then-decompress.

use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};

use crate::api::compression::{should_skip_compression, CompressionAlgorithm, CompressionConfig};
use crate::api::encryption::CipherHandle;
use crate::core::compression::streaming::{new_compressor, new_decompressor};
use crate::core::error::CryptoError;
use crate::core::streaming::{
    finish_file, pad_last_chunk, strip_last_chunk_padding, ChunkAad, ChunkReader, ChunkWriter,
    EncryptedChunk, StreamHeader, CHUNK_SIZE, ENCRYPTED_CHUNK_SIZE, STREAM_HEADER_SIZE,
};

use super::{
    algorithm_from_id, open_input, parse_encrypted_output, read_full, reassemble_into,
    TempFileGuard,
};

/// Stream-compress, then chunk the compressed stream.
///
/// Read input → feed to a streaming compressor → buffer compressed bytes →
/// when buffer >= CHUNK_SIZE, encrypt as intermediate chunk → at EOF,
/// finish compressor, pad only the remainder as the final chunk.
///
/// Compressed data fills 64KB buckets naturally. A file that compresses 50%
/// produces half as many encrypted chunks.
pub(crate) fn compress_encrypt_file_impl(
    cipher: &CipherHandle,
    compression: &CompressionConfig,
    input_path: &str,
    output_path: &str,
    on_progress: &dyn Fn(f64),
) -> Result<(), CryptoError> {
    let algo = algorithm_from_id(cipher.algorithm_id())?;

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

    let level = compression.level;

    let (mut reader, file_size) = open_input(input_path)?;

    let tmp_path = format!("{output_path}.tmp");
    let mut guard = TempFileGuard::new(tmp_path.clone());

    let output_file = File::create(&tmp_path)
        .map_err(|e| CryptoError::IoError(format!("Cannot create output '{tmp_path}': {e}")))?;

    let mut writer = ChunkWriter::new(BufWriter::new(output_file));
    writer.write_header(&StreamHeader::new(algo, effective_algo))?;

    let mut enc_chunk = EncryptedChunk::new();
    let mut read_buf = vec![0u8; CHUNK_SIZE];
    let mut comp_buf = Vec::with_capacity(CHUNK_SIZE * 2);
    let mut chunk_index: u64 = 0;
    let mut bytes_fed: u64 = 0;

    let mut compressor = new_compressor(effective_algo, level)?;

    let flush_full_chunks = |comp_buf: &mut Vec<u8>,
                             chunk_index: &mut u64,
                             enc_chunk: &mut EncryptedChunk,
                             writer: &mut ChunkWriter<BufWriter<File>>|
     -> Result<(), CryptoError> {
        while comp_buf.len() >= CHUNK_SIZE {
            let aad = ChunkAad {
                index: *chunk_index,
                is_final: false,
            }
            .to_bytes();
            let encrypted = cipher.encrypt_raw(&comp_buf[..CHUNK_SIZE], &aad)?;
            parse_encrypted_output(&encrypted, enc_chunk)?;
            writer.write_chunk(enc_chunk)?;

            comp_buf.drain(..CHUNK_SIZE);
            *chunk_index += 1;
        }
        Ok(())
    };

    loop {
        let bytes_read = read_full(&mut reader, &mut read_buf)?;
        if bytes_read == 0 {
            break;
        }

        compressor.compress_chunk(&read_buf[..bytes_read], &mut comp_buf)?;
        bytes_fed += bytes_read as u64;

        flush_full_chunks(&mut comp_buf, &mut chunk_index, &mut enc_chunk, &mut writer)?;

        if file_size > 0 {
            on_progress((bytes_fed as f64 / file_size as f64).min(0.99));
        }
    }

    compressor.finish(&mut comp_buf)?;
    flush_full_chunks(&mut comp_buf, &mut chunk_index, &mut enc_chunk, &mut writer)?;

    let plaintext = pad_last_chunk(&comp_buf)?;
    let aad = ChunkAad {
        index: chunk_index,
        is_final: true,
    }
    .to_bytes();
    let encrypted = cipher.encrypt_raw(&plaintext, &aad)?;
    parse_encrypted_output(&encrypted, &mut enc_chunk)?;
    writer.write_chunk(&enc_chunk)?;
    on_progress(1.0);

    finish_file(writer)?;

    fs::rename(&tmp_path, output_path).map_err(|e| {
        CryptoError::IoError(format!("Cannot rename '{tmp_path}' → '{output_path}': {e}"))
    })?;
    guard.defuse();

    Ok(())
}

/// Decrypt then stream-decompress a file.
///
/// Reads compression algorithm from the file header, then decrypts each
/// chunk and feeds the compressed bytes through a streaming decompressor.
/// Intermediate chunks are raw compressed segments; only the final chunk
/// has length-prefix padding.
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

    let comp_algo = header.compression;

    let data_size = file_size.saturating_sub(STREAM_HEADER_SIZE as u64);
    let estimated_chunks = if data_size > 0 {
        data_size.div_ceil(ENCRYPTED_CHUNK_SIZE as u64)
    } else {
        1
    };

    // Read-ahead by one chunk so we know which chunk is final without
    // trial decryption — each chunk is decrypted exactly once.
    let mut current = EncryptedChunk::new();
    let mut next = EncryptedChunk::new();
    let mut wire_buf = Vec::with_capacity(ENCRYPTED_CHUNK_SIZE);
    let mut decomp_buf = Vec::with_capacity(CHUNK_SIZE * 2);
    let mut decompressor = new_decompressor(comp_algo)?;
    let mut i: u64 = 0;

    if !reader.read_chunk(&mut current)? {
        return Err(CryptoError::DecryptionFailed);
    }

    loop {
        let has_next = reader.read_chunk(&mut next)?;

        reassemble_into(&current, &mut wire_buf);

        if !has_next {
            // Current is the final chunk
            let aad = ChunkAad {
                index: i,
                is_final: true,
            }
            .to_bytes();
            let plaintext = cipher
                .decrypt_raw(&wire_buf, &aad)
                .map_err(|_| CryptoError::DecryptionFailed)?;
            let data = strip_last_chunk_padding(&plaintext)?;
            if !data.is_empty() {
                decompressor.decompress_chunk(&data, &mut decomp_buf)?;
            }
            decompressor.finish(&mut decomp_buf)?;
            if !decomp_buf.is_empty() {
                out_writer
                    .write_all(&decomp_buf)
                    .map_err(|e| CryptoError::IoError(format!("Write failed: {e}")))?;
                decomp_buf.clear();
            }
            on_progress(1.0);
            break;
        }

        // Current is an intermediate chunk
        let aad = ChunkAad {
            index: i,
            is_final: false,
        }
        .to_bytes();
        let plaintext = cipher
            .decrypt_raw(&wire_buf, &aad)
            .map_err(|_| CryptoError::DecryptionFailed)?;
        decompressor.decompress_chunk(&plaintext, &mut decomp_buf)?;
        if !decomp_buf.is_empty() {
            out_writer
                .write_all(&decomp_buf)
                .map_err(|e| CryptoError::IoError(format!("Write failed: {e}")))?;
            decomp_buf.clear();
        }

        std::mem::swap(&mut current, &mut next);
        i += 1;
        on_progress((i as f64 / estimated_chunks.max(1) as f64).min(0.99));
    }

    let file = out_writer
        .into_inner()
        .map_err(|e| CryptoError::IoError(format!("Flush failed: {e}")))?;
    file.sync_all()
        .map_err(|e| CryptoError::IoError(format!("Failed to fsync: {e}")))?;
    drop(file);
    fs::rename(&tmp_path, output_path).map_err(|e| {
        CryptoError::IoError(format!("Cannot rename '{tmp_path}' → '{output_path}': {e}"))
    })?;
    guard.defuse();

    Ok(())
}
