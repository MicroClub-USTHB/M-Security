//! Plain streaming decryption (no decompression).

use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};

use crate::api::encryption::CipherHandle;
use crate::core::error::CryptoError;
use crate::core::streaming::{
    strip_last_chunk_padding, ChunkAad, ChunkReader, EncryptedChunk, ENCRYPTED_CHUNK_SIZE,
    STREAM_HEADER_SIZE,
};

use super::{algorithm_from_id, reassemble_into, TempFileGuard};

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

    let header = reader.read_header()?;
    let expected_algo = algorithm_from_id(cipher.algorithm_id())?;
    if header.algorithm != expected_algo {
        return Err(CryptoError::InvalidParameter(format!(
            "Algorithm mismatch: file uses {:?}, cipher is {}",
            header.algorithm,
            cipher.algorithm_id()
        )));
    }

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
    let mut i: u64 = 0;

    if !reader.read_chunk(&mut current)? {
        return Err(CryptoError::DecryptionFailed);
    }

    loop {
        let has_next = reader.read_chunk(&mut next)?;

        reassemble_into(&current, &mut wire_buf);

        if !has_next {
            // Current is the final chunk
            let aad = ChunkAad { index: i, is_final: true }.to_bytes();
            let plaintext = cipher
                .decrypt_raw(&wire_buf, &aad)
                .map_err(|_| CryptoError::DecryptionFailed)?;
            let real_data = strip_last_chunk_padding(&plaintext)?;
            out_writer
                .write_all(&real_data)
                .map_err(|e| CryptoError::IoError(format!("Write failed: {e}")))?;
            on_progress(1.0);
            break;
        }

        // Current is an intermediate chunk
        let aad = ChunkAad { index: i, is_final: false }.to_bytes();
        let plaintext = cipher
            .decrypt_raw(&wire_buf, &aad)
            .map_err(|_| CryptoError::DecryptionFailed)?;
        out_writer
            .write_all(&plaintext)
            .map_err(|e| CryptoError::IoError(format!("Write failed: {e}")))?;

        std::mem::swap(&mut current, &mut next);
        i += 1;
        on_progress((i as f64 / estimated_chunks.max(1) as f64).min(0.99));
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
