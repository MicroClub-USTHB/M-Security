//! Plain streaming encryption (no compression).

use std::fs::File;
use std::io::BufWriter;

use crate::api::compression::CompressionAlgorithm;
use crate::api::encryption::CipherHandle;
use crate::core::error::CryptoError;
use crate::core::streaming::{
    finish_file, pad_last_chunk, ChunkAad, ChunkWriter, EncryptedChunk, StreamHeader, CHUNK_SIZE,
};

use super::{algorithm_from_id, open_input, parse_encrypted_output, read_full, TempFileGuard};

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
    let algo = algorithm_from_id(cipher.algorithm_id())?;

    let (mut reader, file_size) = open_input(input_path)?;

    let tmp_path = format!("{output_path}.tmp");
    let mut guard = TempFileGuard::new(tmp_path.clone());

    let output_file = File::create(&tmp_path)
        .map_err(|e| CryptoError::IoError(format!("Cannot create output '{tmp_path}': {e}")))?;

    let mut writer = ChunkWriter::new(BufWriter::new(output_file));
    writer.write_header(&StreamHeader::new(algo, CompressionAlgorithm::None))?;

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

    std::fs::rename(&tmp_path, output_path).map_err(|e| {
        CryptoError::IoError(format!("Cannot rename '{tmp_path}' → '{output_path}': {e}"))
    })?;
    guard.defuse();

    Ok(())
}
