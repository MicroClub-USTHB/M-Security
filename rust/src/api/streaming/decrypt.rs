//! Streaming file decryption with chunked AEAD and HKDF-derived nonces.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use aes_gcm::aead::Payload;

use crate::core::error::CryptoError;

use super::crypto::{build_chunk_aad, CipherInstance, StreamKeyContext};
use super::format::{StreamHeader, STREAM_HEADER_SIZE};
use super::{StreamProgress, KEY_LEN, TAG_LEN};

/// Streaming decryption — reads a stream-encrypted file and decrypts chunk by chunk.
pub(crate) fn stream_decrypt_impl(
    input_path: &Path,
    output_path: &Path,
    key: &[u8],
    mut on_progress: impl FnMut(&StreamProgress),
) -> Result<(), CryptoError> {
    if key.len() != KEY_LEN {
        return Err(CryptoError::InvalidKeyLength {
            expected: KEY_LEN,
            actual: key.len(),
        });
    }

    let mut input = File::open(input_path)?;
    let file_size = input.metadata()?.len();

    if file_size < STREAM_HEADER_SIZE as u64 {
        return Err(CryptoError::InvalidParameter(
            "File too small to contain stream header".to_string(),
        ));
    }

    // Read and parse header
    let mut header_bytes = [0u8; STREAM_HEADER_SIZE];
    input.read_exact(&mut header_bytes)?;
    let header = StreamHeader::from_bytes(&header_bytes)?;

    let chunk_size = header.chunk_size as usize;
    let total_chunks = header.total_chunks;
    let data_size = file_size - STREAM_HEADER_SIZE as u64;
    let enc_chunk_size = chunk_size as u64 + TAG_LEN as u64;

    // Validate total_chunks vs actual data size
    if total_chunks == 0 {
        if data_size > 0 {
            return Err(CryptoError::InvalidParameter(
                "Header claims zero chunks but file contains ciphertext data".to_string(),
            ));
        }
    } else {
        // Last chunk: at least tag-only (0-byte plaintext for empty files)
        let min_data = (total_chunks - 1) * enc_chunk_size + TAG_LEN as u64;
        let max_data = total_chunks * enc_chunk_size;
        if data_size < min_data || data_size > max_data {
            return Err(CryptoError::InvalidParameter(
                "Data size does not match chunk count in header".to_string(),
            ));
        }
    }

    // Derive per-file encryption key from master key + file salt
    let key_ctx = StreamKeyContext::new(key, &header.file_salt);
    let file_key = key_ctx.derive_file_key()?;

    let cipher = CipherInstance::from_algorithm(header.algorithm, file_key.as_ref())?;

    // Compute expected total plaintext for progress reporting
    let total_plaintext = if total_chunks == 0 {
        0u64
    } else {
        let last_enc_size = data_size - (total_chunks - 1) * enc_chunk_size;
        let last_plain_size = last_enc_size - TAG_LEN as u64;
        (total_chunks - 1) * chunk_size as u64 + last_plain_size
    };

    let mut output = File::create(output_path)?;
    let mut bytes_processed: u64 = 0;

    for chunk_idx in 0..total_chunks {
        let encrypted_chunk_size = if chunk_idx < total_chunks - 1 {
            chunk_size + TAG_LEN
        } else {
            let prior_bytes = (total_chunks - 1) * enc_chunk_size;
            (data_size - prior_bytes) as usize
        };

        let mut encrypted_buf = vec![0u8; encrypted_chunk_size];
        input.read_exact(&mut encrypted_buf)?;

        let nonce = key_ctx.derive_chunk_nonce(chunk_idx)?;
        let aad = build_chunk_aad(&header_bytes, chunk_idx);

        let plaintext = cipher.decrypt(
            &nonce,
            Payload {
                msg: &encrypted_buf,
                aad: &aad,
            },
        )?;

        output.write_all(&plaintext)?;

        bytes_processed += plaintext.len() as u64;
        on_progress(&StreamProgress {
            bytes_processed,
            total_bytes: total_plaintext,
            chunks_completed: chunk_idx + 1,
            total_chunks,
        });
    }

    output.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::streaming::encrypt::stream_encrypt_impl;
    use crate::api::streaming::StreamCipher;
    use crate::core::rng::generate_random_bytes;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn make_key() -> Vec<u8> {
        generate_random_bytes(32).expect("key gen")
    }

    fn write_temp_file(data: &[u8]) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(data).expect("write");
        f.flush().expect("flush");
        f
    }

    fn encrypt_then_decrypt(data: &[u8], algorithm: StreamCipher) -> Vec<u8> {
        let key = make_key();
        let input = write_temp_file(data);
        let encrypted = NamedTempFile::new().expect("enc");
        let decrypted = NamedTempFile::new().expect("dec");

        stream_encrypt_impl(input.path(), encrypted.path(), &key, algorithm, |_| {}).expect("encrypt");
        stream_decrypt_impl(encrypted.path(), decrypted.path(), &key, |_| {}).expect("decrypt");

        std::fs::read(decrypted.path()).expect("read decrypted")
    }

    #[test]
    fn roundtrip_aes_gcm_small() {
        let data = b"hello streaming roundtrip!";
        let result = encrypt_then_decrypt(data, StreamCipher::AesGcm);
        assert_eq!(result, data);
    }

    #[test]
    fn roundtrip_chacha_small() {
        let data = b"hello chacha streaming!";
        let result = encrypt_then_decrypt(data, StreamCipher::ChaCha20Poly1305);
        assert_eq!(result, data);
    }

    #[test]
    fn roundtrip_exact_chunk_boundary() {
        let data = vec![0xCDu8; 65536 * 2];
        let result = encrypt_then_decrypt(&data, StreamCipher::AesGcm);
        assert_eq!(result, data);
    }

    #[test]
    fn roundtrip_multi_chunk() {
        let data = vec![0xABu8; 65536 * 2 + 32768];
        let result = encrypt_then_decrypt(&data, StreamCipher::ChaCha20Poly1305);
        assert_eq!(result, data);
    }

    #[test]
    fn roundtrip_empty_file() {
        let data = b"";
        let result = encrypt_then_decrypt(data, StreamCipher::AesGcm);
        assert_eq!(result, data);
    }

    #[test]
    fn roundtrip_one_byte() {
        let data = b"\x42";
        let result = encrypt_then_decrypt(data, StreamCipher::AesGcm);
        assert_eq!(result, data);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = make_key();
        let key2 = make_key();
        let input = write_temp_file(b"secret data");
        let encrypted = NamedTempFile::new().expect("enc");
        let decrypted = NamedTempFile::new().expect("dec");

        stream_encrypt_impl(input.path(), encrypted.path(), &key1, StreamCipher::AesGcm, |_| {})
            .expect("encrypt");

        let result = stream_decrypt_impl(encrypted.path(), decrypted.path(), &key2, |_| {});
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn tampered_chunk_fails() {
        let key = make_key();
        let input = write_temp_file(b"data that will be tampered");
        let encrypted = NamedTempFile::new().expect("enc");
        let decrypted = NamedTempFile::new().expect("dec");

        stream_encrypt_impl(input.path(), encrypted.path(), &key, StreamCipher::AesGcm, |_| {})
            .expect("encrypt");

        let mut enc_data = std::fs::read(encrypted.path()).expect("read");
        if enc_data.len() > STREAM_HEADER_SIZE + 1 {
            enc_data[STREAM_HEADER_SIZE + 1] ^= 0xFF;
            std::fs::write(encrypted.path(), &enc_data).expect("write tampered");
        }

        let result = stream_decrypt_impl(encrypted.path(), decrypted.path(), &key, |_| {});
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn tampered_header_fails() {
        let key = make_key();
        let input = write_temp_file(b"header integrity test");
        let encrypted = NamedTempFile::new().expect("enc");
        let decrypted = NamedTempFile::new().expect("dec");

        stream_encrypt_impl(input.path(), encrypted.path(), &key, StreamCipher::AesGcm, |_| {})
            .expect("encrypt");

        // Tamper with the file_salt in the header (byte 18)
        let mut enc_data = std::fs::read(encrypted.path()).expect("read");
        enc_data[18] ^= 0xFF;
        std::fs::write(encrypted.path(), &enc_data).expect("write tampered");

        let result = stream_decrypt_impl(encrypted.path(), decrypted.path(), &key, |_| {});
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn reordered_chunks_fail() {
        let key = make_key();
        let data = vec![0xABu8; 65536 * 3];
        let input = write_temp_file(&data);
        let encrypted = NamedTempFile::new().expect("enc");
        let decrypted = NamedTempFile::new().expect("dec");

        stream_encrypt_impl(input.path(), encrypted.path(), &key, StreamCipher::AesGcm, |_| {})
            .expect("encrypt");

        let mut enc_data = std::fs::read(encrypted.path()).expect("read");
        let enc_chunk_size = 65536 + TAG_LEN;

        // Swap chunk 0 and chunk 1
        let chunk0_start = STREAM_HEADER_SIZE;
        let chunk1_start = STREAM_HEADER_SIZE + enc_chunk_size;
        let chunk0: Vec<u8> = enc_data[chunk0_start..chunk1_start].to_vec();
        let chunk1: Vec<u8> = enc_data[chunk1_start..chunk1_start + enc_chunk_size].to_vec();
        enc_data[chunk0_start..chunk1_start].copy_from_slice(&chunk1);
        enc_data[chunk1_start..chunk1_start + enc_chunk_size].copy_from_slice(&chunk0);
        std::fs::write(encrypted.path(), &enc_data).expect("write swapped");

        let result = stream_decrypt_impl(encrypted.path(), decrypted.path(), &key, |_| {});
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn truncated_file_fails() {
        let key = make_key();
        let input = write_temp_file(b"some data to encrypt");
        let encrypted = NamedTempFile::new().expect("enc");
        let decrypted = NamedTempFile::new().expect("dec");

        stream_encrypt_impl(input.path(), encrypted.path(), &key, StreamCipher::AesGcm, |_| {})
            .expect("encrypt");

        let enc_data = std::fs::read(encrypted.path()).expect("read");
        let truncated = &enc_data[..STREAM_HEADER_SIZE + 5];
        std::fs::write(encrypted.path(), truncated).expect("write truncated");

        let result = stream_decrypt_impl(encrypted.path(), decrypted.path(), &key, |_| {});
        assert!(result.is_err());
    }

    #[test]
    fn progress_reports_correct_totals() {
        let key = make_key();
        let data = vec![0xFFu8; 65536 * 2 + 100]; // 3 chunks
        let input = write_temp_file(&data);
        let encrypted = NamedTempFile::new().expect("enc");
        let decrypted = NamedTempFile::new().expect("dec");

        stream_encrypt_impl(input.path(), encrypted.path(), &key, StreamCipher::AesGcm, |_| {})
            .expect("encrypt");

        let mut progress = Vec::new();
        stream_decrypt_impl(encrypted.path(), decrypted.path(), &key, |p| {
            progress.push(p.clone());
        })
        .expect("decrypt");

        assert_eq!(progress.len(), 3);
        let last = progress.last().expect("last");
        assert_eq!(last.chunks_completed, 3);
        assert_eq!(last.total_chunks, 3);
        assert_eq!(last.bytes_processed, data.len() as u64);
        assert_eq!(last.total_bytes, data.len() as u64);
    }

    #[test]
    fn invalid_key_length() {
        let input = write_temp_file(b"data");
        let encrypted = NamedTempFile::new().expect("enc");
        let key = make_key();

        stream_encrypt_impl(input.path(), encrypted.path(), &key, StreamCipher::AesGcm, |_| {})
            .expect("encrypt");

        let decrypted = NamedTempFile::new().expect("dec");
        let result = stream_decrypt_impl(encrypted.path(), decrypted.path(), &[0u8; 16], |_| {});
        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: 16
            })
        ));
    }

    #[test]
    fn zero_chunks_with_data_fails() {
        let key = make_key();
        let input = write_temp_file(b"data");
        let encrypted = NamedTempFile::new().expect("enc");
        let decrypted = NamedTempFile::new().expect("dec");

        stream_encrypt_impl(input.path(), encrypted.path(), &key, StreamCipher::AesGcm, |_| {})
            .expect("encrypt");

        // Set total_chunks to 0 in header while keeping ciphertext
        let mut enc_data = std::fs::read(encrypted.path()).expect("read");
        enc_data[10..18].copy_from_slice(&0u64.to_le_bytes());
        std::fs::write(encrypted.path(), &enc_data).expect("write");

        let result = stream_decrypt_impl(encrypted.path(), decrypted.path(), &key, |_| {});
        assert!(result.is_err());
    }
}
