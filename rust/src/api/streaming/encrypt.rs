//! Streaming file encryption with chunked AEAD and HKDF-derived nonces.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use aes_gcm::aead::Payload;

use crate::core::error::CryptoError;
use crate::core::rng::generate_random_bytes;

use super::crypto::{algorithm_to_format, build_chunk_aad, CipherInstance, StreamKeyContext};
use super::format::StreamHeader;
use super::{StreamCipher, StreamProgress, DEFAULT_CHUNK_SIZE, KEY_LEN};

/// Streaming encryption — processes a file in 64KB chunks with constant memory.
///
/// Derives a per-file encryption key from the master key + random salt via HKDF,
/// so the master key never touches the AEAD cipher directly.
pub(crate) fn stream_encrypt_impl(
    input_path: &Path,
    output_path: &Path,
    key: &[u8],
    algorithm: StreamCipher,
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

    let chunk_size = DEFAULT_CHUNK_SIZE as u64;
    // Empty files get 1 chunk (zero-length plaintext sealed by AEAD) so the
    // header is always integrity-bound to at least one authenticated operation.
    let total_chunks = if file_size == 0 {
        1
    } else {
        file_size.div_ceil(chunk_size)
    };

    // Random per-file salt for HKDF key + nonce derivation
    let salt_vec = generate_random_bytes(32)?;
    let mut file_salt = [0u8; 32];
    file_salt.copy_from_slice(&salt_vec);

    let header = StreamHeader::new(
        algorithm_to_format(algorithm),
        DEFAULT_CHUNK_SIZE,
        total_chunks,
        file_salt,
    );
    let header_bytes = header.to_bytes();

    // Derive per-file encryption key (master key never used directly as AEAD key)
    let key_ctx = StreamKeyContext::new(key, &file_salt);
    let file_key = key_ctx.derive_file_key()?;

    let cipher = CipherInstance::new(algorithm, file_key.as_ref())?;

    let mut output = File::create(output_path)?;
    output.write_all(&header_bytes)?;

    let mut buf = vec![0u8; DEFAULT_CHUNK_SIZE as usize];
    let mut bytes_processed: u64 = 0;

    for chunk_idx in 0..total_chunks {
        let bytes_to_read = std::cmp::min(
            DEFAULT_CHUNK_SIZE as u64,
            file_size - chunk_idx * chunk_size,
        ) as usize;

        let chunk = &mut buf[..bytes_to_read];
        input.read_exact(chunk)?;

        let nonce = key_ctx.derive_chunk_nonce(chunk_idx)?;
        let aad = build_chunk_aad(&header_bytes, chunk_idx);

        let encrypted = cipher.encrypt(
            &nonce,
            Payload {
                msg: chunk,
                aad: &aad,
            },
        )?;

        output.write_all(&encrypted)?;

        bytes_processed += bytes_to_read as u64;
        on_progress(&StreamProgress {
            bytes_processed,
            total_bytes: file_size,
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
    use crate::api::streaming::format::STREAM_HEADER_SIZE;
    use crate::core::format::Algorithm;
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

    #[test]
    fn encrypt_creates_valid_header() {
        let key = make_key();
        let input = write_temp_file(b"hello streaming encryption");
        let output = NamedTempFile::new().expect("output");

        stream_encrypt_impl(
            input.path(),
            output.path(),
            &key,
            StreamCipher::AesGcm,
            |_| {},
        )
        .expect("encrypt");

        let data = std::fs::read(output.path()).expect("read output");
        let header = StreamHeader::from_bytes(&data).expect("parse header");
        assert_eq!(header.algorithm, Algorithm::AesGcm);
        assert_eq!(header.chunk_size, DEFAULT_CHUNK_SIZE);
        assert_eq!(header.total_chunks, 1);
    }

    #[test]
    fn encrypt_multi_chunk() {
        let key = make_key();
        let data = vec![0xABu8; (DEFAULT_CHUNK_SIZE as usize) * 2 + DEFAULT_CHUNK_SIZE as usize / 2];
        let input = write_temp_file(&data);
        let output = NamedTempFile::new().expect("output");

        let mut progress_updates = Vec::new();
        stream_encrypt_impl(
            input.path(),
            output.path(),
            &key,
            StreamCipher::ChaCha20Poly1305,
            |p| progress_updates.push(p.clone()),
        )
        .expect("encrypt");

        let out_data = std::fs::read(output.path()).expect("read output");
        let header = StreamHeader::from_bytes(&out_data).expect("parse header");
        assert_eq!(header.algorithm, Algorithm::ChaCha20Poly1305);
        assert_eq!(header.total_chunks, 3);
        assert_eq!(progress_updates.len(), 3);
        assert_eq!(progress_updates.last().expect("last").chunks_completed, 3);
    }

    #[test]
    fn encrypt_empty_file() {
        let key = make_key();
        let input = write_temp_file(b"");
        let output = NamedTempFile::new().expect("output");

        stream_encrypt_impl(
            input.path(),
            output.path(),
            &key,
            StreamCipher::AesGcm,
            |_| {},
        )
        .expect("encrypt");

        let data = std::fs::read(output.path()).expect("read");
        let header = StreamHeader::from_bytes(&data).expect("header");
        // Empty file still gets 1 AEAD-sealed chunk (zero-length plaintext + 16-byte tag)
        assert_eq!(header.total_chunks, 1);
        assert_eq!(data.len(), STREAM_HEADER_SIZE + 16); // header + auth tag only
    }

    #[test]
    fn invalid_key_length() {
        let input = write_temp_file(b"data");
        let output = NamedTempFile::new().expect("output");

        let result = stream_encrypt_impl(
            input.path(),
            output.path(),
            &[0u8; 16],
            StreamCipher::AesGcm,
            |_| {},
        );
        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: 16
            })
        ));
    }
}
