//! Streaming file encryption, decryption, compression, and hashing API.
//!
//! Core logic uses a progress callback closure so it's testable without FRB.
//! The public FRB-visible functions are thin wrappers that forward progress
//! to a `StreamSink`.
//!
//! Both encrypt and decrypt write to a temporary file first, then atomically
//! rename on success. On any error the partial output is deleted — a failed
//! decryption never leaves plaintext on disk.

#[cfg(feature = "compression")]
mod compress;
mod decrypt;
mod encrypt;
pub(crate) mod hash;

#[cfg(test)]
mod tests;

use std::fs::{self, File};
use std::io::{BufReader, Read};

#[cfg(feature = "compression")]
use crate::api::compression::CompressionConfig;
use crate::api::encryption::CipherHandle;
use crate::api::hashing::HasherHandle;
use crate::core::error::CryptoError;
use crate::core::streaming::{
    EncryptedChunk, StreamAlgorithm, CHUNK_SIZE, ENCRYPTED_CHUNK_SIZE, NONCE_SIZE,
};

// Re-export impl functions for internal use and tests
#[cfg(feature = "compression")]
pub(crate) use compress::{compress_encrypt_file_impl, decrypt_decompress_file_impl};
pub(crate) use decrypt::decrypt_file_impl;
pub(crate) use encrypt::encrypt_file_impl;
pub(crate) use hash::hash_file_feed;

// -- Shared helpers -----------------------------------------------------------

fn algorithm_from_id(id: &str) -> Result<StreamAlgorithm, CryptoError> {
    match id {
        "aes-256-gcm" => Ok(StreamAlgorithm::AesGcm),
        "chacha20-poly1305" => Ok(StreamAlgorithm::ChaCha20Poly1305),
        other => Err(CryptoError::InvalidParameter(format!(
            "Algorithm '{other}' not supported for streaming"
        ))),
    }
}

fn parse_encrypted_output(data: &[u8], chunk: &mut EncryptedChunk) -> Result<(), CryptoError> {
    if data.len() != ENCRYPTED_CHUNK_SIZE {
        return Err(CryptoError::InvalidParameter(format!(
            "Cipher output wrong size: {} bytes, expected {ENCRYPTED_CHUNK_SIZE}",
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

/// Open an input file and return a buffered reader + file size.
fn open_input(path: &str) -> Result<(BufReader<File>, u64), CryptoError> {
    let file = File::open(path)
        .map_err(|e| CryptoError::IoError(format!("Cannot open input '{path}': {e}")))?;
    let size = file
        .metadata()
        .map_err(|e| CryptoError::IoError(format!("Cannot stat input: {e}")))?
        .len();
    Ok((BufReader::new(file), size))
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

// -- FRB entry points (thin wrappers) ----------------------------------------

use crate::frb_generated::StreamSink;

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

pub fn stream_hash_file(
    hasher: &HasherHandle,
    file_path: String,
    progress_sink: StreamSink<f64>,
) -> Result<(), CryptoError> {
    hash_file_feed(hasher, &file_path, &|p| {
        let _ = progress_sink.add(p);
    })
}
