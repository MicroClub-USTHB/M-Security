//! Streaming file hashing API, plus the encrypted-stream code kept for tests.
//!
//! Core logic uses a progress callback closure so it's testable without FRB.
//! The public FRB-visible function is a thin wrapper that forwards progress
//! to a `StreamSink`.
//!
//! The `MSSE` header is unauthenticated and a chunk carries only its index and
//! finality, so a chunk from another stream encrypted under the same handle
//! splices in. This release exports no way to write or read that format: the
//! encrypt, decrypt and compressed variants below are compiled for the
//! regression tests only, and the Dart methods that used to call them now
//! return a disabled-format result. Hashing is unaffected.
//!
//! The retained encrypt and decrypt code writes to a temporary file first and
//! renames atomically on success, deleting the partial output on any error, so a
//! failed decryption leaves no plaintext on disk. That is a property of the test
//! path only: nothing in the shipped library reaches it.

#[cfg(all(test, feature = "compression"))]
mod compress;
#[cfg(test)]
mod decrypt;
#[cfg(test)]
mod encrypt;
pub(crate) mod hash;

#[cfg(test)]
mod tests;

#[cfg(test)]
use std::fs::{self, File};
#[cfg(test)]
use std::io::BufReader;
use std::io::Read;

use crate::api::hashing::HasherHandle;
use crate::core::error::CryptoError;
#[cfg(test)]
use crate::core::streaming::{
    EncryptedChunk, StreamAlgorithm, CHUNK_SIZE, ENCRYPTED_CHUNK_SIZE, NONCE_SIZE,
};

// Re-export impl functions for internal use and tests
#[cfg(all(test, feature = "compression"))]
pub(crate) use compress::{compress_encrypt_file_impl, decrypt_decompress_file_impl};
#[cfg(test)]
pub(crate) use decrypt::decrypt_file_impl;
#[cfg(test)]
pub(crate) use encrypt::encrypt_file_impl;
pub(crate) use hash::hash_file_feed;

// -- Shared helpers -----------------------------------------------------------

#[cfg(test)]
fn algorithm_from_id(id: &str) -> Result<StreamAlgorithm, CryptoError> {
    match id {
        "aes-256-gcm" => Ok(StreamAlgorithm::AesGcm),
        "chacha20-poly1305" => Ok(StreamAlgorithm::ChaCha20Poly1305),
        other => Err(CryptoError::InvalidParameter(format!(
            "Algorithm '{other}' not supported for streaming"
        ))),
    }
}

#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
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
#[cfg(test)]
struct TempFileGuard {
    path: String,
    active: bool,
}

#[cfg(test)]
impl TempFileGuard {
    fn new(path: String) -> Self {
        Self { path, active: true }
    }

    fn defuse(&mut self) {
        self.active = false;
    }
}

#[cfg(test)]
impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = fs::remove_file(&self.path);
        }
    }
}

// -- FRB entry points (thin wrappers) ----------------------------------------

use crate::frb_generated::StreamSink;

pub fn stream_hash_file(
    hasher: &HasherHandle,
    file_path: String,
    progress_sink: StreamSink<f64>,
) -> Result<(), CryptoError> {
    hash_file_feed(hasher, &file_path, &|p| {
        let _ = progress_sink.add(p);
    })
}
