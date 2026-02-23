//! Streaming file encryption, decryption, and hashing.
//!
//! All operations process files in 64KB chunks with constant ~20MB memory.
//! Progress is reported via callbacks (FRB StreamSink wrappers will be added
//! when codegen runs for Dart bindings).

pub mod decrypt;
pub mod encrypt;
pub mod hash;
pub(crate) mod crypto;
mod format;

use flutter_rust_bridge::frb;

/// AEAD algorithm for streaming encryption.
#[frb(non_opaque)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamCipher {
    AesGcm,
    ChaCha20Poly1305,
}

/// Hash algorithm for streaming file hashing.
#[frb(non_opaque)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamHashAlgorithm {
    Blake3,
    Sha3,
}

/// Progress info emitted during streaming operations.
#[frb(non_opaque)]
#[derive(Debug, Clone)]
pub struct StreamProgress {
    pub bytes_processed: u64,
    pub total_bytes: u64,
    pub chunks_completed: u64,
    pub total_chunks: u64,
}

/// Default plaintext chunk size: 64KB.
pub const DEFAULT_CHUNK_SIZE: u32 = 65536;

/// Auth tag size for both AES-GCM and ChaCha20-Poly1305.
pub(crate) const TAG_LEN: usize = 16;

/// Key length for both AES-256-GCM and ChaCha20-Poly1305.
pub(crate) const KEY_LEN: usize = 32;

/// Nonce length for both algorithms (96-bit IETF standard).
pub(crate) const NONCE_LEN: usize = 12;

// FRB StreamSink API wrappers will be added here after codegen.
// Intended signatures:
//
//   pub fn stream_encrypt_file(
//       input_path: String, output_path: String,
//       key: Vec<u8>, algorithm: StreamCipher,
//       sink: StreamSink<StreamProgress>,
//   ) -> Result<(), CryptoError>
//
//   pub fn stream_decrypt_file(
//       input_path: String, output_path: String,
//       key: Vec<u8>,
//       sink: StreamSink<StreamProgress>,
//   ) -> Result<(), CryptoError>
//
//   pub fn stream_hash_file(
//       input_path: String, algorithm: StreamHashAlgorithm,
//       sink: StreamSink<StreamProgress>,
//   ) -> Result<Vec<u8>, CryptoError>
