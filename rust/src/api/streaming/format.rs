//! Stream file header format for chunked encryption.

use crate::core::error::CryptoError;
use crate::core::format::{Algorithm, FORMAT_VERSION, MAGIC};

const SALT_LEN: usize = 32;

/// Total header size: magic(4) + version(1) + algorithm(1) + chunk_size(4) + total_chunks(8) + salt(32)
pub const STREAM_HEADER_SIZE: usize = 4 + 1 + 1 + 4 + 8 + SALT_LEN;

/// Maximum allowed chunk size (4 MB) — prevents OOM from malformed headers.
pub const MAX_CHUNK_SIZE: u32 = 4 * 1024 * 1024;

/// Header written at the start of a stream-encrypted file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamHeader {
    pub algorithm: Algorithm,
    pub chunk_size: u32,
    pub total_chunks: u64,
    pub file_salt: [u8; SALT_LEN],
}

impl StreamHeader {
    pub fn new(
        algorithm: Algorithm,
        chunk_size: u32,
        total_chunks: u64,
        file_salt: [u8; SALT_LEN],
    ) -> Self {
        Self {
            algorithm,
            chunk_size,
            total_chunks,
            file_salt,
        }
    }

    pub fn to_bytes(&self) -> [u8; STREAM_HEADER_SIZE] {
        let mut buf = [0u8; STREAM_HEADER_SIZE];
        buf[0..4].copy_from_slice(MAGIC);
        buf[4] = FORMAT_VERSION;
        buf[5] = self.algorithm.to_byte();
        buf[6..10].copy_from_slice(&self.chunk_size.to_le_bytes());
        buf[10..18].copy_from_slice(&self.total_chunks.to_le_bytes());
        buf[18..50].copy_from_slice(&self.file_salt);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() < STREAM_HEADER_SIZE {
            return Err(CryptoError::InvalidParameter(format!(
                "Stream header too short: {} bytes, need {}",
                data.len(),
                STREAM_HEADER_SIZE
            )));
        }

        if &data[0..4] != MAGIC {
            return Err(CryptoError::InvalidParameter(
                "Invalid magic bytes".to_string(),
            ));
        }

        let version = data[4];
        if version != FORMAT_VERSION {
            return Err(CryptoError::InvalidParameter(format!(
                "Unsupported format version: {}",
                version
            )));
        }

        let algorithm = Algorithm::from_byte(data[5])?;

        let chunk_size = u32::from_le_bytes([data[6], data[7], data[8], data[9]]);
        if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
            return Err(CryptoError::InvalidParameter(format!(
                "Chunk size {} out of valid range (1..={})",
                chunk_size, MAX_CHUNK_SIZE
            )));
        }

        let total_chunks =
            u64::from_le_bytes([data[10], data[11], data[12], data[13], data[14], data[15], data[16], data[17]]);

        let mut file_salt = [0u8; SALT_LEN];
        file_salt.copy_from_slice(&data[18..50]);

        Ok(Self {
            algorithm,
            chunk_size,
            total_chunks,
            file_salt,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_salt() -> [u8; 32] {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = i as u8;
        }
        s
    }

    #[test]
    fn roundtrip() {
        let header = StreamHeader::new(Algorithm::AesGcm, 65536, 100, make_salt());
        let bytes = header.to_bytes();
        let parsed = StreamHeader::from_bytes(&bytes).expect("parse failed");
        assert_eq!(header, parsed);
    }

    #[test]
    fn roundtrip_chacha() {
        let header = StreamHeader::new(Algorithm::ChaCha20Poly1305, 32768, 1, make_salt());
        let bytes = header.to_bytes();
        let parsed = StreamHeader::from_bytes(&bytes).expect("parse failed");
        assert_eq!(header, parsed);
    }

    #[test]
    fn header_layout() {
        let salt = make_salt();
        let header = StreamHeader::new(Algorithm::AesGcm, 65536, 42, salt);
        let bytes = header.to_bytes();

        assert_eq!(&bytes[0..4], b"MSEC");
        assert_eq!(bytes[4], FORMAT_VERSION);
        assert_eq!(bytes[5], Algorithm::AesGcm.to_byte());
        assert_eq!(u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]), 65536);
        assert_eq!(
            u64::from_le_bytes([bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15], bytes[16], bytes[17]]),
            42
        );
        assert_eq!(&bytes[18..50], &salt);
    }

    #[test]
    fn invalid_magic() {
        let mut bytes = StreamHeader::new(Algorithm::AesGcm, 65536, 1, make_salt()).to_bytes();
        bytes[0] = b'X';
        assert!(StreamHeader::from_bytes(&bytes).is_err());
    }

    #[test]
    fn invalid_algorithm() {
        let mut bytes = StreamHeader::new(Algorithm::AesGcm, 65536, 1, make_salt()).to_bytes();
        bytes[5] = 0xFF;
        assert!(StreamHeader::from_bytes(&bytes).is_err());
    }

    #[test]
    fn truncated_input() {
        let bytes = [0u8; 10];
        assert!(StreamHeader::from_bytes(&bytes).is_err());
    }

    #[test]
    fn zero_chunk_size_rejected() {
        let mut bytes = StreamHeader::new(Algorithm::AesGcm, 65536, 1, make_salt()).to_bytes();
        // Zero out chunk_size
        bytes[6] = 0;
        bytes[7] = 0;
        bytes[8] = 0;
        bytes[9] = 0;
        assert!(StreamHeader::from_bytes(&bytes).is_err());
    }

    #[test]
    fn header_size_is_50() {
        assert_eq!(STREAM_HEADER_SIZE, 50);
    }

    #[test]
    fn oversized_chunk_size_rejected() {
        let mut bytes = StreamHeader::new(Algorithm::AesGcm, 65536, 1, make_salt()).to_bytes();
        // Set chunk_size to MAX_CHUNK_SIZE + 1
        let bad_size = (MAX_CHUNK_SIZE + 1).to_le_bytes();
        bytes[6..10].copy_from_slice(&bad_size);
        assert!(StreamHeader::from_bytes(&bytes).is_err());
    }
}
