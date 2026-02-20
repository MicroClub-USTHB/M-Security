//! Format versioning for encrypted file headers.

use crate::core::error::CryptoError;

/// Magic bytes identifying M-Security encrypted data.
pub const MAGIC: &[u8; 4] = b"MSEC";

/// Current format version.
pub const FORMAT_VERSION: u8 = 1;

/// Header size in bytes (magic + version + algorithm).
pub const HEADER_SIZE: usize = 6;

/// Algorithm identifiers for the format header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Algorithm {
    AesGcm = 0x01,
    ChaCha20Poly1305 = 0x02,
    XChaCha20Poly1305 = 0x03,
}

impl Algorithm {
    /// Convert from byte value.
    pub fn from_byte(b: u8) -> Result<Self, CryptoError> {
        match b {
            0x01 => Ok(Algorithm::AesGcm),
            0x02 => Ok(Algorithm::ChaCha20Poly1305),
            0x03 => Ok(Algorithm::XChaCha20Poly1305),
            _ => Err(CryptoError::InvalidParameter(format!(
                "Unknown algorithm: 0x{:02X}",
                b
            ))),
        }
    }

    /// Convert to byte value.
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

/// File format header for encrypted data.
///
/// Layout: [MAGIC (4)] [VERSION (1)] [ALGORITHM (1)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatHeader {
    pub version: u8,
    pub algorithm: Algorithm,
}

impl FormatHeader {
    /// Create a new header with the current format version.
    pub fn new(algorithm: Algorithm) -> Self {
        Self {
            version: FORMAT_VERSION,
            algorithm,
        }
    }

    /// Serialize header to bytes.
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(MAGIC);
        buf[4] = self.version;
        buf[5] = self.algorithm.to_byte();
        buf
    }

    /// Parse header from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() < HEADER_SIZE {
            return Err(CryptoError::InvalidParameter(format!(
                "Header too short: {} bytes, need {}",
                data.len(),
                HEADER_SIZE
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

        Ok(Self { version, algorithm })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip() {
        let header = FormatHeader::new(Algorithm::AesGcm);
        let bytes = header.to_bytes();
        let parsed = FormatHeader::from_bytes(&bytes).expect("parse failed");
        assert_eq!(header, parsed);
    }

    #[test]
    fn test_header_layout() {
        let header = FormatHeader::new(Algorithm::ChaCha20Poly1305);
        let bytes = header.to_bytes();
        assert_eq!(&bytes[0..4], b"MSEC");
        assert_eq!(bytes[4], FORMAT_VERSION);
        assert_eq!(bytes[5], Algorithm::ChaCha20Poly1305.to_byte());
    }

    #[test]
    fn test_invalid_magic() {
        let mut bytes = FormatHeader::new(Algorithm::AesGcm).to_bytes();
        bytes[0] = b'X';
        let result = FormatHeader::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_algorithm() {
        let result = Algorithm::from_byte(0xFF);
        assert!(result.is_err());
    }
}
