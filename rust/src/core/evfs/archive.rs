//! `.mvex` portable encrypted archive format — types, constants, and serialization.

use crate::core::error::CryptoError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const ARCHIVE_MAGIC: &[u8; 4] = b"MVEX";
pub const REVERSE_MAGIC: &[u8; 4] = b"XEVM";
pub const ARCHIVE_VERSION: u8 = 1;

pub const ARCHIVE_HEADER_SIZE: usize = 32;
pub const WRAPPED_KEY_SIZE: usize = 60; // 12 nonce + 32 ciphertext + 16 tag
pub const ARCHIVE_TRAILER_SIZE: usize = 36; // 32 BLAKE3 + 4 reverse magic

/// AAD used when wrapping the ephemeral export key with the caller's wrapping key.
pub const KEY_WRAP_AAD: &[u8] = b"msec-export-key-wrap";

// ---------------------------------------------------------------------------
// ArchiveHeader (32 bytes)
// ---------------------------------------------------------------------------

/// Fixed-size header at the start of every `.mvex` archive.
///
/// ```text
/// [0..4]   magic "MVEX"
/// [4]      version (1)
/// [5]      algorithm byte (matches vault Algorithm enum)
/// [6..8]   flags (reserved, LE u16)
/// [8..12]  segment_count (LE u32)
/// [12..32] reserved (zeros)
/// ```
pub struct ArchiveHeader {
    pub version: u8,
    pub algorithm: u8,
    pub flags: u16,
    pub segment_count: u32,
}

impl ArchiveHeader {
    pub fn new(algorithm: u8, segment_count: u32) -> Self {
        Self {
            version: ARCHIVE_VERSION,
            algorithm,
            flags: 0,
            segment_count,
        }
    }

    pub fn to_bytes(&self) -> [u8; ARCHIVE_HEADER_SIZE] {
        let mut buf = [0u8; ARCHIVE_HEADER_SIZE];
        buf[0..4].copy_from_slice(ARCHIVE_MAGIC);
        buf[4] = self.version;
        buf[5] = self.algorithm;
        buf[6..8].copy_from_slice(&self.flags.to_le_bytes());
        buf[8..12].copy_from_slice(&self.segment_count.to_le_bytes());
        // [12..32] reserved zeros
        buf
    }

    pub fn from_bytes(buf: &[u8; ARCHIVE_HEADER_SIZE]) -> Result<Self, CryptoError> {
        if &buf[0..4] != ARCHIVE_MAGIC {
            return Err(CryptoError::ExportFailed("invalid archive magic".into()));
        }
        let version = buf[4];
        if version != ARCHIVE_VERSION {
            return Err(CryptoError::ExportFailed(format!(
                "unsupported archive version: {version}"
            )));
        }
        let algorithm = buf[5];
        let flags = u16::from_le_bytes([buf[6], buf[7]]);
        let segment_count = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        Ok(Self {
            version,
            algorithm,
            flags,
            segment_count,
        })
    }
}

// ---------------------------------------------------------------------------
// SegmentRecord — per-segment entry in the archive
// ---------------------------------------------------------------------------

/// A single segment record in the archive.
///
/// ```text
/// [name_len: u16 LE] [name: UTF-8 bytes]
/// [compression: u8]
/// [checksum: 32 bytes BLAKE3]
/// [data_len: u64 LE]  (length of encrypted_data: nonce + ciphertext + tag)
/// [encrypted_data: data_len bytes]
/// ```
pub struct SegmentRecord {
    pub name: String,
    pub compression: u8,
    pub checksum: [u8; 32],
    pub encrypted_data: Vec<u8>,
}

impl SegmentRecord {
    /// Serialize the record header (everything before encrypted_data) into bytes.
    /// Returns the header bytes. The caller writes encrypted_data separately.
    pub fn write_header(&self) -> Result<Vec<u8>, CryptoError> {
        let name_bytes = self.name.as_bytes();
        let name_len = u16::try_from(name_bytes.len()).map_err(|_| {
            CryptoError::ExportFailed("segment name too long for archive".into())
        })?;
        let data_len = self.encrypted_data.len() as u64;

        // name_len(2) + name + compression(1) + checksum(32) + data_len(8)
        let header_size = 2 + name_bytes.len() + 1 + 32 + 8;
        let mut buf = Vec::with_capacity(header_size);

        buf.extend_from_slice(&name_len.to_le_bytes());
        buf.extend_from_slice(name_bytes);
        buf.push(self.compression);
        buf.extend_from_slice(&self.checksum);
        buf.extend_from_slice(&data_len.to_le_bytes());

        Ok(buf)
    }

    /// Read a segment record header from a byte slice, returning (record_minus_data, bytes_consumed).
    /// The caller must then read `data_len` bytes of encrypted_data.
    pub fn read_header(data: &[u8]) -> Result<(String, u8, [u8; 32], u64, usize), CryptoError> {
        if data.len() < 2 {
            return Err(CryptoError::ExportFailed("truncated segment record".into()));
        }
        let name_len = u16::from_le_bytes([data[0], data[1]]) as usize;
        let mut pos = 2;

        if data.len() < pos + name_len + 1 + 32 + 8 {
            return Err(CryptoError::ExportFailed("truncated segment record".into()));
        }

        let name = std::str::from_utf8(&data[pos..pos + name_len])
            .map_err(|_| CryptoError::ExportFailed("invalid UTF-8 segment name".into()))?
            .to_string();
        pos += name_len;

        let compression = data[pos];
        pos += 1;

        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        let data_len = u64::from_le_bytes(
            data[pos..pos + 8]
                .try_into()
                .map_err(|_| CryptoError::ExportFailed("truncated data_len field".into()))?,
        );
        pos += 8;

        Ok((name, compression, checksum, data_len, pos))
    }
}

// ---------------------------------------------------------------------------
// ArchiveTrailer (36 bytes)
// ---------------------------------------------------------------------------

/// Trailer at the end of every `.mvex` archive.
///
/// ```text
/// [0..32]  BLAKE3 hash of everything before the trailer
/// [32..36] reverse magic "XEVM"
/// ```
pub struct ArchiveTrailer {
    pub checksum: [u8; 32],
}

impl ArchiveTrailer {
    pub fn to_bytes(&self) -> [u8; ARCHIVE_TRAILER_SIZE] {
        let mut buf = [0u8; ARCHIVE_TRAILER_SIZE];
        buf[0..32].copy_from_slice(&self.checksum);
        buf[32..36].copy_from_slice(REVERSE_MAGIC);
        buf
    }

    pub fn from_bytes(buf: &[u8; ARCHIVE_TRAILER_SIZE]) -> Result<Self, CryptoError> {
        if &buf[32..36] != REVERSE_MAGIC {
            return Err(CryptoError::ExportFailed(
                "invalid archive trailer magic".into(),
            ));
        }
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&buf[0..32]);
        Ok(Self { checksum })
    }
}
