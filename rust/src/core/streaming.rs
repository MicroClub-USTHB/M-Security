//! Low-level streaming primitives for chunk-based encryption.
//!
//! Defines the on-disk format: a 16-byte header followed by uniformly-sized
//! encrypted chunks. The header intentionally omits chunk count to prevent
//! metadata leakage, and the last chunk is padded to uniform size.

use std::io::{Read, Write};

use crate::core::error::CryptoError;
use crate::core::format::Algorithm;

// -- Constants ----------------------------------------------------------------

/// Plaintext chunk size (64 KiB).
pub const CHUNK_SIZE: usize = 64 * 1024;

/// AEAD nonce size (12 bytes for AES-GCM / ChaCha20-Poly1305).
pub const NONCE_SIZE: usize = 12;

/// AEAD authentication tag size (16 bytes).
pub const TAG_SIZE: usize = 16;

/// Every encrypted chunk on disk is exactly this size — no size leakage.
pub const ENCRYPTED_CHUNK_SIZE: usize = NONCE_SIZE + CHUNK_SIZE + TAG_SIZE;

/// Stream header magic bytes.
pub const STREAM_MAGIC: &[u8; 4] = b"MSSE";

/// Stream format version.
pub const STREAM_VERSION: u16 = 1;

/// Stream header size in bytes.
pub const STREAM_HEADER_SIZE: usize = 16;

/// Per-chunk AAD size: index (8 bytes) + is_final (1 byte).
pub const AAD_SIZE: usize = 9;

/// Length prefix size for last-chunk padding.
const PADDING_PREFIX_SIZE: usize = 4;

// -- Algorithm ID (stream-specific) -------------------------------------------

/// Algorithm identifiers stored in the stream header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum StreamAlgorithm {
    AesGcm = 0x0001,
    ChaCha20Poly1305 = 0x0002,
}

impl StreamAlgorithm {
    pub fn from_u16(v: u16) -> Result<Self, CryptoError> {
        match v {
            0x0001 => Ok(Self::AesGcm),
            0x0002 => Ok(Self::ChaCha20Poly1305),
            _ => Err(CryptoError::InvalidParameter(format!(
                "Unknown stream algorithm: 0x{v:04X}"
            ))),
        }
    }

    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

impl From<StreamAlgorithm> for Algorithm {
    fn from(sa: StreamAlgorithm) -> Self {
        match sa {
            StreamAlgorithm::AesGcm => Algorithm::AesGcm,
            StreamAlgorithm::ChaCha20Poly1305 => Algorithm::ChaCha20Poly1305,
        }
    }
}

impl TryFrom<Algorithm> for StreamAlgorithm {
    type Error = CryptoError;

    fn try_from(a: Algorithm) -> Result<Self, Self::Error> {
        match a {
            Algorithm::AesGcm => Ok(StreamAlgorithm::AesGcm),
            Algorithm::ChaCha20Poly1305 => Ok(StreamAlgorithm::ChaCha20Poly1305),
            _ => Err(CryptoError::InvalidParameter(format!(
                "Algorithm {a:?} not supported for streaming"
            ))),
        }
    }
}

// -- StreamHeader -------------------------------------------------------------

/// 16-byte header at the start of every encrypted stream.
///
/// Chunk count is intentionally NOT stored — an observer must not learn
/// the file size from unencrypted metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamHeader {
    pub version: u16,
    pub algorithm: StreamAlgorithm,
    // 8 reserved bytes (zeroed) — replaces chunk_count
}

impl StreamHeader {
    pub fn new(algorithm: StreamAlgorithm) -> Self {
        Self {
            version: STREAM_VERSION,
            algorithm,
        }
    }

    pub fn to_bytes(&self) -> [u8; STREAM_HEADER_SIZE] {
        let mut buf = [0u8; STREAM_HEADER_SIZE];
        buf[0..4].copy_from_slice(STREAM_MAGIC);
        buf[4..6].copy_from_slice(&self.version.to_le_bytes());
        buf[6..8].copy_from_slice(&self.algorithm.to_u16().to_le_bytes());
        // bytes 8..16 stay zeroed (reserved)
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() < STREAM_HEADER_SIZE {
            return Err(CryptoError::InvalidParameter(format!(
                "Stream header too short: {} bytes, need {STREAM_HEADER_SIZE}",
                data.len()
            )));
        }

        if &data[0..4] != STREAM_MAGIC {
            return Err(CryptoError::InvalidParameter(
                "Invalid stream magic bytes".to_string(),
            ));
        }

        let version = u16::from_le_bytes([data[4], data[5]]);
        if version != STREAM_VERSION {
            return Err(CryptoError::InvalidParameter(format!(
                "Unsupported stream version: {version}"
            )));
        }

        let algorithm = StreamAlgorithm::from_u16(u16::from_le_bytes([data[6], data[7]]))?;

        Ok(Self { version, algorithm })
    }
}

// -- ChunkAad -----------------------------------------------------------------

/// Per-chunk authenticated additional data.
///
/// Prevents reordering, duplication, truncation, and appending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkAad {
    pub index: u64,
    pub is_final: bool,
}

impl ChunkAad {
    pub fn to_bytes(self) -> [u8; AAD_SIZE] {
        let mut buf = [0u8; AAD_SIZE];
        buf[0..8].copy_from_slice(&self.index.to_le_bytes());
        buf[8] = u8::from(self.is_final);
        buf
    }

    pub fn from_bytes(bytes: &[u8; AAD_SIZE]) -> Self {
        let index = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let is_final = bytes[8] != 0;
        Self { index, is_final }
    }
}

// -- EncryptedChunk -----------------------------------------------------------

/// A single encrypted chunk as it appears on disk.
///
/// Use `EncryptedChunk::new()` to pre-allocate, then reuse across reads
/// to avoid per-chunk heap allocation in hot loops.
pub struct EncryptedChunk {
    pub nonce: [u8; NONCE_SIZE],
    pub ciphertext: Vec<u8>, // always CHUNK_SIZE bytes
    pub tag: [u8; TAG_SIZE],
}

impl EncryptedChunk {
    /// Pre-allocate a reusable chunk buffer.
    pub fn new() -> Self {
        Self {
            nonce: [0u8; NONCE_SIZE],
            ciphertext: vec![0u8; CHUNK_SIZE],
            tag: [0u8; TAG_SIZE],
        }
    }
}

impl Default for EncryptedChunk {
    fn default() -> Self {
        Self::new()
    }
}

// -- Last-chunk padding -------------------------------------------------------

/// Pad the last chunk's plaintext to exactly `CHUNK_SIZE`.
///
/// Layout: `[real_len: u32 LE (4B)] [real_data] [zero padding]`
pub fn pad_last_chunk(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let real_len = data.len();
    let max_payload = CHUNK_SIZE - PADDING_PREFIX_SIZE;

    if real_len > max_payload {
        return Err(CryptoError::InvalidParameter(format!(
            "Last chunk payload too large: {real_len} bytes, max {max_payload}"
        )));
    }

    let mut buf = vec![0u8; CHUNK_SIZE];
    buf[0..4].copy_from_slice(&(real_len as u32).to_le_bytes());
    buf[4..4 + real_len].copy_from_slice(data);
    // remaining bytes stay zeroed
    Ok(buf)
}

/// Strip padding from a decrypted last chunk, returning only the real data.
///
/// Validates that the length prefix is in range and that all padding
/// bytes beyond the real data are zero (rejects tampered padding).
pub fn strip_last_chunk_padding(padded: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if padded.len() != CHUNK_SIZE {
        return Err(CryptoError::InvalidParameter(format!(
            "Padded chunk wrong size: {} bytes, expected {CHUNK_SIZE}",
            padded.len()
        )));
    }

    let real_len = u32::from_le_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
    let max_payload = CHUNK_SIZE - PADDING_PREFIX_SIZE;

    if real_len > max_payload {
        return Err(CryptoError::InvalidParameter(format!(
            "Invalid padding length: {real_len}, max {max_payload}"
        )));
    }

    // Reject non-zero bytes in padding region
    let padding_start = PADDING_PREFIX_SIZE + real_len;
    if !padded[padding_start..].iter().all(|&b| b == 0) {
        return Err(CryptoError::InvalidParameter(
            "Non-zero bytes in padding region".to_string(),
        ));
    }

    Ok(padded[PADDING_PREFIX_SIZE..PADDING_PREFIX_SIZE + real_len].to_vec())
}

// -- ChunkReader --------------------------------------------------------------

/// Reads encrypted chunks sequentially from a stream.
///
/// Uses an internal buffer for atomic reads (one I/O call per chunk).
/// Caller provides a reusable `EncryptedChunk` via `read_chunk()` to
/// avoid per-chunk heap allocation.
pub struct ChunkReader<R: Read> {
    reader: R,
    buf: Vec<u8>,
}

impl<R: Read> ChunkReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            buf: vec![0u8; ENCRYPTED_CHUNK_SIZE],
        }
    }

    /// Read and parse the 16-byte stream header.
    pub fn read_header(&mut self) -> Result<StreamHeader, CryptoError> {
        let mut header_buf = [0u8; STREAM_HEADER_SIZE];
        self.reader
            .read_exact(&mut header_buf)
            .map_err(|e| CryptoError::IoError(format!("Failed to read stream header: {e}")))?;
        StreamHeader::from_bytes(&header_buf)
    }

    /// Read the next encrypted chunk into `chunk`. Returns `true` if a
    /// chunk was read, `false` at clean EOF.
    ///
    /// Reuse the same `EncryptedChunk` across iterations — zero heap
    /// allocation in the hot loop.
    pub fn read_chunk(&mut self, chunk: &mut EncryptedChunk) -> Result<bool, CryptoError> {
        match read_exact_or_eof(&mut self.reader, &mut self.buf) {
            Ok(true) => {}
            Ok(false) => return Ok(false),
            Err(e) => return Err(CryptoError::IoError(format!("Failed to read chunk: {e}"))),
        }

        chunk.nonce.copy_from_slice(&self.buf[..NONCE_SIZE]);
        chunk.ciphertext[..CHUNK_SIZE]
            .copy_from_slice(&self.buf[NONCE_SIZE..NONCE_SIZE + CHUNK_SIZE]);
        chunk
            .tag
            .copy_from_slice(&self.buf[NONCE_SIZE + CHUNK_SIZE..]);

        Ok(true)
    }

    /// Consume the reader and return the underlying stream.
    pub fn into_inner(self) -> R {
        self.reader
    }
}

/// Read exactly `buf.len()` bytes, or detect clean EOF (0 bytes read).
/// Returns `Ok(true)` on full read, `Ok(false)` on clean EOF.
/// Returns `Err` on partial read (corrupt/truncated stream).
fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<bool, std::io::Error> {
    let mut offset = 0;
    loop {
        match reader.read(&mut buf[offset..]) {
            Ok(0) => {
                if offset == 0 {
                    return Ok(false); // clean EOF
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!(
                        "Truncated chunk: read {offset} of {} bytes",
                        buf.len()
                    ),
                ));
            }
            Ok(n) => {
                offset += n;
                if offset == buf.len() {
                    return Ok(true);
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

// -- ChunkWriter --------------------------------------------------------------

/// Writes encrypted chunks sequentially to a stream.
///
/// Uses an internal buffer to batch nonce+ciphertext+tag into a single
/// `write_all` call, reducing syscall overhead.
pub struct ChunkWriter<W: Write> {
    writer: W,
    buf: Vec<u8>,
}

impl<W: Write> ChunkWriter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            buf: vec![0u8; ENCRYPTED_CHUNK_SIZE],
        }
    }

    /// Write the 16-byte stream header.
    pub fn write_header(&mut self, header: &StreamHeader) -> Result<(), CryptoError> {
        self.writer.write_all(&header.to_bytes()).map_err(|e| {
            CryptoError::IoError(format!("Failed to write stream header: {e}"))
        })
    }

    /// Write one encrypted chunk in a single I/O call.
    ///
    /// Caller must ensure ciphertext is exactly `CHUNK_SIZE` bytes.
    pub fn write_chunk(&mut self, chunk: &EncryptedChunk) -> Result<(), CryptoError> {
        if chunk.ciphertext.len() != CHUNK_SIZE {
            return Err(CryptoError::InvalidParameter(format!(
                "Chunk ciphertext must be {CHUNK_SIZE} bytes, got {}",
                chunk.ciphertext.len()
            )));
        }

        self.buf[..NONCE_SIZE].copy_from_slice(&chunk.nonce);
        self.buf[NONCE_SIZE..NONCE_SIZE + CHUNK_SIZE].copy_from_slice(&chunk.ciphertext);
        self.buf[NONCE_SIZE + CHUNK_SIZE..].copy_from_slice(&chunk.tag);

        self.writer
            .write_all(&self.buf)
            .map_err(|e| CryptoError::IoError(format!("Failed to write chunk: {e}")))
    }

    /// Flush and return the underlying writer.
    pub fn finish(mut self) -> Result<W, CryptoError> {
        self.writer
            .flush()
            .map_err(|e| CryptoError::IoError(format!("Failed to flush: {e}")))?;
        Ok(self.writer)
    }
}

/// Flush, fsync, and consume a file-backed writer to guarantee durability.
pub fn finish_file(
    writer: ChunkWriter<std::io::BufWriter<std::fs::File>>,
) -> Result<(), CryptoError> {
    let buf_writer = writer.finish()?;
    buf_writer
        .get_ref()
        .sync_all()
        .map_err(|e| CryptoError::IoError(format!("Failed to fsync: {e}")))
}

/// Compute the byte offset of chunk `k` within the stream (after the header).
pub fn chunk_offset(k: u64) -> u64 {
    STREAM_HEADER_SIZE as u64 + k * ENCRYPTED_CHUNK_SIZE as u64
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_header_roundtrip() {
        let header = StreamHeader::new(StreamAlgorithm::AesGcm);
        let bytes = header.to_bytes();

        assert_eq!(bytes.len(), STREAM_HEADER_SIZE);
        assert_eq!(&bytes[0..4], b"MSSE");
        // reserved bytes are zeroed
        assert!(bytes[8..16].iter().all(|&b| b == 0));

        let parsed = StreamHeader::from_bytes(&bytes).expect("parse failed");
        assert_eq!(header, parsed);

        // Also test ChaCha20 variant
        let header2 = StreamHeader::new(StreamAlgorithm::ChaCha20Poly1305);
        let bytes2 = header2.to_bytes();
        let parsed2 = StreamHeader::from_bytes(&bytes2).expect("parse failed");
        assert_eq!(header2, parsed2);
    }

    #[test]
    fn test_single_chunk_roundtrip() {
        let mut output = Vec::new();

        {
            let mut writer = ChunkWriter::new(&mut output);
            let header = StreamHeader::new(StreamAlgorithm::AesGcm);
            writer.write_header(&header).expect("write header");

            let chunk = EncryptedChunk {
                nonce: [0xAA; NONCE_SIZE],
                ciphertext: vec![0xBB; CHUNK_SIZE],
                tag: [0xCC; TAG_SIZE],
            };
            writer.write_chunk(&chunk).expect("write chunk");
        }

        assert_eq!(output.len(), STREAM_HEADER_SIZE + ENCRYPTED_CHUNK_SIZE);

        let mut reader = ChunkReader::new(Cursor::new(&output));
        let header = reader.read_header().expect("read header");
        assert_eq!(header.algorithm, StreamAlgorithm::AesGcm);

        let mut chunk = EncryptedChunk::new();
        assert!(reader.read_chunk(&mut chunk).expect("read chunk"));
        assert_eq!(chunk.nonce, [0xAA; NONCE_SIZE]);
        assert_eq!(chunk.ciphertext.len(), CHUNK_SIZE);
        assert!(chunk.ciphertext.iter().all(|&b| b == 0xBB));
        assert_eq!(chunk.tag, [0xCC; TAG_SIZE]);

        assert!(!reader.read_chunk(&mut chunk).expect("eof"));
    }

    #[test]
    fn test_multi_chunk_roundtrip() {
        let num_chunks = 5;
        let mut output = Vec::new();

        {
            let mut writer = ChunkWriter::new(&mut output);
            writer
                .write_header(&StreamHeader::new(StreamAlgorithm::ChaCha20Poly1305))
                .expect("write header");

            for i in 0..num_chunks {
                let chunk = EncryptedChunk {
                    nonce: [i as u8; NONCE_SIZE],
                    ciphertext: vec![i as u8 + 0x10; CHUNK_SIZE],
                    tag: [i as u8 + 0x20; TAG_SIZE],
                };
                writer.write_chunk(&chunk).expect("write chunk");
            }
        }

        let expected_size = STREAM_HEADER_SIZE + num_chunks * ENCRYPTED_CHUNK_SIZE;
        assert_eq!(output.len(), expected_size);

        let mut reader = ChunkReader::new(Cursor::new(&output));
        let header = reader.read_header().expect("read header");
        assert_eq!(header.algorithm, StreamAlgorithm::ChaCha20Poly1305);

        // Reuse one chunk across all reads — zero allocation in hot loop
        let mut chunk = EncryptedChunk::new();
        for i in 0..num_chunks {
            assert!(reader.read_chunk(&mut chunk).expect("read chunk"));
            assert_eq!(chunk.nonce, [i as u8; NONCE_SIZE]);
            assert!(chunk.ciphertext.iter().all(|&b| b == i as u8 + 0x10));
            assert_eq!(chunk.tag, [i as u8 + 0x20; TAG_SIZE]);
        }

        assert!(!reader.read_chunk(&mut chunk).expect("eof"));
    }

    #[test]
    fn test_bad_magic_rejected() {
        let mut bytes = StreamHeader::new(StreamAlgorithm::AesGcm).to_bytes();
        bytes[0] = b'X';
        let result = StreamHeader::from_bytes(&bytes);
        assert!(result.is_err());
        let err = result.expect_err("should fail").to_string();
        assert!(err.contains("magic"), "Error should mention magic: {err}");
    }

    #[test]
    fn test_chunk_offset_calculation() {
        for k in 0..6u64 {
            let expected = STREAM_HEADER_SIZE as u64 + k * ENCRYPTED_CHUNK_SIZE as u64;
            assert_eq!(chunk_offset(k), expected, "offset mismatch for chunk {k}");
        }
    }

    #[test]
    fn test_aad_serialization() {
        let aad = ChunkAad {
            index: 42,
            is_final: true,
        };
        let bytes = aad.to_bytes();
        assert_eq!(bytes.len(), AAD_SIZE);

        // index = 42 in LE
        let mut expected_index = [0u8; 8];
        expected_index[0] = 42;
        assert_eq!(&bytes[0..8], &expected_index);
        // is_final = true
        assert_eq!(bytes[8], 1);

        let roundtrip = ChunkAad::from_bytes(&bytes);
        assert_eq!(roundtrip, aad);

        // Also test is_final = false
        let aad2 = ChunkAad {
            index: 0,
            is_final: false,
        };
        let bytes2 = aad2.to_bytes();
        assert_eq!(bytes2[8], 0);
        assert_eq!(ChunkAad::from_bytes(&bytes2), aad2);
    }

    #[test]
    fn test_all_chunks_uniform_size() {
        let mut output = Vec::new();

        {
            let mut writer = ChunkWriter::new(&mut output);
            writer
                .write_header(&StreamHeader::new(StreamAlgorithm::AesGcm))
                .expect("write header");

            // Simulate 3 chunks — last one would be "short" in plaintext,
            // but after padding the encrypted output is uniform.
            for _ in 0..3 {
                let chunk = EncryptedChunk {
                    nonce: [0u8; NONCE_SIZE],
                    ciphertext: vec![0u8; CHUNK_SIZE],
                    tag: [0u8; TAG_SIZE],
                };
                writer.write_chunk(&chunk).expect("write chunk");
            }
        }

        // Verify total size matches uniform chunk expectation
        let data_portion = output.len() - STREAM_HEADER_SIZE;
        assert_eq!(data_portion % ENCRYPTED_CHUNK_SIZE, 0);
        assert_eq!(data_portion / ENCRYPTED_CHUNK_SIZE, 3);
    }

    #[test]
    fn test_last_chunk_padding_strip() {
        let real_data = vec![0x42u8; 100];
        let padded = pad_last_chunk(&real_data).expect("pad");

        assert_eq!(padded.len(), CHUNK_SIZE);

        // Length prefix
        let stored_len =
            u32::from_le_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
        assert_eq!(stored_len, 100);

        // Real data follows prefix
        assert_eq!(&padded[4..104], &real_data);

        // Padding is zeroes
        assert!(padded[104..].iter().all(|&b| b == 0));

        // Round-trip via strip
        let stripped = strip_last_chunk_padding(&padded).expect("strip");
        assert_eq!(stripped, real_data);
    }

    #[test]
    fn test_padding_empty_payload() {
        let padded = pad_last_chunk(&[]).expect("pad empty");
        assert_eq!(padded.len(), CHUNK_SIZE);
        let stripped = strip_last_chunk_padding(&padded).expect("strip");
        assert!(stripped.is_empty());
    }

    #[test]
    fn test_padding_max_payload() {
        let max = CHUNK_SIZE - PADDING_PREFIX_SIZE;
        let data = vec![0xFF; max];
        let padded = pad_last_chunk(&data).expect("pad max");
        assert_eq!(padded.len(), CHUNK_SIZE);
        let stripped = strip_last_chunk_padding(&padded).expect("strip");
        assert_eq!(stripped.len(), max);
    }

    #[test]
    fn test_padding_overflow_rejected() {
        let too_big = vec![0u8; CHUNK_SIZE]; // exceeds max payload
        assert!(pad_last_chunk(&too_big).is_err());
    }

    #[test]
    fn test_write_chunk_rejects_wrong_size() {
        let mut output = Vec::new();
        let mut writer = ChunkWriter::new(&mut output);

        let bad_chunk = EncryptedChunk {
            nonce: [0u8; NONCE_SIZE],
            ciphertext: vec![0u8; 100], // wrong size
            tag: [0u8; TAG_SIZE],
        };

        let result = writer.write_chunk(&bad_chunk);
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_stream_detected() {
        let mut output = Vec::new();
        {
            let mut writer = ChunkWriter::new(&mut output);
            writer
                .write_header(&StreamHeader::new(StreamAlgorithm::AesGcm))
                .expect("write header");

            let chunk = EncryptedChunk {
                nonce: [0u8; NONCE_SIZE],
                ciphertext: vec![0u8; CHUNK_SIZE],
                tag: [0u8; TAG_SIZE],
            };
            writer.write_chunk(&chunk).expect("write chunk");
        }

        // Truncate mid-chunk
        output.truncate(STREAM_HEADER_SIZE + 100);

        let mut reader = ChunkReader::new(Cursor::new(&output));
        reader.read_header().expect("header ok");
        let mut chunk = EncryptedChunk::new();
        assert!(
            reader.read_chunk(&mut chunk).is_err(),
            "Should detect truncated chunk"
        );
    }

    #[test]
    fn test_header_too_short_rejected() {
        let result = StreamHeader::from_bytes(&[0u8; 4]);
        assert!(result.is_err());
    }

    #[test]
    fn test_unsupported_version_rejected() {
        let mut bytes = StreamHeader::new(StreamAlgorithm::AesGcm).to_bytes();
        bytes[4] = 0xFF; // bad version (LE low byte)
        bytes[5] = 0x00;
        let result = StreamHeader::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_algorithm_rejected() {
        let result = StreamAlgorithm::from_u16(0xFFFF);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_padding_rejected() {
        let real_data = vec![0x42u8; 100];
        let mut padded = pad_last_chunk(&real_data).expect("pad");

        // Inject non-zero byte in the padding region
        padded[CHUNK_SIZE - 1] = 0xFF;

        let result = strip_last_chunk_padding(&padded);
        assert!(result.is_err());
        let err = result.expect_err("should fail").to_string();
        assert!(
            err.contains("padding"),
            "Error should mention padding: {err}"
        );
    }

    #[test]
    fn test_algorithm_conversion_roundtrip() {
        let algo: Algorithm = StreamAlgorithm::AesGcm.into();
        assert_eq!(algo, Algorithm::AesGcm);

        let algo: Algorithm = StreamAlgorithm::ChaCha20Poly1305.into();
        assert_eq!(algo, Algorithm::ChaCha20Poly1305);

        let sa: StreamAlgorithm = Algorithm::AesGcm.try_into().expect("aes");
        assert_eq!(sa, StreamAlgorithm::AesGcm);

        let sa: StreamAlgorithm = Algorithm::ChaCha20Poly1305.try_into().expect("chacha");
        assert_eq!(sa, StreamAlgorithm::ChaCha20Poly1305);

        // XChaCha20 not supported for streaming yet
        let result: Result<StreamAlgorithm, _> = Algorithm::XChaCha20Poly1305.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_writer_finish_returns_inner() {
        let output = Vec::new();
        let mut writer = ChunkWriter::new(output);
        writer
            .write_header(&StreamHeader::new(StreamAlgorithm::AesGcm))
            .expect("write header");

        let recovered = writer.finish().expect("finish");
        assert_eq!(recovered.len(), STREAM_HEADER_SIZE);
    }

    #[test]
    fn test_reader_into_inner() {
        let data = StreamHeader::new(StreamAlgorithm::AesGcm).to_bytes();
        let cursor = Cursor::new(data.to_vec());
        let mut reader = ChunkReader::new(cursor);
        reader.read_header().expect("read header");

        let inner = reader.into_inner();
        assert_eq!(inner.position(), STREAM_HEADER_SIZE as u64);
    }

    #[test]
    fn test_encrypted_chunk_default() {
        let chunk = EncryptedChunk::default();
        assert_eq!(chunk.nonce, [0u8; NONCE_SIZE]);
        assert_eq!(chunk.ciphertext.len(), CHUNK_SIZE);
        assert_eq!(chunk.tag, [0u8; TAG_SIZE]);
    }

    #[test]
    fn test_chunk_reuse_overwrites_previous() {
        let mut output = Vec::new();
        {
            let mut writer = ChunkWriter::new(&mut output);
            writer
                .write_header(&StreamHeader::new(StreamAlgorithm::AesGcm))
                .expect("header");

            for i in 0u8..3 {
                let chunk = EncryptedChunk {
                    nonce: [i + 1; NONCE_SIZE],
                    ciphertext: vec![i + 0x10; CHUNK_SIZE],
                    tag: [i + 0x20; TAG_SIZE],
                };
                writer.write_chunk(&chunk).expect("write");
            }
        }

        let mut reader = ChunkReader::new(Cursor::new(&output));
        reader.read_header().expect("header");

        let mut chunk = EncryptedChunk::new();

        assert!(reader.read_chunk(&mut chunk).expect("c0"));
        assert_eq!(chunk.nonce[0], 1);
        assert_eq!(chunk.ciphertext[0], 0x10);

        // Second read overwrites first chunk's data
        assert!(reader.read_chunk(&mut chunk).expect("c1"));
        assert_eq!(chunk.nonce[0], 2);
        assert_eq!(chunk.ciphertext[0], 0x11);

        assert!(reader.read_chunk(&mut chunk).expect("c2"));
        assert_eq!(chunk.nonce[0], 3);
        assert_eq!(chunk.ciphertext[0], 0x12);

        assert!(!reader.read_chunk(&mut chunk).expect("eof"));
    }
}
