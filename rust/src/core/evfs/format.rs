//! On-disk `.vault` format: header, segment index, free-region list, layout constants.

use crate::api::compression::CompressionAlgorithm;
use crate::core::error::CryptoError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const VAULT_MAGIC: &[u8; 4] = b"MVLT";
pub const VAULT_VERSION: u8 = 1;
pub const VAULT_HEADER_SIZE: usize = 32;

/// Max segment name length in bytes (UTF-8).
pub const MAX_SEGMENT_NAME_LEN: usize = 255;

/// Index is always serialized to this size (zero-padded).
/// 64KB supports approximately 200 segments + free regions.
pub const INDEX_PAD_SIZE: usize = 64 * 1024;

/// Encrypted index size on disk: padded plaintext + AEAD nonce (12) + tag (16).
pub const ENCRYPTED_INDEX_SIZE: usize = INDEX_PAD_SIZE + 12 + 16;

/// Vault file layout offsets.
pub const PRIMARY_INDEX_OFFSET: u64 = VAULT_HEADER_SIZE as u64;
pub const DATA_REGION_OFFSET: u64 = PRIMARY_INDEX_OFFSET + ENCRYPTED_INDEX_SIZE as u64;

/// Shadow index offset depends on vault capacity.
pub fn shadow_index_offset(capacity: u64) -> Result<u64, CryptoError> {
    DATA_REGION_OFFSET
        .checked_add(capacity)
        .ok_or_else(|| CryptoError::InvalidParameter("vault capacity overflows layout".into()))
}

/// WAL region starts after the shadow index.
pub fn wal_region_offset(capacity: u64) -> Result<u64, CryptoError> {
    shadow_index_offset(capacity)?
        .checked_add(ENCRYPTED_INDEX_SIZE as u64)
        .ok_or_else(|| CryptoError::InvalidParameter("vault capacity overflows layout".into()))
}

/// Total vault file size: header + 2 encrypted indices + data capacity.
pub fn total_vault_size(capacity: u64) -> Result<u64, CryptoError> {
    let base = VAULT_HEADER_SIZE as u64 + 2 * ENCRYPTED_INDEX_SIZE as u64;
    base.checked_add(capacity)
        .ok_or_else(|| CryptoError::InvalidParameter("vault size overflows".into()))
}

// ---------------------------------------------------------------------------
// VaultHeader
// ---------------------------------------------------------------------------

/// On-disk vault header (32 bytes).
///
/// Layout: `[MAGIC(4)] [VERSION(1)] [ALGORITHM(1)] [FLAGS(2)] [RESERVED(24)]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultHeader {
    pub version: u8,
    /// AEAD algorithm ID (reuses `core::format::Algorithm` byte values).
    pub algorithm: u8,
    pub flags: u16,
}

impl VaultHeader {
    pub fn new(algorithm: u8) -> Self {
        Self {
            version: VAULT_VERSION,
            algorithm,
            flags: 0,
        }
    }

    pub fn to_bytes(&self) -> [u8; VAULT_HEADER_SIZE] {
        let mut buf = [0u8; VAULT_HEADER_SIZE];
        buf[0..4].copy_from_slice(VAULT_MAGIC);
        buf[4] = self.version;
        buf[5] = self.algorithm;
        buf[6..8].copy_from_slice(&self.flags.to_le_bytes());
        // bytes 8..32 reserved (zeros)
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() < VAULT_HEADER_SIZE {
            return Err(CryptoError::VaultCorrupted(format!(
                "header too short: {} bytes, need {VAULT_HEADER_SIZE}",
                data.len()
            )));
        }
        if &data[0..4] != VAULT_MAGIC {
            return Err(CryptoError::VaultCorrupted(
                "invalid magic bytes".to_string(),
            ));
        }
        let version = data[4];
        if version != VAULT_VERSION {
            return Err(CryptoError::VaultCorrupted(format!(
                "unsupported vault version: {version}"
            )));
        }
        let algorithm = data[5];
        let flags = u16::from_le_bytes([data[6], data[7]]);
        Ok(Self {
            version,
            algorithm,
            flags,
        })
    }
}

// ---------------------------------------------------------------------------
// FreeRegion
// ---------------------------------------------------------------------------

/// A free region in the data area available for reuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreeRegion {
    /// Byte offset relative to data region start.
    pub offset: u64,
    pub size: u64,
}

// ---------------------------------------------------------------------------
// SegmentEntry
// ---------------------------------------------------------------------------

/// Segment index entry — one per stored segment.
#[derive(Debug, Clone)]
pub struct SegmentEntry {
    /// Segment name (1–255 bytes UTF-8).
    pub name: String,
    /// Byte offset in vault data region.
    pub offset: u64,
    /// Encrypted segment size (nonce + ciphertext + tag).
    pub size: u64,
    /// Write generation (increments on overwrite).
    pub generation: u64,
    /// BLAKE3 hash of original plaintext (pre-compression).
    pub checksum: [u8; 32],
    /// Algorithm used to compress this segment.
    pub compression: CompressionAlgorithm,
}

impl SegmentEntry {
    pub fn new(
        name: &str,
        offset: u64,
        size: u64,
        generation: u64,
        checksum: [u8; 32],
        compression: CompressionAlgorithm,
    ) -> Result<Self, CryptoError> {
        if name.is_empty() || name.len() > MAX_SEGMENT_NAME_LEN {
            return Err(CryptoError::InvalidParameter(format!(
                "segment name must be 1\u{2013}{MAX_SEGMENT_NAME_LEN} bytes, got {}",
                name.len()
            )));
        }
        Ok(Self {
            name: name.to_string(),
            offset,
            size,
            generation,
            checksum,
            compression,
        })
    }
}

// ---------------------------------------------------------------------------
// SegmentIndex
// ---------------------------------------------------------------------------

/// Encrypted segment index — stored encrypted after the header.
///
/// Tracks live segments, freed regions for space reclamation, and the
/// append cursor (`next_free_offset`) for when no free region fits.
#[derive(Debug, Clone)]
pub struct SegmentIndex {
    pub entries: Vec<SegmentEntry>,
    /// Sorted by offset, adjacent regions merged.
    pub free_regions: Vec<FreeRegion>,
    /// Append cursor (relative to data region start).
    pub next_free_offset: u64,
    /// Total data region size in bytes.
    pub capacity: u64,
    /// Global generation counter.
    pub next_generation: u64,
}

// -- helpers for little-endian I/O ------------------------------------------

fn put_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn put_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn read_u16(data: &[u8], off: &mut usize) -> Result<u16, CryptoError> {
    let end = *off + 2;
    if end > data.len() {
        return Err(CryptoError::VaultCorrupted("index truncated (u16)".into()));
    }
    let v = u16::from_le_bytes([data[*off], data[*off + 1]]);
    *off = end;
    Ok(v)
}

fn read_u32(data: &[u8], off: &mut usize) -> Result<u32, CryptoError> {
    let end = *off + 4;
    if end > data.len() {
        return Err(CryptoError::VaultCorrupted("index truncated (u32)".into()));
    }
    let v = u32::from_le_bytes([data[*off], data[*off + 1], data[*off + 2], data[*off + 3]]);
    *off = end;
    Ok(v)
}

fn read_u64(data: &[u8], off: &mut usize) -> Result<u64, CryptoError> {
    let end = *off + 8;
    if end > data.len() {
        return Err(CryptoError::VaultCorrupted("index truncated (u64)".into()));
    }
    let v = u64::from_le_bytes([
        data[*off],
        data[*off + 1],
        data[*off + 2],
        data[*off + 3],
        data[*off + 4],
        data[*off + 5],
        data[*off + 6],
        data[*off + 7],
    ]);
    *off = end;
    Ok(v)
}

fn read_bytes(data: &[u8], off: &mut usize, len: usize) -> Result<Vec<u8>, CryptoError> {
    let end = *off + len;
    if end > data.len() {
        return Err(CryptoError::VaultCorrupted(
            "index truncated (bytes)".into(),
        ));
    }
    let v = data[*off..end].to_vec();
    *off = end;
    Ok(v)
}

impl SegmentIndex {
    /// Create an empty index for a new vault.
    pub fn new(capacity: u64) -> Self {
        Self {
            entries: Vec::new(),
            free_regions: Vec::new(),
            next_free_offset: 0,
            capacity,
            next_generation: 0,
        }
    }

    /// Serialize index to bytes, padded to `INDEX_PAD_SIZE`.
    ///
    /// Wire format:
    /// ```text
    ///   [entry_count: u32]
    ///   [free_region_count: u32]
    ///   [next_free_offset: u64]
    ///   [capacity: u64]
    ///   [next_generation: u64]
    ///   -- entries --
    ///   per entry:
    ///     [name_len: u16] [name: UTF-8] [offset: u64] [size: u64]
    ///     [generation: u64] [checksum: 32B] [compression: u8]
    ///   -- free regions --
    ///   per region:
    ///     [offset: u64] [size: u64]
    ///   -- zero padding to INDEX_PAD_SIZE --
    /// ```
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        let mut buf = Vec::with_capacity(INDEX_PAD_SIZE);

        let entry_count = u32::try_from(self.entries.len())
            .map_err(|_| CryptoError::VaultCorrupted("too many segment entries".into()))?;
        let free_count = u32::try_from(self.free_regions.len())
            .map_err(|_| CryptoError::VaultCorrupted("too many free regions".into()))?;

        put_u32(&mut buf, entry_count);
        put_u32(&mut buf, free_count);
        put_u64(&mut buf, self.next_free_offset);
        put_u64(&mut buf, self.capacity);
        put_u64(&mut buf, self.next_generation);

        for entry in &self.entries {
            let name_bytes = entry.name.as_bytes();
            let name_len = u16::try_from(name_bytes.len()).map_err(|_| {
                CryptoError::InvalidParameter("segment name too long for u16".into())
            })?;
            put_u16(&mut buf, name_len);
            buf.extend_from_slice(name_bytes);
            put_u64(&mut buf, entry.offset);
            put_u64(&mut buf, entry.size);
            put_u64(&mut buf, entry.generation);
            buf.extend_from_slice(&entry.checksum);
            buf.push(entry.compression.to_u8());
        }

        for region in &self.free_regions {
            put_u64(&mut buf, region.offset);
            put_u64(&mut buf, region.size);
        }

        if buf.len() > INDEX_PAD_SIZE {
            return Err(CryptoError::VaultCorrupted(format!(
                "index content ({} bytes) exceeds INDEX_PAD_SIZE ({INDEX_PAD_SIZE})",
                buf.len()
            )));
        }

        buf.resize(INDEX_PAD_SIZE, 0);
        Ok(buf)
    }

    /// Deserialize index from decrypted bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() < 32 {
            return Err(CryptoError::VaultCorrupted("index too short".into()));
        }

        let mut off = 0;
        let entry_count = read_u32(data, &mut off)? as usize;
        let free_count = read_u32(data, &mut off)? as usize;

        // Sanity-cap: the smallest possible entry is ~59 bytes (1-byte name),
        // free region is 16 bytes. Reject clearly corrupted counts early.
        let max_entries = INDEX_PAD_SIZE / 59;
        let max_free = INDEX_PAD_SIZE / 16;
        if entry_count > max_entries {
            return Err(CryptoError::VaultCorrupted(format!(
                "entry count {entry_count} exceeds maximum {max_entries}"
            )));
        }
        if free_count > max_free {
            return Err(CryptoError::VaultCorrupted(format!(
                "free region count {free_count} exceeds maximum {max_free}"
            )));
        }

        let next_free_offset = read_u64(data, &mut off)?;
        let capacity = read_u64(data, &mut off)?;
        let next_generation = read_u64(data, &mut off)?;

        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            let name_len = read_u16(data, &mut off)? as usize;
            if name_len == 0 || name_len > MAX_SEGMENT_NAME_LEN {
                return Err(CryptoError::VaultCorrupted(format!(
                    "invalid segment name length: {name_len}"
                )));
            }
            let name_bytes = read_bytes(data, &mut off, name_len)?;
            let name = String::from_utf8(name_bytes).map_err(|_| {
                CryptoError::VaultCorrupted("segment name is not valid UTF-8".into())
            })?;
            let offset = read_u64(data, &mut off)?;
            let size = read_u64(data, &mut off)?;
            let generation = read_u64(data, &mut off)?;
            let checksum_bytes = read_bytes(data, &mut off, 32)?;
            let mut checksum = [0u8; 32];
            checksum.copy_from_slice(&checksum_bytes);
            let comp_byte = read_bytes(data, &mut off, 1)?;
            let compression = CompressionAlgorithm::from_u8(comp_byte[0])?;
            entries.push(SegmentEntry {
                name,
                offset,
                size,
                generation,
                checksum,
                compression,
            });
        }

        let mut free_regions = Vec::with_capacity(free_count);
        for _ in 0..free_count {
            let offset = read_u64(data, &mut off)?;
            let size = read_u64(data, &mut off)?;
            free_regions.push(FreeRegion { offset, size });
        }

        Ok(Self {
            entries,
            free_regions,
            next_free_offset,
            capacity,
            next_generation,
        })
    }

    // -- lookup / mutation --------------------------------------------------

    /// Add a segment entry. Rejects duplicate names.
    pub fn add(&mut self, entry: SegmentEntry) -> Result<(), CryptoError> {
        if self.entries.iter().any(|e| e.name == entry.name) {
            return Err(CryptoError::InvalidParameter(format!(
                "duplicate segment name: {}",
                entry.name
            )));
        }
        self.entries.push(entry);
        Ok(())
    }

    pub fn find(&self, name: &str) -> Option<&SegmentEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    pub fn find_mut(&mut self, name: &str) -> Option<&mut SegmentEntry> {
        self.entries.iter_mut().find(|e| e.name == name)
    }

    pub fn remove(&mut self, name: &str) -> Option<SegmentEntry> {
        if let Some(pos) = self.entries.iter().position(|e| e.name == name) {
            Some(self.entries.remove(pos))
        } else {
            None
        }
    }

    pub fn names(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.name.as_str()).collect()
    }

    // -- allocation ---------------------------------------------------------

    /// Allocate space for `size` bytes. Returns the data-region offset.
    ///
    /// Strategy: best-fit search in `free_regions` first (smallest region
    /// that fits), then fall back to appending at `next_free_offset`.
    pub fn allocate(&mut self, size: u64) -> Result<u64, CryptoError> {
        if size == 0 {
            return Err(CryptoError::InvalidParameter(
                "cannot allocate zero bytes".into(),
            ));
        }

        // Best-fit search in free list
        let best = self
            .free_regions
            .iter()
            .enumerate()
            .filter(|(_, r)| r.size >= size)
            .min_by_key(|(_, r)| r.size);

        if let Some((idx, _)) = best {
            let region = self.free_regions.remove(idx);
            let offset = region.offset;
            let leftover = region.size - size;
            if leftover > 0 {
                self.free_regions.push(FreeRegion {
                    offset: offset + size,
                    size: leftover,
                });
                self.free_regions.sort_by_key(|r| r.offset);
            }
            return Ok(offset);
        }

        // Fall back to append (checked arithmetic to prevent overflow)
        let end = self
            .next_free_offset
            .checked_add(size)
            .ok_or(CryptoError::VaultFull {
                needed: size,
                available: self.capacity.saturating_sub(self.next_free_offset),
            })?;
        if end > self.capacity {
            return Err(CryptoError::VaultFull {
                needed: size,
                available: self.capacity.saturating_sub(self.next_free_offset),
            });
        }
        let offset = self.next_free_offset;
        self.next_free_offset = end;
        Ok(offset)
    }

    /// Return a region to the free list. Merges adjacent regions.
    pub fn deallocate(&mut self, offset: u64, size: u64) {
        self.free_regions.push(FreeRegion { offset, size });
        self.free_regions.sort_by_key(|r| r.offset);
        self.merge_adjacent();
    }

    fn merge_adjacent(&mut self) {
        let mut i = 0;
        while i + 1 < self.free_regions.len() {
            let end = self.free_regions[i].offset + self.free_regions[i].size;
            if end == self.free_regions[i + 1].offset {
                self.free_regions[i].size += self.free_regions[i + 1].size;
                self.free_regions.remove(i + 1);
            } else {
                i += 1;
            }
        }
    }

    // -- generation ---------------------------------------------------------

    pub fn next_gen(&mut self) -> u64 {
        let gen = self.next_generation;
        self.next_generation += 1;
        gen
    }

    // -- stats --------------------------------------------------------------

    pub fn used_bytes(&self) -> u64 {
        self.entries.iter().map(|e| e.size).sum()
    }

    pub fn free_list_bytes(&self) -> u64 {
        self.free_regions.iter().map(|r| r.size).sum()
    }

    // -- defragmentation ----------------------------------------------------

    /// Compute the list of segment moves needed to compact the index.
    ///
    /// Returns moves sorted by target offset. Each move describes copying
    /// encrypted bytes from `old_offset` to `new_offset` (both relative to
    /// data region start). Segments already in place are skipped.
    pub fn plan_defrag(&self) -> Vec<DefragMove> {
        let mut order: Vec<usize> = (0..self.entries.len()).collect();
        order.sort_by_key(|&i| self.entries[i].offset);

        let mut moves = Vec::new();
        let mut target: u64 = 0;

        for &i in &order {
            let old_offset = self.entries[i].offset;
            let size = self.entries[i].size;

            if old_offset != target {
                moves.push(DefragMove {
                    entry_index: i,
                    old_offset,
                    new_offset: target,
                    size,
                });
            }
            target += size;
        }

        moves
    }

    /// Apply a single defrag move to the in-memory index.
    ///
    /// Updates the entry offset. Does NOT touch free_regions or
    /// next_free_offset — call `complete_defrag()` after all moves.
    pub fn apply_move(&mut self, entry_index: usize, new_offset: u64) {
        self.entries[entry_index].offset = new_offset;
    }

    /// Finalize defrag: clear free_regions, set next_free_offset to the
    /// sum of all segment sizes. Call after all moves have been applied.
    pub fn complete_defrag(&mut self) {
        self.free_regions.clear();
        self.next_free_offset = self.used_bytes();
    }

    /// Returns true if the index has fragmented free space that defrag
    /// would reclaim.
    pub fn needs_defrag(&self) -> bool {
        !self.free_regions.is_empty()
    }
}

/// A single segment move planned by `SegmentIndex::plan_defrag()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefragMove {
    /// Index into `SegmentIndex.entries`.
    pub entry_index: usize,
    /// Current offset (relative to data region start).
    pub old_offset: u64,
    /// Target offset after compaction.
    pub new_offset: u64,
    /// Encrypted segment size in bytes.
    pub size: u64,
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_checksum(val: u8) -> [u8; 32] {
        [val; 32]
    }

    // -- VaultHeader --------------------------------------------------------

    #[test]
    fn test_vault_header_roundtrip() {
        let header = VaultHeader::new(0x01);
        let bytes = header.to_bytes();
        let parsed = VaultHeader::from_bytes(&bytes).expect("parse");
        assert_eq!(header, parsed);
    }

    #[test]
    fn test_vault_header_invalid_magic() {
        let mut bytes = VaultHeader::new(0x01).to_bytes();
        bytes[0] = b'X';
        assert!(VaultHeader::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_vault_header_invalid_version() {
        let mut bytes = VaultHeader::new(0x01).to_bytes();
        bytes[4] = 99;
        assert!(VaultHeader::from_bytes(&bytes).is_err());
    }

    // -- SegmentEntry -------------------------------------------------------

    #[test]
    fn test_segment_entry_valid_name() {
        // 1 byte
        let e = SegmentEntry::new(
            "a",
            0,
            100,
            0,
            dummy_checksum(0),
            CompressionAlgorithm::None,
        );
        assert!(e.is_ok());

        // 255 bytes
        let long = "a".repeat(MAX_SEGMENT_NAME_LEN);
        let e = SegmentEntry::new(
            &long,
            0,
            100,
            0,
            dummy_checksum(0),
            CompressionAlgorithm::None,
        );
        assert!(e.is_ok());
    }

    #[test]
    fn test_segment_entry_name_too_long() {
        let long = "a".repeat(MAX_SEGMENT_NAME_LEN + 1);
        let e = SegmentEntry::new(
            &long,
            0,
            100,
            0,
            dummy_checksum(0),
            CompressionAlgorithm::None,
        );
        assert!(e.is_err());
    }

    #[test]
    fn test_segment_entry_name_empty() {
        let e = SegmentEntry::new("", 0, 100, 0, dummy_checksum(0), CompressionAlgorithm::None);
        assert!(e.is_err());
    }

    // -- SegmentIndex serialization -----------------------------------------

    fn make_test_index() -> SegmentIndex {
        let mut idx = SegmentIndex::new(1024 * 1024);
        idx.add(
            SegmentEntry::new(
                "hello.txt",
                0,
                4096,
                1,
                dummy_checksum(0xAA),
                CompressionAlgorithm::Zstd,
            )
            .expect("entry"),
        )
        .expect("add");
        idx.add(
            SegmentEntry::new(
                "photo.jpg",
                4096,
                8192,
                2,
                dummy_checksum(0xBB),
                CompressionAlgorithm::None,
            )
            .expect("entry"),
        )
        .expect("add");
        idx.free_regions.push(FreeRegion {
            offset: 12288,
            size: 2048,
        });
        idx.next_free_offset = 14336;
        idx.next_generation = 3;
        idx
    }

    #[test]
    fn test_segment_index_roundtrip() {
        let idx = make_test_index();
        let bytes = idx.to_bytes().expect("serialize");
        let parsed = SegmentIndex::from_bytes(&bytes).expect("parse");

        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].name, "hello.txt");
        assert_eq!(parsed.entries[0].offset, 0);
        assert_eq!(parsed.entries[0].size, 4096);
        assert_eq!(parsed.entries[0].generation, 1);
        assert_eq!(parsed.entries[0].checksum, dummy_checksum(0xAA));
        assert_eq!(parsed.entries[0].compression, CompressionAlgorithm::Zstd);

        assert_eq!(parsed.entries[1].name, "photo.jpg");
        assert_eq!(parsed.entries[1].compression, CompressionAlgorithm::None);

        assert_eq!(parsed.free_regions.len(), 1);
        assert_eq!(parsed.free_regions[0].offset, 12288);
        assert_eq!(parsed.free_regions[0].size, 2048);

        assert_eq!(parsed.next_free_offset, 14336);
        assert_eq!(parsed.capacity, 1024 * 1024);
        assert_eq!(parsed.next_generation, 3);
    }

    #[test]
    fn test_segment_index_roundtrip_with_generation() {
        let mut idx = SegmentIndex::new(1024);
        idx.next_generation = 42;
        idx.entries.push(
            SegmentEntry::new(
                "gen",
                0,
                64,
                41,
                dummy_checksum(0),
                CompressionAlgorithm::None,
            )
            .expect("entry"),
        );
        let bytes = idx.to_bytes().expect("serialize");
        let parsed = SegmentIndex::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed.next_generation, 42);
        assert_eq!(parsed.entries[0].generation, 41);
    }

    #[test]
    fn test_segment_index_compression_field() {
        let mut idx = SegmentIndex::new(1024 * 1024);
        for (i, algo) in [
            CompressionAlgorithm::Zstd,
            CompressionAlgorithm::Brotli,
            CompressionAlgorithm::None,
        ]
        .iter()
        .enumerate()
        {
            idx.entries.push(
                SegmentEntry::new(
                    &format!("seg{i}"),
                    (i as u64) * 1024,
                    1024,
                    0,
                    dummy_checksum(i as u8),
                    *algo,
                )
                .expect("entry"),
            );
        }
        let bytes = idx.to_bytes().expect("serialize");
        let parsed = SegmentIndex::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed.entries[0].compression, CompressionAlgorithm::Zstd);
        assert_eq!(parsed.entries[1].compression, CompressionAlgorithm::Brotli);
        assert_eq!(parsed.entries[2].compression, CompressionAlgorithm::None);
    }

    #[test]
    fn test_segment_index_free_regions_roundtrip() {
        let mut idx = SegmentIndex::new(1024 * 1024);
        idx.free_regions.push(FreeRegion {
            offset: 0,
            size: 100,
        });
        idx.free_regions.push(FreeRegion {
            offset: 500,
            size: 200,
        });
        idx.free_regions.push(FreeRegion {
            offset: 1000,
            size: 300,
        });
        let bytes = idx.to_bytes().expect("serialize");
        let parsed = SegmentIndex::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed.free_regions.len(), 3);
        assert_eq!(
            parsed.free_regions[0],
            FreeRegion {
                offset: 0,
                size: 100
            }
        );
        assert_eq!(
            parsed.free_regions[1],
            FreeRegion {
                offset: 500,
                size: 200
            }
        );
        assert_eq!(
            parsed.free_regions[2],
            FreeRegion {
                offset: 1000,
                size: 300
            }
        );
    }

    #[test]
    fn test_segment_index_padded_size() {
        // Empty index
        let idx = SegmentIndex::new(1024);
        let bytes = idx.to_bytes().expect("serialize");
        assert_eq!(bytes.len(), INDEX_PAD_SIZE);

        // Index with entries + free regions
        let idx = make_test_index();
        let bytes = idx.to_bytes().expect("serialize");
        assert_eq!(bytes.len(), INDEX_PAD_SIZE);
    }

    #[test]
    fn test_segment_index_overflow() {
        let mut idx = SegmentIndex::new(u64::MAX);
        // Each entry with a 255-byte name uses 2 + 255 + 8 + 8 + 8 + 32 + 1 = 314 bytes.
        // Index header is 32 bytes. (65536 - 32) / 314 ≈ 208 entries max.
        for i in 0..210 {
            let name = format!("{:0>255}", i);
            idx.entries.push(
                SegmentEntry::new(
                    &name,
                    0,
                    64,
                    0,
                    dummy_checksum(0),
                    CompressionAlgorithm::None,
                )
                .expect("entry"),
            );
        }
        assert!(idx.to_bytes().is_err());
    }

    // -- SegmentIndex lookup / mutation --------------------------------------

    #[test]
    fn test_segment_index_find() {
        let idx = make_test_index();
        let found = idx.find("hello.txt");
        assert!(found.is_some());
        assert_eq!(found.expect("find").offset, 0);

        assert!(idx.find("nonexistent").is_none());
    }

    #[test]
    fn test_segment_index_remove() {
        let mut idx = make_test_index();
        let removed = idx.remove("hello.txt");
        assert!(removed.is_some());
        assert_eq!(removed.expect("remove").name, "hello.txt");
        assert!(idx.find("hello.txt").is_none());
        assert_eq!(idx.entries.len(), 1);
    }

    // -- Allocation ---------------------------------------------------------

    #[test]
    fn test_allocate_appends_when_no_free_regions() {
        let mut idx = SegmentIndex::new(1024);
        let off1 = idx.allocate(100).expect("alloc");
        assert_eq!(off1, 0);
        assert_eq!(idx.next_free_offset, 100);

        let off2 = idx.allocate(200).expect("alloc");
        assert_eq!(off2, 100);
        assert_eq!(idx.next_free_offset, 300);
    }

    #[test]
    fn test_allocate_reuses_free_region_exact_fit() {
        let mut idx = SegmentIndex::new(1024);
        idx.free_regions.push(FreeRegion {
            offset: 0,
            size: 100,
        });

        let off = idx.allocate(100).expect("alloc");
        assert_eq!(off, 0);
        assert!(idx.free_regions.is_empty());
    }

    #[test]
    fn test_allocate_reuses_free_region_with_split() {
        let mut idx = SegmentIndex::new(1024);
        idx.free_regions.push(FreeRegion {
            offset: 0,
            size: 300,
        });

        let off = idx.allocate(100).expect("alloc");
        assert_eq!(off, 0);
        assert_eq!(idx.free_regions.len(), 1);
        assert_eq!(idx.free_regions[0].offset, 100);
        assert_eq!(idx.free_regions[0].size, 200);
    }

    #[test]
    fn test_allocate_best_fit() {
        let mut idx = SegmentIndex::new(1024);
        idx.free_regions.push(FreeRegion {
            offset: 0,
            size: 500,
        });
        idx.free_regions.push(FreeRegion {
            offset: 600,
            size: 150,
        });
        idx.free_regions.push(FreeRegion {
            offset: 800,
            size: 200,
        });

        // Needs 150 — should pick region at 600 (exact fit 150)
        let off = idx.allocate(150).expect("alloc");
        assert_eq!(off, 600);
        // The 150-byte region was consumed exactly
        assert_eq!(idx.free_regions.len(), 2);
    }

    #[test]
    fn test_allocate_falls_back_to_append() {
        let mut idx = SegmentIndex::new(1024);
        idx.free_regions.push(FreeRegion {
            offset: 0,
            size: 50,
        });
        idx.next_free_offset = 100;

        // Needs 80 — free region only has 50, so append at 100
        let off = idx.allocate(80).expect("alloc");
        assert_eq!(off, 100);
        assert_eq!(idx.next_free_offset, 180);
        // Free region untouched
        assert_eq!(idx.free_regions.len(), 1);
    }

    #[test]
    fn test_allocate_vault_full() {
        let mut idx = SegmentIndex::new(100);
        idx.next_free_offset = 80;

        let err = idx.allocate(50).expect_err("should be VaultFull");
        match err {
            CryptoError::VaultFull { needed, available } => {
                assert_eq!(needed, 50);
                assert_eq!(available, 20);
            }
            other => panic!("expected VaultFull, got {other:?}"),
        }
    }

    // -- Deallocation -------------------------------------------------------

    #[test]
    fn test_deallocate_adds_to_free_list() {
        let mut idx = SegmentIndex::new(1024);
        idx.deallocate(100, 50);
        assert_eq!(idx.free_regions.len(), 1);
        assert_eq!(
            idx.free_regions[0],
            FreeRegion {
                offset: 100,
                size: 50
            }
        );
    }

    #[test]
    fn test_deallocate_merges_adjacent() {
        let mut idx = SegmentIndex::new(1024);
        idx.deallocate(100, 50);
        idx.deallocate(150, 50);
        assert_eq!(idx.free_regions.len(), 1);
        assert_eq!(
            idx.free_regions[0],
            FreeRegion {
                offset: 100,
                size: 100
            }
        );
    }

    #[test]
    fn test_deallocate_no_merge_non_adjacent() {
        let mut idx = SegmentIndex::new(1024);
        idx.deallocate(100, 50);
        idx.deallocate(200, 50);
        assert_eq!(idx.free_regions.len(), 2);
    }

    #[test]
    fn test_deallocate_triple_merge() {
        let mut idx = SegmentIndex::new(1024);
        // Free A, C first (gap at B), then free B to trigger triple merge
        idx.deallocate(0, 100);
        idx.deallocate(200, 100);
        assert_eq!(idx.free_regions.len(), 2);

        // Free the middle gap
        idx.deallocate(100, 100);
        assert_eq!(idx.free_regions.len(), 1);
        assert_eq!(
            idx.free_regions[0],
            FreeRegion {
                offset: 0,
                size: 300
            }
        );
    }

    #[test]
    fn test_allocate_after_deallocate() {
        let mut idx = SegmentIndex::new(1024);
        // Allocate then free a region
        let off = idx.allocate(200).expect("alloc");
        assert_eq!(off, 0);
        idx.deallocate(0, 200);

        // Next allocation should reuse the freed space
        let off = idx.allocate(200).expect("realloc");
        assert_eq!(off, 0);
        assert!(idx.free_regions.is_empty());
    }

    // -- Generation counter -------------------------------------------------

    #[test]
    fn test_generation_counter_increments() {
        let mut idx = SegmentIndex::new(1024);
        assert_eq!(idx.next_gen(), 0);
        assert_eq!(idx.next_gen(), 1);
        assert_eq!(idx.next_gen(), 2);
    }

    // -- Layout constants ---------------------------------------------------

    #[test]
    fn test_layout_offsets() {
        // Primary index immediately after header
        assert_eq!(PRIMARY_INDEX_OFFSET, VAULT_HEADER_SIZE as u64);

        // Data region after primary index
        assert_eq!(
            DATA_REGION_OFFSET,
            PRIMARY_INDEX_OFFSET + ENCRYPTED_INDEX_SIZE as u64
        );

        let cap = 10 * 1024 * 1024; // 10MB
        let shadow = shadow_index_offset(cap).expect("shadow");
        let wal = wal_region_offset(cap).expect("wal");

        // Shadow index after data region
        assert_eq!(shadow, DATA_REGION_OFFSET + cap);

        // WAL after shadow index
        assert_eq!(wal, shadow + ENCRYPTED_INDEX_SIZE as u64);

        // No overlapping regions
        assert!(shadow > DATA_REGION_OFFSET);
        assert!(wal > shadow);
    }

    #[test]
    fn test_layout_overflow() {
        assert!(shadow_index_offset(u64::MAX).is_err());
        assert!(wal_region_offset(u64::MAX).is_err());
    }

    // -- Zero-size allocation -----------------------------------------------

    #[test]
    fn test_allocate_zero_rejected() {
        let mut idx = SegmentIndex::new(1024);
        assert!(idx.allocate(0).is_err());
    }

    // -- Duplicate names ----------------------------------------------------

    #[test]
    fn test_add_duplicate_name_rejected() {
        let mut idx = SegmentIndex::new(1024);
        let e1 = SegmentEntry::new(
            "dup",
            0,
            64,
            0,
            dummy_checksum(0),
            CompressionAlgorithm::None,
        )
        .expect("entry");
        let e2 = SegmentEntry::new(
            "dup",
            64,
            64,
            1,
            dummy_checksum(1),
            CompressionAlgorithm::None,
        )
        .expect("entry");
        idx.add(e1).expect("first add");
        assert!(idx.add(e2).is_err());
        assert_eq!(idx.entries.len(), 1);
    }

    // -- Defragmentation planning -------------------------------------------

    #[test]
    fn test_plan_defrag_no_gaps() {
        let mut idx = SegmentIndex::new(1024);
        idx.entries.push(
            SegmentEntry::new(
                "a",
                0,
                100,
                0,
                dummy_checksum(0),
                CompressionAlgorithm::None,
            )
            .expect("entry"),
        );
        idx.entries.push(
            SegmentEntry::new(
                "b",
                100,
                200,
                1,
                dummy_checksum(1),
                CompressionAlgorithm::None,
            )
            .expect("entry"),
        );
        idx.next_free_offset = 300;

        let moves = idx.plan_defrag();
        assert!(moves.is_empty(), "no moves needed when compact");
    }

    #[test]
    fn test_plan_defrag_single_gap() {
        let mut idx = SegmentIndex::new(1024);
        // A at 0, gap at 100, B at 200
        idx.entries.push(
            SegmentEntry::new(
                "a",
                0,
                100,
                0,
                dummy_checksum(0),
                CompressionAlgorithm::None,
            )
            .expect("entry"),
        );
        idx.entries.push(
            SegmentEntry::new(
                "b",
                200,
                100,
                1,
                dummy_checksum(1),
                CompressionAlgorithm::None,
            )
            .expect("entry"),
        );
        idx.free_regions.push(FreeRegion {
            offset: 100,
            size: 100,
        });
        idx.next_free_offset = 300;

        let moves = idx.plan_defrag();
        assert_eq!(moves.len(), 1);
        assert_eq!(moves[0].old_offset, 200);
        assert_eq!(moves[0].new_offset, 100);
        assert_eq!(moves[0].size, 100);
    }

    #[test]
    fn test_plan_defrag_gap_at_start() {
        let mut idx = SegmentIndex::new(1024);
        // Gap at 0, A at 200
        idx.entries.push(
            SegmentEntry::new(
                "a",
                200,
                100,
                0,
                dummy_checksum(0),
                CompressionAlgorithm::None,
            )
            .expect("entry"),
        );
        idx.free_regions.push(FreeRegion {
            offset: 0,
            size: 200,
        });
        idx.next_free_offset = 300;

        let moves = idx.plan_defrag();
        assert_eq!(moves.len(), 1);
        assert_eq!(moves[0].old_offset, 200);
        assert_eq!(moves[0].new_offset, 0);
    }

    #[test]
    fn test_plan_defrag_multiple_gaps() {
        let mut idx = SegmentIndex::new(2048);
        // A(0-100) gap(100-200) B(200-350) gap(350-400) C(400-500)
        idx.entries.push(
            SegmentEntry::new(
                "a",
                0,
                100,
                0,
                dummy_checksum(0),
                CompressionAlgorithm::None,
            )
            .expect("entry"),
        );
        idx.entries.push(
            SegmentEntry::new(
                "b",
                200,
                150,
                1,
                dummy_checksum(1),
                CompressionAlgorithm::None,
            )
            .expect("entry"),
        );
        idx.entries.push(
            SegmentEntry::new(
                "c",
                400,
                100,
                2,
                dummy_checksum(2),
                CompressionAlgorithm::None,
            )
            .expect("entry"),
        );
        idx.free_regions.push(FreeRegion {
            offset: 100,
            size: 100,
        });
        idx.free_regions.push(FreeRegion {
            offset: 350,
            size: 50,
        });
        idx.next_free_offset = 500;

        let moves = idx.plan_defrag();
        assert_eq!(moves.len(), 2); // B and C need to move

        // B: 200 → 100
        assert_eq!(moves[0].old_offset, 200);
        assert_eq!(moves[0].new_offset, 100);
        assert_eq!(moves[0].size, 150);

        // C: 400 → 250
        assert_eq!(moves[1].old_offset, 400);
        assert_eq!(moves[1].new_offset, 250);
        assert_eq!(moves[1].size, 100);
    }

    #[test]
    fn test_plan_defrag_empty_index() {
        let idx = SegmentIndex::new(1024);
        let moves = idx.plan_defrag();
        assert!(moves.is_empty());
    }

    #[test]
    fn test_apply_move_and_complete() {
        let mut idx = SegmentIndex::new(1024);
        idx.entries.push(
            SegmentEntry::new(
                "a",
                0,
                100,
                0,
                dummy_checksum(0),
                CompressionAlgorithm::None,
            )
            .expect("entry"),
        );
        idx.entries.push(
            SegmentEntry::new(
                "b",
                200,
                100,
                1,
                dummy_checksum(1),
                CompressionAlgorithm::None,
            )
            .expect("entry"),
        );
        idx.free_regions.push(FreeRegion {
            offset: 100,
            size: 100,
        });
        idx.next_free_offset = 300;

        let moves = idx.plan_defrag();
        for m in &moves {
            idx.apply_move(m.entry_index, m.new_offset);
        }
        idx.complete_defrag();

        assert_eq!(idx.free_regions.len(), 0);
        assert_eq!(idx.next_free_offset, 200); // 100 + 100
        assert_eq!(idx.entries[1].offset, 100); // B moved from 200 → 100

        // Entries preserve generation and checksum
        assert_eq!(idx.entries[0].generation, 0);
        assert_eq!(idx.entries[1].generation, 1);
    }

    #[test]
    fn test_needs_defrag() {
        let mut idx = SegmentIndex::new(1024);
        assert!(!idx.needs_defrag());

        idx.free_regions.push(FreeRegion {
            offset: 0,
            size: 100,
        });
        assert!(idx.needs_defrag());
    }
}
