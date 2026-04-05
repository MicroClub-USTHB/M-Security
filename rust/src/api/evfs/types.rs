use crate::core::error::CryptoError;
use crate::core::evfs::format::SegmentIndex;
use crate::core::evfs::segment::VaultKeys;
use crate::core::evfs::wal::{VaultLock, WriteAheadLog};
use crate::core::format::Algorithm;
use flutter_rust_bridge::frb;
use memmap2::Mmap;
use std::fs::File;

// ---------------------------------------------------------------------------
// VaultMmap — read-only memory-mapped view of the vault file
// ---------------------------------------------------------------------------

/// Read-only memory-mapped view of the vault file for zero-copy segment reads.
///
/// Created on vault open and recreated after any mutation (write, delete,
/// defrag, resize) that changes the file contents.
pub(crate) struct VaultMmap {
    mmap: Mmap,
}

impl VaultMmap {
    /// Create a new read-only mapping of the vault file.
    ///
    /// # Safety contract
    /// The caller must hold an exclusive flock on the file (VaultLock) so no
    /// concurrent writer can modify the file while the mapping is live.
    pub(crate) fn new(file: &File) -> Result<Self, CryptoError> {
        // SAFETY: the caller holds an exclusive advisory flock via VaultLock,
        // ensuring no cooperating process modifies the file while mapped.
        // Non-cooperating processes are outside this library's threat model.
        let mmap = unsafe { Mmap::map(file) }
            .map_err(|e| CryptoError::IoError(format!("mmap failed: {e}")))?;

        // Lock pages to prevent kernel from swapping ciphertext to disk.
        // Failure is non-fatal (mlock limits may be low on some systems).
        #[cfg(unix)]
        {
            unsafe {
                libc::mlock(mmap.as_ptr().cast::<libc::c_void>(), mmap.len());
            }
        }

        Ok(Self { mmap })
    }

    /// Return a byte slice into the mapped region at `[offset..offset+len]`.
    ///
    /// Returns `Err` if the range is out of bounds (e.g. 32-bit overflow or
    /// the file was truncated between mapping and read).
    pub(crate) fn slice(&self, offset: u64, len: u64) -> Result<&[u8], CryptoError> {
        let start = usize::try_from(offset).map_err(|_| {
            CryptoError::VaultCorrupted(format!("mmap offset {offset} exceeds address space"))
        })?;
        let size = usize::try_from(len).map_err(|_| {
            CryptoError::VaultCorrupted(format!("mmap length {len} exceeds address space"))
        })?;
        let end = start
            .checked_add(size)
            .ok_or_else(|| CryptoError::VaultCorrupted("mmap range overflow".into()))?;
        if end > self.mmap.len() {
            return Err(CryptoError::VaultCorrupted(format!(
                "mmap read {start}..{end} exceeds file size {}",
                self.mmap.len()
            )));
        }
        Ok(&self.mmap[start..end])
    }
}

#[cfg(unix)]
impl Drop for VaultMmap {
    fn drop(&mut self) {
        // Unlock pages before the mmap is unmapped
        unsafe {
            libc::munlock(self.mmap.as_ptr().cast::<libc::c_void>(), self.mmap.len());
        }
    }
}

// ---------------------------------------------------------------------------
// VaultHandle
// ---------------------------------------------------------------------------

/// Opaque handle for an open vault.
///
/// Holds the open file, derived sub-keys, cached index, WAL, and file lock.
/// All key material uses SecretBuffer (ZeroizeOnDrop).
#[frb(opaque)]
pub struct VaultHandle {
    #[allow(dead_code)] // used by Dart wrappers
    pub(crate) path: String,
    pub(crate) algorithm: Algorithm,
    pub(crate) keys: VaultKeys,
    pub(crate) index: SegmentIndex,
    /// Padded plaintext index size, set at creation and read from header on open.
    pub(crate) index_pad_size: usize,
    /// Read-only mmap for zero-copy reads. None if mmap failed (32-bit fallback).
    /// Dropped before `file` so munlock/munmap runs while the fd is still open.
    pub(crate) mmap: Option<VaultMmap>,
    pub(crate) file: File,
    pub(crate) wal: WriteAheadLog,
    pub(crate) lock: VaultLock,
    /// True when the in-memory index has been modified but not yet flushed to disk.
    pub(crate) index_dirty: bool,
}

impl VaultHandle {
    /// (Re)create the mmap after a mutation. Silently falls back to None on failure.
    pub(crate) fn refresh_mmap(&mut self) {
        self.mmap = VaultMmap::new(&self.file).ok();
    }
}

/// Capacity info returned to callers.
#[frb(non_opaque)]
pub struct VaultCapacityInfo {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub free_list_bytes: u64,
    pub unallocated_bytes: u64,
    pub segment_count: usize,
}

/// Result of a vault defragmentation operation.
#[frb(non_opaque)]
pub struct DefragResult {
    /// Number of segments that were physically moved on disk.
    pub segments_moved: u32,
    /// Bytes of free-list space reclaimed into contiguous unallocated space.
    pub bytes_reclaimed: u64,
    /// Number of scattered free regions before defragmentation.
    pub free_regions_before: u32,
}

/// Vault health and diagnostic info returned to callers.
#[frb(non_opaque)]
#[derive(Debug, Clone, PartialEq)]
pub struct VaultHealthInfo {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub free_list_bytes: u64,
    pub unallocated_bytes: u64,
    pub segment_count: u32,
    pub free_region_count: u32,
    pub largest_free_block: u64,
    /// 0.0 = no fragmentation, 1.0 = all free space is fragmented
    pub fragmentation_ratio: f64,
    /// True when `used + free_list + unallocated == total`. False signals
    /// index corruption or a bug in allocation bookkeeping.
    pub is_consistent: bool,
}

impl VaultHandle {
    /// Compute health information from the in-memory index only (no file I/O or WAL writes).
    #[must_use]
    pub fn health(&self) -> VaultHealthInfo {
        let total_bytes = self.index.capacity;
        let used_bytes = self.index.used_bytes();
        let free_list_bytes = self.index.free_list_bytes();

        // We use `saturating_sub` to safely handle subtractions. If next_free_offset
        // exceeds capacity (which shouldn't happen, but defensive programming is key),
        // it firmly caps at 0 instead of causing a thread panic.
        let unallocated_bytes = self
            .index
            .capacity
            .saturating_sub(self.index.next_free_offset);

        let segment_count = u32::try_from(self.index.entries.len()).unwrap_or(u32::MAX);
        let free_region_count = u32::try_from(self.index.free_regions.len()).unwrap_or(u32::MAX);

        let free_list_max = self
            .index
            .free_regions
            .iter()
            .map(|r| r.size)
            .max()
            .unwrap_or(0);

        let largest_free_block = std::cmp::max(free_list_max, unallocated_bytes);

        let total_free = free_list_bytes.saturating_add(unallocated_bytes);

        let fragmentation_ratio = if total_free == 0 {
            0.0
        } else {
            (free_list_bytes as f64) / (total_free as f64)
        };

        let is_consistent = used_bytes
            .checked_add(free_list_bytes)
            .and_then(|v| v.checked_add(unallocated_bytes))
            == Some(total_bytes);

        VaultHealthInfo {
            total_bytes,
            used_bytes,
            free_list_bytes,
            unallocated_bytes,
            segment_count,
            free_region_count,
            largest_free_block,
            fragmentation_ratio,
            is_consistent,
        }
    }
}
