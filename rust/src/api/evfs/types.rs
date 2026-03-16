use crate::core::evfs::format::SegmentIndex;
use crate::core::evfs::segment::VaultKeys;
use crate::core::evfs::wal::{VaultLock, WriteAheadLog};
use crate::core::format::Algorithm;
use flutter_rust_bridge::frb;
use std::fs::File;

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
    pub(crate) file: File,
    pub(crate) wal: WriteAheadLog,
    pub(crate) lock: VaultLock,
}

/// Capacity info returned to callers.
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
///
/// `#[frb(non_opaque)]` tells the code generator to expose this as a direct Dart class
/// with all these fields accessible, instead of hiding it behind a pointer.
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
}

impl VaultHandle {
    /// Compute health information from the in-memory index only (no file I/O or WAL writes).
    ///
    /// The `#[must_use]` attribute is a Rust best practice indicating that the return value
    /// of this function should not be silently ignored by callers.
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

        // Ensure accurate type casting with safety bounds.
        let segment_count = self.index.entries.len() as u32;
        let free_region_count = self.index.free_regions.len() as u32;

        // Functional programming in Rust: iterate over free regions, map to size, and find the max.
        let free_list_max = self
            .index
            .free_regions
            .iter()
            .map(|r| r.size)
            .max()
            .unwrap_or(0);

        let tail = unallocated_bytes;
        // The largest available chunk is either the biggest free list block or the unallocated tail.
        let largest_free_block = std::cmp::max(free_list_max, tail);

        // Calculate total free space securely.
        let total_free = free_list_bytes.saturating_add(unallocated_bytes);

        // Prevent Divide-by-Zero errors with a standard conditional cast.
        let fragmentation_ratio = if total_free == 0 {
            0.0
        } else {
            (free_list_bytes as f64) / (total_free as f64)
        };

        VaultHealthInfo {
            total_bytes,
            used_bytes,
            free_list_bytes,
            unallocated_bytes,
            segment_count,
            free_region_count,
            largest_free_block,
            fragmentation_ratio,
        }
    }
}
