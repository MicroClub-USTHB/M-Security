//! Write-ahead log, crash recovery, and file locking.

use flutter_rust_bridge::frb;

use crate::core::error::CryptoError;
use fs4::fs_std::FileExt;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// WAL entry header: op(1) + data_len(4) = 5 bytes.
const ENTRY_HEADER_SIZE: usize = 5;

/// WAL entry footer: crc32(4) + committed(1) = 5 bytes.
const ENTRY_FOOTER_SIZE: usize = 5;

/// Max snapshot size (256KB). The encrypted index is ~65KB; this leaves
/// generous headroom while rejecting clearly corrupt `data_len` values
/// that would cause OOM allocations.
const MAX_SNAPSHOT_SIZE: usize = 256 * 1024;

// ---------------------------------------------------------------------------
// WalOp
// ---------------------------------------------------------------------------

/// WAL operation types (for logging/diagnostics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[frb(ignore)]
pub enum WalOp {
    WriteSegment = 0x01,
    DeleteSegment = 0x02,
    UpdateIndex = 0x03,
}

impl WalOp {
    pub fn from_byte(b: u8) -> Result<Self, CryptoError> {
        match b {
            0x01 => Ok(WalOp::WriteSegment),
            0x02 => Ok(WalOp::DeleteSegment),
            0x03 => Ok(WalOp::UpdateIndex),
            _ => Err(CryptoError::VaultCorrupted(format!(
                "unknown WAL op: 0x{b:02X}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// WalEntry
// ---------------------------------------------------------------------------

/// A single WAL journal entry — undo record.
///
/// On-disk layout:
/// `[op: u8] [data_len: u32 LE] [data: bytes] [crc32: u32 LE] [committed: u8]`
///
/// CRC32 covers `op || data_len || data` (everything before the CRC field).
#[derive(Debug, Clone)]
#[frb(ignore)]
pub struct WalEntry {
    pub op: WalOp,
    /// Encrypted index bytes captured before the mutation.
    pub old_index_snapshot: Vec<u8>,
    pub crc: u32,
    pub committed: bool,
}

impl WalEntry {
    /// Create a new uncommitted WAL entry. CRC is computed automatically.
    pub fn new(op: WalOp, old_index_snapshot: Vec<u8>) -> Self {
        let crc = Self::compute_crc(op, &old_index_snapshot);
        Self {
            op,
            old_index_snapshot,
            crc,
            committed: false,
        }
    }

    /// Serialize the entry for on-disk storage.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        let data_len = u32::try_from(self.old_index_snapshot.len()).map_err(|_| {
            CryptoError::InvalidParameter("WAL entry data too large for u32 length".into())
        })?;

        let total = ENTRY_HEADER_SIZE + self.old_index_snapshot.len() + ENTRY_FOOTER_SIZE;
        let mut buf = Vec::with_capacity(total);

        buf.push(self.op as u8);
        buf.extend_from_slice(&data_len.to_le_bytes());
        buf.extend_from_slice(&self.old_index_snapshot);
        buf.extend_from_slice(&self.crc.to_le_bytes());
        buf.push(u8::from(self.committed));

        Ok(buf)
    }

    /// Deserialize an entry from on-disk bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        let min_size = ENTRY_HEADER_SIZE + ENTRY_FOOTER_SIZE;
        if data.len() < min_size {
            return Err(CryptoError::VaultCorrupted("WAL entry too short".into()));
        }

        let op = WalOp::from_byte(data[0])?;
        let data_len =
            u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as usize;

        if data_len > MAX_SNAPSHOT_SIZE {
            return Err(CryptoError::VaultCorrupted(format!(
                "WAL data_len {data_len} exceeds max {MAX_SNAPSHOT_SIZE}"
            )));
        }

        // Safe from overflow: data_len <= MAX_SNAPSHOT_SIZE (256KB) so
        // ENTRY_HEADER_SIZE + data_len + ENTRY_FOOTER_SIZE fits in usize
        // on both 32-bit and 64-bit targets.
        let expected_total = ENTRY_HEADER_SIZE + data_len + ENTRY_FOOTER_SIZE;
        if data.len() < expected_total {
            return Err(CryptoError::VaultCorrupted(format!(
                "WAL entry truncated: need {expected_total} bytes, have {}",
                data.len()
            )));
        }

        let snapshot = data[ENTRY_HEADER_SIZE..ENTRY_HEADER_SIZE + data_len].to_vec();

        let crc_off = ENTRY_HEADER_SIZE + data_len;
        let crc = u32::from_le_bytes([
            data[crc_off],
            data[crc_off + 1],
            data[crc_off + 2],
            data[crc_off + 3],
        ]);
        let committed = data[crc_off + 4] != 0;

        // Verify CRC
        let expected_crc = Self::compute_crc(op, &snapshot);
        if crc != expected_crc {
            return Err(CryptoError::VaultCorrupted(format!(
                "WAL CRC mismatch: stored 0x{crc:08X}, computed 0x{expected_crc:08X}"
            )));
        }

        Ok(Self {
            op,
            old_index_snapshot: snapshot,
            crc,
            committed,
        })
    }

    /// Total on-disk size of this entry.
    pub fn on_disk_size(&self) -> usize {
        ENTRY_HEADER_SIZE + self.old_index_snapshot.len() + ENTRY_FOOTER_SIZE
    }

    /// CRC32 over `op || data_len(LE) || data`.
    fn compute_crc(op: WalOp, data: &[u8]) -> u32 {
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&[op as u8]);
        let len = data.len() as u32;
        hasher.update(&len.to_le_bytes());
        hasher.update(data);
        hasher.finalize()
    }
}

// ---------------------------------------------------------------------------
// WriteAheadLog
// ---------------------------------------------------------------------------

/// Write-ahead log for crash recovery.
///
/// Before each vault mutation the current encrypted index is journaled with
/// `committed = false`. After the mutation completes the entry is marked
/// committed. On recovery any uncommitted entry triggers restoration of the
/// old index snapshot.
#[frb(ignore)]
pub struct WriteAheadLog {
    file: File,
}

impl WriteAheadLog {
    /// Create or open the WAL file at `{vault_path}.wal`.
    pub fn open(vault_path: &str) -> Result<Self, CryptoError> {
        let wal_path = format!("{vault_path}.wal");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&wal_path)
            .map_err(|e| CryptoError::IoError(format!("cannot open WAL: {e}")))?;
        Ok(Self { file })
    }

    /// Journal the current encrypted index before a mutation.
    ///
    /// Writes the entry with `committed = false`, then fsyncs.
    pub fn begin(&mut self, op: WalOp, encrypted_index: &[u8]) -> Result<(), CryptoError> {
        let entry = WalEntry::new(op, encrypted_index.to_vec());
        let bytes = entry.to_bytes()?;

        self.file.seek(SeekFrom::End(0))?;
        self.file.write_all(&bytes)?;
        self.file.sync_all()?;
        Ok(())
    }

    /// Mark the last entry as committed and fsync.
    ///
    /// The committed byte is the final byte of the last entry, so we seek
    /// to one byte before EOF and overwrite it with `0x01`.
    ///
    /// Caller contract: `begin()` must have been called exactly once since
    /// the last `commit()` or `checkpoint()`. Calling `commit()` without a
    /// preceding `begin()` returns an error.
    pub fn commit(&mut self) -> Result<(), CryptoError> {
        let end = self.file.seek(SeekFrom::End(0))?;
        if end == 0 {
            return Err(CryptoError::VaultCorrupted(
                "WAL is empty, nothing to commit".into(),
            ));
        }

        // Verify the last entry is actually uncommitted
        self.file.seek(SeekFrom::End(-1))?;
        let mut flag = [0u8; 1];
        self.file.read_exact(&mut flag)?;
        if flag[0] != 0 {
            return Err(CryptoError::VaultCorrupted(
                "WAL commit called but last entry is already committed".into(),
            ));
        }

        // Overwrite committed flag
        self.file.seek(SeekFrom::End(-1))?;
        self.file.write_all(&[1u8])?;
        self.file.sync_all()?;
        Ok(())
    }

    /// Recover: read all entries and find the last uncommitted one.
    ///
    /// Returns `Some(old_encrypted_index)` if recovery is needed (caller
    /// should restore that index), `None` if the WAL is clean.
    pub fn recover(&mut self) -> Result<Option<Vec<u8>>, CryptoError> {
        self.file.seek(SeekFrom::Start(0))?;
        let mut all_bytes = Vec::new();
        self.file.read_to_end(&mut all_bytes)?;

        if all_bytes.is_empty() {
            return Ok(None);
        }

        let mut offset = 0;
        let mut last_uncommitted: Option<Vec<u8>> = None;

        while offset < all_bytes.len() {
            let remaining = &all_bytes[offset..];
            if remaining.len() < ENTRY_HEADER_SIZE + ENTRY_FOOTER_SIZE {
                // SAFETY: truncated tail means begin() was interrupted before
                // its fsync completed. The mutation hasn't started, so the
                // on-disk index is still consistent. Safe to ignore.
                break;
            }

            let entry = WalEntry::from_bytes(remaining)?;
            if !entry.committed {
                last_uncommitted = Some(entry.old_index_snapshot.clone());
            }
            offset += entry.on_disk_size();
        }

        Ok(last_uncommitted)
    }

    /// Checkpoint: truncate the WAL file after successful operations.
    pub fn checkpoint(&mut self) -> Result<(), CryptoError> {
        self.file.set_len(0)?;
        self.file.seek(SeekFrom::Start(0))?;
        self.file.sync_all()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// VaultLock
// ---------------------------------------------------------------------------

/// Advisory file lock to prevent concurrent vault access.
///
/// The lock is held for as long as the `VaultLock` exists. Dropping without
/// calling `release()` still releases the OS flock (the `File` is closed),
/// but the `.lock` file on disk is only cleaned up by `release()`.
#[frb(ignore)]
pub struct VaultLock {
    // Held open to keep the flock alive.
    lock_file: File,
    path: String,
}

impl std::fmt::Debug for VaultLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultLock")
            .field("path", &self.path)
            .finish()
    }
}

impl VaultLock {
    /// Acquire an advisory flock on `{vault_path}.lock`.
    ///
    /// Returns `CryptoError::VaultLocked` if already held by another process.
    pub fn acquire(vault_path: &str) -> Result<Self, CryptoError> {
        let path = format!("{vault_path}.lock");
        let file = File::create(&path)
            .map_err(|e| CryptoError::IoError(format!("cannot create lock file: {e}")))?;
        file.try_lock_exclusive()
            .map_err(|_| CryptoError::VaultLocked)?;
        Ok(Self {
            lock_file: file,
            path,
        })
    }

    /// Release the lock and remove the `.lock` file.
    pub fn release(self) -> Result<(), CryptoError> {
        self.lock_file
            .unlock()
            .map_err(|e| CryptoError::IoError(format!("unlock failed: {e}")))?;
        let _ = std::fs::remove_file(&self.path);
        Ok(())
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_index_data() -> Vec<u8> {
        vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]
    }

    // -- WalEntry -----------------------------------------------------------

    #[test]
    fn test_wal_entry_roundtrip() {
        let data = sample_index_data();
        let entry = WalEntry::new(WalOp::WriteSegment, data.clone());
        assert!(!entry.committed);

        let bytes = entry.to_bytes().expect("serialize");
        let parsed = WalEntry::from_bytes(&bytes).expect("parse");

        assert_eq!(parsed.op, WalOp::WriteSegment);
        assert_eq!(parsed.old_index_snapshot, data);
        assert_eq!(parsed.crc, entry.crc);
        assert!(!parsed.committed);
    }

    #[test]
    fn test_wal_entry_all_ops() {
        for op in [WalOp::WriteSegment, WalOp::DeleteSegment, WalOp::UpdateIndex] {
            let entry = WalEntry::new(op, vec![0x42]);
            let bytes = entry.to_bytes().expect("serialize");
            let parsed = WalEntry::from_bytes(&bytes).expect("parse");
            assert_eq!(parsed.op, op);
        }
    }

    #[test]
    fn test_wal_op_from_byte_invalid() {
        assert!(WalOp::from_byte(0xFF).is_err());
        assert!(WalOp::from_byte(0x00).is_err());
        assert!(WalOp::from_byte(0x04).is_err());
    }

    #[test]
    fn test_wal_entry_crc_corruption() {
        let entry = WalEntry::new(WalOp::WriteSegment, sample_index_data());
        let mut bytes = entry.to_bytes().expect("serialize");

        // Tamper with the CRC (4 bytes before the committed byte)
        let crc_pos = bytes.len() - 5;
        bytes[crc_pos] ^= 0xFF;

        let result = WalEntry::from_bytes(&bytes);
        assert!(result.is_err());
        if let Err(CryptoError::VaultCorrupted(msg)) = result {
            assert!(msg.contains("CRC mismatch"));
        }
    }

    #[test]
    fn test_wal_entry_data_corruption_detected_by_crc() {
        let entry = WalEntry::new(WalOp::WriteSegment, sample_index_data());
        let mut bytes = entry.to_bytes().expect("serialize");

        // Tamper with the data portion
        bytes[ENTRY_HEADER_SIZE] ^= 0xFF;

        let result = WalEntry::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_wal_entry_empty_data() {
        let entry = WalEntry::new(WalOp::UpdateIndex, Vec::new());
        let bytes = entry.to_bytes().expect("serialize");
        let parsed = WalEntry::from_bytes(&bytes).expect("parse");
        assert!(parsed.old_index_snapshot.is_empty());
        assert_eq!(parsed.op, WalOp::UpdateIndex);
    }

    #[test]
    fn test_wal_entry_too_short() {
        assert!(WalEntry::from_bytes(&[0x01]).is_err());
        assert!(WalEntry::from_bytes(&[]).is_err());
    }

    #[test]
    fn test_wal_entry_oversized_data_len_rejected() {
        // Craft a header claiming data_len > MAX_SNAPSHOT_SIZE
        let mut buf = vec![0x01u8]; // op = WriteSegment
        let huge_len = (MAX_SNAPSHOT_SIZE as u32) + 1;
        buf.extend_from_slice(&huge_len.to_le_bytes());
        // Pad with enough bytes so it doesn't fail on truncation first
        buf.resize(ENTRY_HEADER_SIZE + huge_len as usize + ENTRY_FOOTER_SIZE, 0);
        let result = WalEntry::from_bytes(&buf);
        assert!(result.is_err());
        if let Err(CryptoError::VaultCorrupted(msg)) = result {
            assert!(msg.contains("exceeds max"));
        }
    }

    // -- WriteAheadLog ------------------------------------------------------

    #[test]
    fn test_wal_begin_commit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_path = dir.path().join("test.vault");
        let vault_str = vault_path.to_str().expect("path");

        let mut wal = WriteAheadLog::open(vault_str).expect("open");
        wal.begin(WalOp::WriteSegment, &sample_index_data())
            .expect("begin");
        wal.commit().expect("commit");

        let recovery = wal.recover().expect("recover");
        assert!(recovery.is_none());
    }

    #[test]
    fn test_wal_recover_uncommitted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_path = dir.path().join("test.vault");
        let vault_str = vault_path.to_str().expect("path");

        let data = sample_index_data();
        {
            let mut wal = WriteAheadLog::open(vault_str).expect("open");
            wal.begin(WalOp::WriteSegment, &data).expect("begin");
            // No commit — simulates crash
        }

        // Reopen and recover
        let mut wal = WriteAheadLog::open(vault_str).expect("reopen");
        let recovery = wal.recover().expect("recover");
        assert!(recovery.is_some());
        assert_eq!(recovery.expect("snapshot"), data);
    }

    #[test]
    fn test_wal_recover_committed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_path = dir.path().join("test.vault");
        let vault_str = vault_path.to_str().expect("path");

        let mut wal = WriteAheadLog::open(vault_str).expect("open");
        wal.begin(WalOp::WriteSegment, &sample_index_data())
            .expect("begin");
        wal.commit().expect("commit");

        let recovery = wal.recover().expect("recover");
        assert!(recovery.is_none());
    }

    #[test]
    fn test_wal_crc_corruption_in_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_path = dir.path().join("test.vault");
        let vault_str = vault_path.to_str().expect("path");

        {
            let mut wal = WriteAheadLog::open(vault_str).expect("open");
            wal.begin(WalOp::WriteSegment, &sample_index_data())
                .expect("begin");
        }

        // Tamper with the WAL file CRC
        let wal_path = format!("{vault_str}.wal");
        let mut bytes = std::fs::read(&wal_path).expect("read");
        let crc_pos = bytes.len() - 5;
        bytes[crc_pos] ^= 0xFF;
        std::fs::write(&wal_path, &bytes).expect("write");

        let mut wal = WriteAheadLog::open(vault_str).expect("reopen");
        let result = wal.recover();
        assert!(result.is_err());
    }

    #[test]
    fn test_wal_checkpoint_truncates() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_path = dir.path().join("test.vault");
        let vault_str = vault_path.to_str().expect("path");

        let mut wal = WriteAheadLog::open(vault_str).expect("open");
        wal.begin(WalOp::WriteSegment, &sample_index_data())
            .expect("begin");
        wal.commit().expect("commit");
        wal.checkpoint().expect("checkpoint");

        // WAL file should be empty
        let wal_path = format!("{vault_str}.wal");
        let meta = std::fs::metadata(&wal_path).expect("meta");
        assert_eq!(meta.len(), 0);

        // Recover should find nothing
        let recovery = wal.recover().expect("recover");
        assert!(recovery.is_none());
    }

    #[test]
    fn test_wal_double_commit_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_path = dir.path().join("test.vault");
        let vault_str = vault_path.to_str().expect("path");

        let mut wal = WriteAheadLog::open(vault_str).expect("open");
        wal.begin(WalOp::WriteSegment, &sample_index_data())
            .expect("begin");
        wal.commit().expect("commit");

        // Second commit without begin should fail
        let result = wal.commit();
        assert!(result.is_err());
    }

    #[test]
    fn test_wal_multiple_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_path = dir.path().join("test.vault");
        let vault_str = vault_path.to_str().expect("path");

        let mut wal = WriteAheadLog::open(vault_str).expect("open");

        for i in 0u8..5 {
            wal.begin(WalOp::WriteSegment, &[i; 16])
                .expect("begin");
            wal.commit().expect("commit");
        }

        let recovery = wal.recover().expect("recover");
        assert!(recovery.is_none());
    }

    #[test]
    fn test_wal_multiple_entries_last_uncommitted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_path = dir.path().join("test.vault");
        let vault_str = vault_path.to_str().expect("path");

        let mut wal = WriteAheadLog::open(vault_str).expect("open");

        // Two committed, then one uncommitted
        wal.begin(WalOp::WriteSegment, &[0xAA; 16])
            .expect("begin");
        wal.commit().expect("commit");
        wal.begin(WalOp::DeleteSegment, &[0xBB; 16])
            .expect("begin");
        wal.commit().expect("commit");

        let crash_data = vec![0xCC; 16];
        wal.begin(WalOp::UpdateIndex, &crash_data).expect("begin");
        // No commit — simulates crash

        let recovery = wal.recover().expect("recover");
        assert!(recovery.is_some());
        assert_eq!(recovery.expect("snapshot"), crash_data);
    }

    // -- VaultLock ----------------------------------------------------------

    #[test]
    fn test_lock_acquire_release() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_path = dir.path().join("test.vault");
        let vault_str = vault_path.to_str().expect("path");

        let lock = VaultLock::acquire(vault_str).expect("acquire");
        lock.release().expect("release");
    }

    #[test]
    fn test_lock_double_acquire_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_path = dir.path().join("test.vault");
        let vault_str = vault_path.to_str().expect("path");

        let _lock = VaultLock::acquire(vault_str).expect("acquire");
        let result = VaultLock::acquire(vault_str);
        assert!(result.is_err());
        match result {
            Err(CryptoError::VaultLocked) => {} // expected
            other => panic!("expected VaultLocked, got {other:?}"),
        }
    }

    #[test]
    fn test_lock_release_allows_reacquire() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_path = dir.path().join("test.vault");
        let vault_str = vault_path.to_str().expect("path");

        let lock = VaultLock::acquire(vault_str).expect("acquire");
        lock.release().expect("release");

        let lock2 = VaultLock::acquire(vault_str).expect("reacquire");
        lock2.release().expect("release");
    }

    #[test]
    fn test_lock_file_cleanup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_path = dir.path().join("test.vault");
        let vault_str = vault_path.to_str().expect("path");
        let lock_path = format!("{vault_str}.lock");

        let lock = VaultLock::acquire(vault_str).expect("acquire");
        assert!(std::path::Path::new(&lock_path).exists());

        lock.release().expect("release");
        assert!(!std::path::Path::new(&lock_path).exists());
    }
}
