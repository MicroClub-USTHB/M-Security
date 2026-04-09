use super::*;
use crate::core::evfs::format::{encrypted_index_size, MIN_INDEX_PAD_SIZE};

pub(super) fn test_key() -> Vec<u8> {
    vec![0xAA; 32]
}

pub(super) fn test_key2() -> Vec<u8> {
    vec![0xAB; 32]
}

pub(super) fn wrong_key() -> Vec<u8> {
    vec![0xBB; 32]
}

pub(super) fn create_test_vault(dir: &tempfile::TempDir, capacity: u64) -> VaultHandle {
    let path = dir
        .path()
        .join("test.vault")
        .to_str()
        .expect("path")
        .to_string();
    vault_create(path, test_key(), "aes-256-gcm".into(), capacity).expect("create vault")
}

pub(super) fn vault_path(dir: &tempfile::TempDir) -> String {
    dir.path()
        .join("test.vault")
        .to_str()
        .expect("path")
        .to_string()
}

pub(super) const SIZE_MB: u64 = 0x100000;

/// Helper: stream-write data in fixed-size pieces.
pub(super) fn stream_write_chunks(
    handle: &mut VaultHandle,
    name: &str,
    data: &[u8],
    piece_size: usize,
) -> Result<(), CryptoError> {
    let chunks: Vec<Vec<u8>> = data.chunks(piece_size).map(|c| c.to_vec()).collect();
    vault_write_stream(
        handle,
        name.to_string(),
        data.len() as u64,
        chunks.into_iter(),
        None,
    )
}

mod crud;
mod compression;
mod allocator;
mod delete;
mod resize;
mod defragment;
mod streaming;
mod rotation;
mod export_import;
mod index_cache;
mod parallel;
mod rename;
mod metadata;
