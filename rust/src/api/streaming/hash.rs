//! Streaming file hashing with 64KB chunks.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::api::hashing::blake3::Blake3Hasher;
use crate::api::hashing::sha3::Sha3Hasher;
use crate::core::error::CryptoError;
use crate::core::traits::Hasher;

use super::{StreamHashAlgorithm, StreamProgress, DEFAULT_CHUNK_SIZE};

/// Streaming file hash — processes in 64KB chunks with constant memory.
pub(crate) fn stream_hash_impl(
    input_path: &Path,
    algorithm: StreamHashAlgorithm,
    mut on_progress: impl FnMut(&StreamProgress),
) -> Result<Vec<u8>, CryptoError> {
    let mut input = File::open(input_path)?;
    let file_size = input.metadata()?.len();

    let chunk_size = DEFAULT_CHUNK_SIZE as u64;
    let total_chunks = if file_size == 0 {
        0
    } else {
        file_size.div_ceil(chunk_size)
    };

    let mut hasher: Box<dyn Hasher> = match algorithm {
        StreamHashAlgorithm::Blake3 => Box::new(Blake3Hasher::new()),
        StreamHashAlgorithm::Sha3 => Box::new(Sha3Hasher::new()),
    };

    let mut buf = vec![0u8; DEFAULT_CHUNK_SIZE as usize];
    let mut bytes_processed: u64 = 0;
    let mut remaining = file_size;

    for chunk_idx in 0..total_chunks {
        let to_read = std::cmp::min(remaining, chunk_size) as usize;
        input.read_exact(&mut buf[..to_read])?;

        hasher.update(&buf[..to_read])?;
        bytes_processed += to_read as u64;
        remaining -= to_read as u64;

        on_progress(&StreamProgress {
            bytes_processed,
            total_bytes: file_size,
            chunks_completed: chunk_idx + 1,
            total_chunks,
        });
    }

    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp_file(data: &[u8]) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(data).expect("write");
        f.flush().expect("flush");
        f
    }

    #[test]
    fn stream_blake3_matches_oneshot() {
        let data = b"hello world, streaming hash test!";
        let input = write_temp_file(data);

        let stream_digest =
            stream_hash_impl(input.path(), StreamHashAlgorithm::Blake3, |_| {}).expect("hash");

        let oneshot = crate::api::hashing::blake3_hash(data.to_vec());
        assert_eq!(stream_digest, oneshot);
    }

    #[test]
    fn stream_sha3_matches_oneshot() {
        let data = b"hello world, streaming hash test!";
        let input = write_temp_file(data);

        let stream_digest =
            stream_hash_impl(input.path(), StreamHashAlgorithm::Sha3, |_| {}).expect("hash");

        let oneshot = crate::api::hashing::sha3_hash(data.to_vec());
        assert_eq!(stream_digest, oneshot);
    }

    #[test]
    fn stream_hash_multi_chunk() {
        let data = vec![0x42u8; DEFAULT_CHUNK_SIZE as usize * 3 + 1000];
        let input = write_temp_file(&data);

        let mut progress_updates = Vec::new();
        let stream_digest = stream_hash_impl(input.path(), StreamHashAlgorithm::Blake3, |p| {
            progress_updates.push(p.clone());
        })
        .expect("hash");

        let oneshot = crate::api::hashing::blake3_hash(data);
        assert_eq!(stream_digest, oneshot);
        assert_eq!(progress_updates.len(), 4);
    }

    #[test]
    fn stream_hash_empty_file() {
        let input = write_temp_file(b"");

        let stream_digest =
            stream_hash_impl(input.path(), StreamHashAlgorithm::Blake3, |_| {}).expect("hash");

        let oneshot = crate::api::hashing::blake3_hash(vec![]);
        assert_eq!(stream_digest, oneshot);
    }

    #[test]
    fn progress_chunks_never_exceed_total() {
        let data = vec![0x42u8; DEFAULT_CHUNK_SIZE as usize * 2 + 500];
        let input = write_temp_file(&data);

        let mut progress_updates = Vec::new();
        stream_hash_impl(input.path(), StreamHashAlgorithm::Blake3, |p| {
            progress_updates.push(p.clone());
        })
        .expect("hash");

        for p in &progress_updates {
            assert!(p.chunks_completed <= p.total_chunks);
        }
    }
}
