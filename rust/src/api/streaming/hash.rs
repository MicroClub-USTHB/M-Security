//! Streaming file hashing (no encryption padding).

use std::fs::File;
use std::io::BufReader;

use crate::api::hashing::HasherHandle;
use crate::core::error::CryptoError;
use crate::core::streaming::CHUNK_SIZE;

use super::read_full;

/// Feed an entire file into the hasher in 64KB chunks. Does NOT finalize.
///
/// Resets the hasher first to ensure a clean state, then feeds raw file bytes
/// (no padding). Caller must call `finalize_raw()` / `hasherFinalize()` to
/// obtain the digest.
pub(crate) fn hash_file_feed(
    hasher: &HasherHandle,
    file_path: &str,
    on_progress: &dyn Fn(f64),
) -> Result<(), CryptoError> {
    hasher.reset_raw()?;

    let file = File::open(file_path)
        .map_err(|e| CryptoError::IoError(format!("Cannot open input '{file_path}': {e}")))?;
    let file_size = file
        .metadata()
        .map_err(|e| CryptoError::IoError(format!("Cannot stat input: {e}")))?
        .len();

    let mut reader = BufReader::new(file);
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut bytes_hashed: u64 = 0;

    loop {
        let n = read_full(&mut reader, &mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update_raw(&buf[..n])?;
        bytes_hashed += n as u64;
        if file_size > 0 {
            on_progress((bytes_hashed as f64 / file_size as f64).min(0.99));
        }
    }

    on_progress(1.0);
    Ok(())
}

/// Hash a file in streaming 64KB chunks (feed + finalize).
///
/// Convenience wrapper: feeds the entire file then finalizes.
#[cfg(test)]
pub(crate) fn hash_file_impl(
    hasher: &HasherHandle,
    file_path: &str,
    on_progress: &dyn Fn(f64),
) -> Result<Vec<u8>, CryptoError> {
    hash_file_feed(hasher, file_path, on_progress)?;
    hasher.finalize_raw()
}
