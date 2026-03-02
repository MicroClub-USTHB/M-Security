//! Zstd compression wrapper.

use crate::core::error::CryptoError;

pub const DEFAULT_LEVEL: i32 = 3;
// zstd treats level 0 as "use library default" — we reject it
// to force callers to choose explicitly or use None.
pub const MIN_LEVEL: i32 = 1;
pub const MAX_LEVEL: i32 = 22;

pub fn validate_level(level: i32) -> Result<(), CryptoError> {
    if !(MIN_LEVEL..=MAX_LEVEL).contains(&level) {
        return Err(CryptoError::InvalidParameter(format!(
            "Zstd level must be {MIN_LEVEL}–{MAX_LEVEL}, got {level}"
        )));
    }
    Ok(())
}

pub fn compress(data: &[u8], level: i32) -> Result<Vec<u8>, CryptoError> {
    validate_level(level)?;
    zstd::encode_all(std::io::Cursor::new(data), level)
        .map_err(|e| CryptoError::CompressionFailed(e.to_string()))
}

pub fn decompress(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    zstd::decode_all(std::io::Cursor::new(data))
        .map_err(|e| CryptoError::CompressionFailed(e.to_string()))
}
