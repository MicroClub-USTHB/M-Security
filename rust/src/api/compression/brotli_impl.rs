//! Brotli compression wrapper.

use crate::core::error::CryptoError;

pub const DEFAULT_LEVEL: u32 = 4;
pub const MIN_LEVEL: u32 = 0;
pub const MAX_LEVEL: u32 = 11;

pub fn validate_level(level: u32) -> Result<(), CryptoError> {
    if level > MAX_LEVEL {
        return Err(CryptoError::InvalidParameter(format!(
            "Brotli level must be {MIN_LEVEL}–{MAX_LEVEL}, got {level}"
        )));
    }
    Ok(())
}

pub fn compress(data: &[u8], level: u32) -> Result<Vec<u8>, CryptoError> {
    validate_level(level)?;
    let mut output = Vec::new();
    {
        let params = brotli::enc::BrotliEncoderParams {
            quality: level as i32,
            ..Default::default()
        };
        let mut writer = brotli::CompressorWriter::with_params(&mut output, 4096, &params);
        std::io::Write::write_all(&mut writer, data)
            .map_err(|e| CryptoError::CompressionFailed(e.to_string()))?;
    }
    Ok(output)
}

pub fn decompress(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut output = Vec::new();
    let mut reader = brotli::Decompressor::new(std::io::Cursor::new(data), 4096);
    std::io::Read::read_to_end(&mut reader, &mut output)
        .map_err(|e| CryptoError::CompressionFailed(e.to_string()))?;
    Ok(output)
}
