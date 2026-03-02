//! Streaming compression/decompression wrappers for the chunk pipeline.
//!
//! These wrap zstd and brotli in a uniform interface that accepts incremental
//! input and appends compressed/decompressed bytes to an output buffer.

use std::io::Write;

use crate::api::compression::CompressionAlgorithm;
use crate::core::error::CryptoError;

// -- Compressor trait ---------------------------------------------------------

pub trait CompressorOp {
    /// Feed plaintext in, append compressed bytes to `out`.
    fn compress_chunk(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), CryptoError>;

    /// Signal EOF — flush remaining compressed bytes to `out`.
    fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), CryptoError>;
}

pub trait DecompressorOp {
    /// Feed compressed bytes in, append decompressed bytes to `out`.
    fn decompress_chunk(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), CryptoError>;

    /// Signal EOF — flush remaining decompressed bytes to `out`.
    fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), CryptoError>;
}

// -- Factory ------------------------------------------------------------------

pub fn new_compressor(
    algo: CompressionAlgorithm,
    level: Option<i32>,
) -> Result<Box<dyn CompressorOp>, CryptoError> {
    match algo {
        CompressionAlgorithm::Zstd => {
            let level = level.unwrap_or(super::zstd_impl::DEFAULT_LEVEL);
            super::zstd_impl::validate_level(level)?;
            Ok(Box::new(ZstdCompressor::new(level)?))
        }
        CompressionAlgorithm::Brotli => {
            let level = level.unwrap_or(super::brotli_impl::DEFAULT_LEVEL as i32);
            let level = u32::try_from(level).map_err(|_| {
                CryptoError::InvalidParameter(format!(
                    "Brotli level must be non-negative, got {level}"
                ))
            })?;
            super::brotli_impl::validate_level(level)?;
            Ok(Box::new(BrotliCompressor::new(level)))
        }
        CompressionAlgorithm::None => Ok(Box::new(PassthroughCodec)),
    }
}

pub fn new_decompressor(
    algo: CompressionAlgorithm,
) -> Result<Box<dyn DecompressorOp>, CryptoError> {
    match algo {
        CompressionAlgorithm::Zstd => Ok(Box::new(ZstdDecompressor::new()?)),
        CompressionAlgorithm::Brotli => Ok(Box::new(BrotliDecompressor::new())),
        CompressionAlgorithm::None => Ok(Box::new(PassthroughCodec)),
    }
}

// -- Passthrough (CompressionAlgorithm::None) ---------------------------------

struct PassthroughCodec;

impl CompressorOp for PassthroughCodec {
    fn compress_chunk(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), CryptoError> {
        out.extend_from_slice(input);
        Ok(())
    }
    fn finish(&mut self, _out: &mut Vec<u8>) -> Result<(), CryptoError> {
        Ok(())
    }
}

impl DecompressorOp for PassthroughCodec {
    fn decompress_chunk(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), CryptoError> {
        out.extend_from_slice(input);
        Ok(())
    }
    fn finish(&mut self, _out: &mut Vec<u8>) -> Result<(), CryptoError> {
        Ok(())
    }
}

// -- Zstd streaming -----------------------------------------------------------

struct ZstdCompressor<'a> {
    encoder: zstd::stream::raw::Encoder<'a>,
}

impl<'a> ZstdCompressor<'a> {
    fn new(level: i32) -> Result<Self, CryptoError> {
        let encoder = zstd::stream::raw::Encoder::new(level)
            .map_err(|e| CryptoError::CompressionFailed(format!("Zstd encoder init: {e}")))?;
        Ok(Self { encoder })
    }
}

impl CompressorOp for ZstdCompressor<'_> {
    fn compress_chunk(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), CryptoError> {
        use zstd::stream::raw::Operation;

        let mut src = input;
        loop {
            let prev_len = out.len();
            out.resize(prev_len + zstd::zstd_safe::CCtx::out_size(), 0);
            let status = self
                .encoder
                .run_on_buffers(src, &mut out[prev_len..])
                .map_err(|e| CryptoError::CompressionFailed(format!("Zstd compress: {e}")))?;
            out.truncate(prev_len + status.bytes_written);
            src = &src[status.bytes_read..];
            if src.is_empty() {
                break;
            }
        }
        Ok(())
    }

    fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), CryptoError> {
        use zstd::stream::raw::{Operation, OutBuffer};

        loop {
            let mut buf = vec![0u8; zstd::zstd_safe::CCtx::out_size()];
            let mut ob = OutBuffer::around(&mut buf);
            let remaining = self
                .encoder
                .finish(&mut ob, true)
                .map_err(|e| CryptoError::CompressionFailed(format!("Zstd finish: {e}")))?;
            let written = ob.pos();
            out.extend_from_slice(&buf[..written]);
            if remaining == 0 {
                break;
            }
        }
        Ok(())
    }
}

struct ZstdDecompressor<'a> {
    decoder: zstd::stream::raw::Decoder<'a>,
}

impl<'a> ZstdDecompressor<'a> {
    fn new() -> Result<Self, CryptoError> {
        let decoder = zstd::stream::raw::Decoder::new()
            .map_err(|e| CryptoError::CompressionFailed(format!("Zstd decoder init: {e}")))?;
        Ok(Self { decoder })
    }
}

impl DecompressorOp for ZstdDecompressor<'_> {
    fn decompress_chunk(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), CryptoError> {
        use zstd::stream::raw::Operation;

        let mut src = input;
        loop {
            let prev_len = out.len();
            out.resize(prev_len + zstd::zstd_safe::DCtx::out_size(), 0);
            let status = self
                .decoder
                .run_on_buffers(src, &mut out[prev_len..])
                .map_err(|e| CryptoError::CompressionFailed(format!("Zstd decompress: {e}")))?;
            out.truncate(prev_len + status.bytes_written);
            src = &src[status.bytes_read..];
            if src.is_empty() {
                break;
            }
        }
        Ok(())
    }

    fn finish(&mut self, _out: &mut Vec<u8>) -> Result<(), CryptoError> {
        Ok(())
    }
}

// -- Brotli streaming ---------------------------------------------------------
//
// Brotli's CompressorWriter<W: Write> wraps a W and writes compressed bytes
// to it. We use Vec<u8> as the inner writer — `compress_chunk` writes input
// through the compressor, `finish` drops it to flush the final frame.

struct BrotliCompressor {
    // Option so we can take() in finish() to trigger Drop/flush
    inner: Option<brotli::CompressorWriter<Vec<u8>>>,
}

impl BrotliCompressor {
    fn new(level: u32) -> Self {
        let params = brotli::enc::BrotliEncoderParams {
            quality: level as i32,
            ..Default::default()
        };
        let writer =
            brotli::CompressorWriter::with_params(Vec::with_capacity(64 * 1024), 4096, &params);
        Self {
            inner: Some(writer),
        }
    }
}

impl CompressorOp for BrotliCompressor {
    fn compress_chunk(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), CryptoError> {
        let w = self.inner.as_mut().ok_or_else(|| {
            CryptoError::CompressionFailed("Brotli compressor already finished".into())
        })?;
        w.write_all(input)
            .map_err(|e| CryptoError::CompressionFailed(format!("Brotli compress: {e}")))?;
        // Brotli buffers internally — compressed bytes appear in the inner Vec
        // once enough data accumulates or on flush/drop.
        // Drain whatever compressed bytes are available so far.
        let inner_vec = w.get_ref();
        if !inner_vec.is_empty() {
            out.extend_from_slice(inner_vec);
            w.get_mut().clear();
        }
        Ok(())
    }

    fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), CryptoError> {
        let w = self.inner.take().ok_or_else(|| {
            CryptoError::CompressionFailed("Brotli compressor already finished".into())
        })?;
        // into_inner() flushes the brotli stream and returns the inner Vec
        let compressed = w.into_inner();
        out.extend_from_slice(&compressed);
        Ok(())
    }
}

struct BrotliDecompressor {
    // DecompressorWriter: write compressed bytes IN, decompressed bytes go to
    // the inner Vec<u8>. Truly streaming — no whole-file buffering.
    inner: Option<brotli::DecompressorWriter<Vec<u8>>>,
}

impl BrotliDecompressor {
    fn new() -> Self {
        Self {
            inner: Some(brotli::DecompressorWriter::new(
                Vec::with_capacity(64 * 1024),
                4096,
            )),
        }
    }
}

impl DecompressorOp for BrotliDecompressor {
    fn decompress_chunk(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(), CryptoError> {
        let w = self.inner.as_mut().ok_or_else(|| {
            CryptoError::CompressionFailed("Brotli decompressor already finished".into())
        })?;
        w.write_all(input)
            .map_err(|e| CryptoError::CompressionFailed(format!("Brotli decompress: {e}")))?;
        // Drain decompressed bytes that appeared in the inner Vec
        let inner_vec = w.get_ref();
        if !inner_vec.is_empty() {
            out.extend_from_slice(inner_vec);
            w.get_mut().clear();
        }
        Ok(())
    }

    fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), CryptoError> {
        let w = self.inner.take().ok_or_else(|| {
            CryptoError::CompressionFailed("Brotli decompressor already finished".into())
        })?;
        // into_inner() flushes remaining decompressed data to the inner Vec
        let remaining = w.into_inner().map_err(|_| {
            CryptoError::CompressionFailed("Brotli decompressor flush failed".into())
        })?;
        if !remaining.is_empty() {
            out.extend_from_slice(&remaining);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zstd_streaming_roundtrip() {
        let input = b"Hello zstd streaming compression! ".repeat(1000);
        let mut compressed = Vec::new();

        let mut c = new_compressor(CompressionAlgorithm::Zstd, None).unwrap();
        c.compress_chunk(&input[..500], &mut compressed).unwrap();
        c.compress_chunk(&input[500..], &mut compressed).unwrap();
        c.finish(&mut compressed).unwrap();

        let mut decompressed = Vec::new();
        let mut d = new_decompressor(CompressionAlgorithm::Zstd).unwrap();
        d.decompress_chunk(&compressed, &mut decompressed).unwrap();
        d.finish(&mut decompressed).unwrap();

        assert_eq!(decompressed, input);
    }

    #[test]
    fn test_brotli_streaming_roundtrip() {
        let input = b"Hello brotli streaming compression! ".repeat(1000);
        let mut compressed = Vec::new();

        let mut c = new_compressor(CompressionAlgorithm::Brotli, None).unwrap();
        c.compress_chunk(&input[..500], &mut compressed).unwrap();
        c.compress_chunk(&input[500..], &mut compressed).unwrap();
        c.finish(&mut compressed).unwrap();

        let mut decompressed = Vec::new();
        let mut d = new_decompressor(CompressionAlgorithm::Brotli).unwrap();
        d.decompress_chunk(&compressed, &mut decompressed).unwrap();
        d.finish(&mut decompressed).unwrap();

        assert_eq!(decompressed, input);
    }

    #[test]
    fn test_none_streaming_passthrough() {
        let input = b"passthrough data";
        let mut out = Vec::new();

        let mut c = new_compressor(CompressionAlgorithm::None, None).unwrap();
        c.compress_chunk(input, &mut out).unwrap();
        c.finish(&mut out).unwrap();
        assert_eq!(out, input);

        let mut dec_out = Vec::new();
        let mut d = new_decompressor(CompressionAlgorithm::None).unwrap();
        d.decompress_chunk(&out, &mut dec_out).unwrap();
        d.finish(&mut dec_out).unwrap();
        assert_eq!(dec_out, input);
    }

    #[test]
    fn test_empty_input() {
        for algo in [
            CompressionAlgorithm::Zstd,
            CompressionAlgorithm::Brotli,
            CompressionAlgorithm::None,
        ] {
            let mut compressed = Vec::new();
            let mut c = new_compressor(algo, None).unwrap();
            c.finish(&mut compressed).unwrap();

            let mut decompressed = Vec::new();
            let mut d = new_decompressor(algo).unwrap();
            if !compressed.is_empty() {
                d.decompress_chunk(&compressed, &mut decompressed).unwrap();
            }
            d.finish(&mut decompressed).unwrap();
            assert!(decompressed.is_empty(), "algo={algo:?}");
        }
    }
}
