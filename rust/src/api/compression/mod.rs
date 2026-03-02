//! Compression API module — Zstd, Brotli, and MIME-aware skip.

#[cfg(feature = "compression")]
pub mod brotli_impl;
#[cfg(feature = "compression")]
pub mod zstd_impl;

#[cfg(feature = "compression")]
use crate::core::error::CryptoError;

/// Which compression algorithm to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionAlgorithm {
    Zstd,
    Brotli,
    None,
}

impl CompressionAlgorithm {
    /// Serialize to the byte stored in the stream header.
    pub fn to_u8(self) -> u8 {
        match self {
            Self::None => 0x00,
            Self::Zstd => 0x01,
            Self::Brotli => 0x02,
        }
    }

    /// Deserialize from the byte stored in the stream header.
    #[cfg(feature = "compression")]
    pub fn from_u8(byte: u8) -> Result<Self, CryptoError> {
        match byte {
            0x00 => Ok(Self::None),
            0x01 => Ok(Self::Zstd),
            0x02 => Ok(Self::Brotli),
            other => Err(CryptoError::InvalidParameter(format!(
                "Unknown compression algorithm byte: {other:#04x}"
            ))),
        }
    }
}

/// Configuration for a compress operation.
#[derive(Debug, Clone)]
pub struct CompressionConfig {
    pub algorithm: CompressionAlgorithm,
    /// Compression level. Valid range depends on algorithm:
    /// - Zstd: 1–22 (default 3)
    /// - Brotli: 0–11 (default 4)
    /// - None: ignored
    pub level: Option<i32>,
}

/// Compress a byte buffer according to `config`.
#[cfg(feature = "compression")]
pub fn compress(data: &[u8], config: &CompressionConfig) -> Result<Vec<u8>, CryptoError> {
    match config.algorithm {
        CompressionAlgorithm::Zstd => {
            let level = config.level.unwrap_or(zstd_impl::DEFAULT_LEVEL);
            zstd_impl::compress(data, level)
        }
        CompressionAlgorithm::Brotli => {
            let level = config.level.unwrap_or(brotli_impl::DEFAULT_LEVEL as i32);
            let level = u32::try_from(level).map_err(|_| {
                CryptoError::InvalidParameter(format!(
                    "Brotli level must be {}–{}, got {level}",
                    brotli_impl::MIN_LEVEL,
                    brotli_impl::MAX_LEVEL
                ))
            })?;
            brotli_impl::compress(data, level)
        }
        CompressionAlgorithm::None => Ok(data.to_vec()),
    }
}

/// Decompress a byte buffer produced by the given algorithm.
#[cfg(feature = "compression")]
pub fn decompress(data: &[u8], algorithm: CompressionAlgorithm) -> Result<Vec<u8>, CryptoError> {
    match algorithm {
        CompressionAlgorithm::Zstd => zstd_impl::decompress(data),
        CompressionAlgorithm::Brotli => brotli_impl::decompress(data),
        CompressionAlgorithm::None => Ok(data.to_vec()),
    }
}

/// Returns `true` when the file extension indicates already-compressed data.
pub fn should_skip_compression(file_path: &str) -> bool {
    const SKIP: &[&str] = &[
        // images
        "jpg", "jpeg", "png", "gif", "webp",
        // video
        "mp4", "mkv", "avi", "mov", "webm",
        // audio
        "mp3", "aac", "ogg", "flac",
        // archives
        "zip", "gz", "bz2", "xz", "zst", "br", "7z", "rar",
    ];

    file_path
        .rsplit('.')
        .next()
        .map(|ext| SKIP.contains(&ext.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

#[cfg(all(test, feature = "compression"))]
mod tests {
    use super::*;

    // -- roundtrip --------------------------------------------------------

    #[test]
    fn test_zstd_roundtrip() {
        let data = b"Hello, Zstd compression roundtrip!";
        let config = CompressionConfig {
            algorithm: CompressionAlgorithm::Zstd,
            level: None,
        };
        let compressed = compress(data, &config).expect("zstd compress");
        let decompressed =
            decompress(&compressed, CompressionAlgorithm::Zstd).expect("zstd decompress");
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_brotli_roundtrip() {
        let data = b"Hello, Brotli compression roundtrip!";
        let config = CompressionConfig {
            algorithm: CompressionAlgorithm::Brotli,
            level: None,
        };
        let compressed = compress(data, &config).expect("brotli compress");
        let decompressed =
            decompress(&compressed, CompressionAlgorithm::Brotli).expect("brotli decompress");
        assert_eq!(decompressed, data);
    }

    // -- custom levels ----------------------------------------------------

    #[test]
    fn test_zstd_custom_level() {
        let data = b"level test data for zstd";
        for level in [1, 19] {
            let config = CompressionConfig {
                algorithm: CompressionAlgorithm::Zstd,
                level: Some(level),
            };
            let compressed = compress(data, &config).expect("zstd compress");
            let decompressed =
                decompress(&compressed, CompressionAlgorithm::Zstd).expect("zstd decompress");
            assert_eq!(decompressed, data);
        }
    }

    #[test]
    fn test_brotli_custom_level() {
        let data = b"level test data for brotli";
        for level in [0, 11] {
            let config = CompressionConfig {
                algorithm: CompressionAlgorithm::Brotli,
                level: Some(level),
            };
            let compressed = compress(data, &config).expect("brotli compress");
            let decompressed =
                decompress(&compressed, CompressionAlgorithm::Brotli).expect("brotli decompress");
            assert_eq!(decompressed, data);
        }
    }

    // -- level validation -------------------------------------------------

    #[test]
    fn test_zstd_invalid_level() {
        let config = CompressionConfig {
            algorithm: CompressionAlgorithm::Zstd,
            level: Some(0),
        };
        assert!(compress(b"x", &config).is_err());

        let config = CompressionConfig {
            algorithm: CompressionAlgorithm::Zstd,
            level: Some(23),
        };
        assert!(compress(b"x", &config).is_err());
    }

    #[test]
    fn test_brotli_invalid_level() {
        let config = CompressionConfig {
            algorithm: CompressionAlgorithm::Brotli,
            level: Some(12),
        };
        assert!(compress(b"x", &config).is_err());

        let config = CompressionConfig {
            algorithm: CompressionAlgorithm::Brotli,
            level: Some(-1),
        };
        assert!(compress(b"x", &config).is_err());
    }

    // -- None passthrough -------------------------------------------------

    #[test]
    fn test_none_passthrough() {
        let data = b"should stay the same";
        let config = CompressionConfig {
            algorithm: CompressionAlgorithm::None,
            level: None,
        };
        let result = compress(data, &config).expect("none compress");
        assert_eq!(result, data);

        let result = decompress(data, CompressionAlgorithm::None).expect("none decompress");
        assert_eq!(result, data);
    }

    // -- MIME-aware skip --------------------------------------------------

    #[test]
    fn test_should_skip_compressed_extensions() {
        assert!(should_skip_compression("photo.jpg"));
        assert!(should_skip_compression("photo.JPEG"));
        assert!(should_skip_compression("archive.zip"));
        assert!(should_skip_compression("archive.ZIP"));
        assert!(should_skip_compression("video.mp4"));
        assert!(should_skip_compression("VIDEO.MP4"));
        assert!(should_skip_compression("SONG.MP3"));
    }

    #[test]
    fn test_should_not_skip_uncompressed_extensions() {
        assert!(!should_skip_compression("notes.txt"));
        assert!(!should_skip_compression("data.json"));
        assert!(!should_skip_compression("report.pdf"));
    }

    // -- empty data -------------------------------------------------------

    #[test]
    fn test_empty_data() {
        let empty: &[u8] = &[];

        let config_zstd = CompressionConfig {
            algorithm: CompressionAlgorithm::Zstd,
            level: None,
        };
        let compressed = compress(empty, &config_zstd).expect("zstd compress empty");
        let decompressed =
            decompress(&compressed, CompressionAlgorithm::Zstd).expect("zstd decompress empty");
        assert!(decompressed.is_empty());

        let config_brotli = CompressionConfig {
            algorithm: CompressionAlgorithm::Brotli,
            level: None,
        };
        let compressed = compress(empty, &config_brotli).expect("brotli compress empty");
        let decompressed = decompress(&compressed, CompressionAlgorithm::Brotli)
            .expect("brotli decompress empty");
        assert!(decompressed.is_empty());
    }
}
