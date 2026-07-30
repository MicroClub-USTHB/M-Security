import 'package:m_security/src/rust/api/compression.dart';
import 'package:m_security/src/rust/api/encryption.dart' as rust_encryption;
import 'package:m_security/src/rust/core/error.dart';

/// Compressed streaming file operations.
///
/// Both are disabled in this release. They wrote and read the same encrypted
/// stream format as the plain streaming methods, whose header is unauthenticated
/// and whose chunks are bound to nothing but their index and finality, so a
/// chunk from another stream encrypted under the same handle splices in. The
/// native entry points are gone and the methods below fail before touching
/// either path.
class CompressionService {
  CompressionService._();

  /// Disabled. Kept so existing code still compiles.
  ///
  /// Emits one disabled-format error before reading [inputPath] or creating
  /// [outputPath].
  static Stream<double> compressAndEncryptFile({
    required String inputPath,
    required String outputPath,
    required rust_encryption.CipherHandle cipher,
    CompressionConfig config = const CompressionConfig(
      algorithm: CompressionAlgorithm.zstd,
    ),
  }) {
    return Stream<double>.error(
      const CryptoError.disabledFormat('compressed encrypted stream write'),
    );
  }

  /// Disabled. Kept so existing code still compiles.
  ///
  /// Emits one disabled-format error before reading [inputPath] or creating
  /// [outputPath].
  static Stream<double> decryptAndDecompressFile({
    required String inputPath,
    required String outputPath,
    required rust_encryption.CipherHandle cipher,
  }) {
    return Stream<double>.error(
      const CryptoError.disabledFormat('compressed encrypted stream read'),
    );
  }
}
