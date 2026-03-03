import 'package:m_security/src/rust/api/compression/mod.dart';
import 'package:m_security/src/rust/api/streaming/mod.dart';
import 'package:m_security/src/rust/frb_generated.dart';

class CompressionService {
  /// Compress then encrypt a file.
  /// Returns a stream of progress values (0.0 to 1.0).
  Stream compressAndEncryptFile({
    required String inputPath,
    required String outputPath,
    required CipherHandle cipher,
    CompressionConfig config = const CompressionConfig(
      algorithm: CompressionAlgorithm.zstd,
      level: null,
    ),
  }) {
    return streamCompressEncryptFile(
      cipher: cipher,
      compression: config,
      inputPath: inputPath,
      outputPath: outputPath,
    );
  }

  /// Decrypt then decompress a file.
  /// Algorithm is read from the encrypted file header — no config needed.
  Stream decryptAndDecompressFile({
    required String inputPath,
    required String outputPath,
    required CipherHandle cipher,
  }) {
    return streamDecryptDecompressFile(
      cipher: cipher,
      inputPath: inputPath,
      outputPath: outputPath,
    );
  }
}