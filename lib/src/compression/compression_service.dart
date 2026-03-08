import 'dart:async';

import 'package:m_security/src/rust/api/compression.dart';
import 'package:m_security/src/rust/api/encryption.dart' as rust_encryption;
import 'package:m_security/src/rust/api/streaming.dart' as rust_streaming;

/// Compressed streaming file operations (compress+encrypt, decrypt+decompress).
///
/// Uses stream-compress-then-chunk: input is compressed as a stream, then
/// the compressed bytes are chunked and encrypted. Decompression algorithm
/// is stored in the file header — decrypt needs no config.
class CompressionService {
  CompressionService._();

  /// Compress then encrypt a file.
  /// Returns a Stream of progress (0.0 to 1.0).
  static Stream<double> compressAndEncryptFile({
    required String inputPath,
    required String outputPath,
    required rust_encryption.CipherHandle cipher,
    CompressionConfig config = const CompressionConfig(
      algorithm: CompressionAlgorithm.zstd,
    ),
  }) {
    return _guardedStream(
      () => rust_streaming.streamCompressEncryptFile(
        cipher: cipher,
        compression: config,
        inputPath: inputPath,
        outputPath: outputPath,
      ),
    );
  }

  /// Decrypt then decompress a file.
  /// Algorithm is read from the encrypted file header — no config needed.
  static Stream<double> decryptAndDecompressFile({
    required String inputPath,
    required String outputPath,
    required rust_encryption.CipherHandle cipher,
  }) {
    return _guardedStream(
      () => rust_streaming.streamDecryptDecompressFile(
        cipher: cipher,
        inputPath: inputPath,
        outputPath: outputPath,
      ),
    );
  }

  static Stream<double> _guardedStream(Stream<double> Function() factory) {
    final controller = StreamController<double>();
    runZonedGuarded(
      () {
        factory().listen(
          controller.add,
          onError: controller.addError,
          onDone: () {
            Future(() {
              if (!controller.isClosed) controller.close();
            });
          },
        );
      },
      (error, stack) {
        if (!controller.isClosed) {
          controller.addError(error, stack);
          controller.close();
        }
      },
    );
    return controller.stream;
  }
}
