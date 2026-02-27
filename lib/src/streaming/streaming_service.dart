import 'dart:async' show StreamController;
import 'dart:typed_data';
import 'package:m_security/src/rust/api/streaming.dart' as rust_streaming;
import 'package:m_security/src/rust/api/encryption.dart' as rust_encryption;
import 'package:m_security/src/rust/api/hashing.dart' as rust_hashing;
import 'dart:io';

/// Service for streaming file operations. (encrypt, decrypt, hash)
///
///Process large files in 64KB chunks to maintain constant RAM usage
///regardless of file size.

class StreamingService {
  StreamingService._();

  /// Encrypt a file, writing the result to outputPath.
  /// Returns a Stream of progress (0.0 to 1.0).
  ///
  /// The encrypted file uses uniform-size chunks — the last chunk
  /// is padded so all chunks are the same size on disk.
  static Stream<double> encryptFile({
    required String inputPath,
    required String outputPath,
    required rust_encryption.CipherHandle cipher,
  }) {
    final inputFile = File(inputPath);
    if (!inputFile.existsSync()) {
      throw Exception('Input file does not exist: $inputPath');
    }

    try {
      return rust_streaming.streamEncryptFile(
        cipher: cipher,
        inputPath: inputPath,
        outputPath: outputPath,
      );
    } catch (e) {
      throw Exception('Stream encrypt failed: $e');
    }
  }

  /// Decrypt a streaming-encrypted file.
  /// Returns a Stream of progress (0.0 to 1.0).
  ///
  /// Reads chunks until is_final sentinel is found.
  /// Strips padding from the last chunk automatically.
  /// Validates padding bytes are zero (tampered padding → error).
  static Stream<double> decryptFile({
  required String inputPath,
  required String outputPath,
  required rust_encryption.CipherHandle cipher,
}) {
  if (!File(inputPath).existsSync()) {
    return Stream.error(Exception('Input file does not exist: $inputPath'));
  }

  final controller = StreamController<double>();
  final sourceStream = rust_streaming.streamDecryptFile(
    cipher: cipher,
    inputPath: inputPath,
    outputPath: outputPath,
  );

  sourceStream.listen(
    controller.add,
    onError: controller.addError,
    onDone: () {
      if (!controller.isClosed) controller.close();
    },
    cancelOnError: false,
  );

  return controller.stream;
}

  /// Hash a file without loading it into memory.
  /// Returns the digest bytes. Optionally reports progress.
  ///
  /// Uses raw file bytes (no encryption padding) so the digest
  static Future<Uint8List> hashFile({
    required String filePath,
    required rust_hashing.HasherHandle hasher,
    void Function(double progress)? onProgress,
  }) async {
    final file = File(filePath);
    if (!await file.exists()) {
      throw Exception('File does not exist: $filePath');
    }
    try {
      //Stream the file into hasher
      await  rust_streaming.streamHashFile(
        hasher: hasher,
        filePath: filePath,
      ).last;
      return await rust_hashing.hasherFinalize(handle: hasher);
    } catch (e) {
      throw Exception('Stream hash failed: $e');
    }
  }
}
