import 'dart:async';
import 'dart:typed_data';
import 'package:m_security/src/rust/api/streaming.dart' as rust_streaming;
import 'package:m_security/src/rust/api/encryption.dart' as rust_encryption;
import 'package:m_security/src/rust/api/hashing.dart' as rust_hashing;
import 'package:m_security/src/rust/core/error.dart';

/// Streaming file operations.
///
/// Processes large files in 64KB chunks to maintain constant RAM usage
/// regardless of file size.
///
/// Only hashing is available in this release. The encrypted stream format
/// leaves its header unauthenticated and binds a chunk to nothing but its index
/// and finality, so a chunk from another stream encrypted under the same handle
/// splices in. Its native entry points are gone and the methods below fail
/// before touching either path.
class StreamingService {
  StreamingService._();

  /// Disabled. Kept so existing code still compiles.
  ///
  /// Emits one disabled-format error before reading [inputPath] or creating
  /// [outputPath].
  static Stream<double> encryptFile({
    required String inputPath,
    required String outputPath,
    required rust_encryption.CipherHandle cipher,
  }) {
    return Stream<double>.error(
      const CryptoError.disabledFormat('encrypted stream write'),
    );
  }

  /// Disabled. Kept so existing code still compiles.
  ///
  /// Emits one disabled-format error before reading [inputPath] or creating
  /// [outputPath].
  static Stream<double> decryptFile({
    required String inputPath,
    required String outputPath,
    required rust_encryption.CipherHandle cipher,
  }) {
    return Stream<double>.error(
      const CryptoError.disabledFormat('encrypted stream read'),
    );
  }

  /// Hash a file without loading it into memory.
  /// Returns the digest bytes.
  static Future<Uint8List> hashFile({
    required String filePath,
    required rust_hashing.HasherHandle hasher,
  }) async {
    await _guardedStream(
      () => rust_streaming.streamHashFile(hasher: hasher, filePath: filePath),
    ).drain();
    return await rust_hashing.hasherFinalize(handle: hasher);
  }

  // FRB stream functions use unawaited(handler.executeNormal(...)),
  // so the Rust error is thrown as a zone error, not a stream error.
  // The error arrives AFTER the progress stream closes, so we delay
  // closing the controller to let the zone handler forward it first.
  static Stream<double> _guardedStream(Stream<double> Function() factory) {
    final controller = StreamController<double>();
    runZonedGuarded(
      () {
        factory().listen(
          controller.add,
          onError: controller.addError,
          onDone: () {
            // FRB delivers errors after the stream closes — schedule close
            // in the event loop so pending microtasks (zone errors) run first.
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
