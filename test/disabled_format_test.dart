import 'dart:async';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:m_security/src/compression/compression_service.dart';
import 'package:m_security/src/evfs/vault_service.dart';
import 'package:m_security/src/rust/api/compression.dart';
import 'package:m_security/src/rust/api/encryption.dart';
import 'package:m_security/src/rust/api/evfs/types.dart';
import 'package:m_security/src/rust/core/error.dart';
import 'package:m_security/src/streaming/streaming_service.dart';

/// Stand-in for a real handle. Nothing reaches native, so it is never used.
class _NeverUsedCipher implements CipherHandle {
  @override
  void dispose() {}

  @override
  bool get isDisposed => false;
}

class _NeverUsedVault implements VaultHandle {
  @override
  void dispose() {}

  @override
  bool get isDisposed => false;

  @override
  Future<VaultHealthInfo> health() => throw UnimplementedError();
}

Future<Object?> errorFrom(Future<void> call) async {
  try {
    await call;
  } catch (error) {
    return error;
  }
  return null;
}

Future<({List<double> values, List<Object> errors})> drain(
  Stream<double> progress,
) async {
  final values = <double>[];
  final errors = <Object>[];
  final done = Completer<void>();

  progress.listen(
    values.add,
    onError: errors.add,
    onDone: done.complete,
    cancelOnError: false,
  );
  await done.future;

  return (values: values, errors: errors);
}

void main() {
  // RustLib is deliberately never initialised. The archive and encrypted-stream
  // methods have to refuse before they reach the bridge, so these pass without
  // a native library. Anything that did reach the bridge would fail differently.
  final cipher = _NeverUsedCipher();
  final vault = _NeverUsedVault();

  group('archive methods', () {
    test('export returns one disabled-format error', () async {
      final error = await errorFrom(
        VaultService.export(
          handle: vault,
          wrappingKey: Uint8List(32),
          exportPath: '/definitely/not/writable/out.mvex',
        ),
      );

      expect(error, isA<CryptoError_DisabledFormat>());
      expect(
        (error as CryptoError_DisabledFormat).field0,
        contains('.mvex archive export'),
      );
    });

    test('import returns one disabled-format error', () async {
      final error = await errorFrom(
        VaultService.importVault(
          archivePath: '/definitely/not/there/in.mvex',
          wrappingKey: Uint8List(32),
          destPath: '/definitely/not/writable/out.vault',
          newMasterKey: Uint8List(32),
          algorithm: 'aes-256-gcm',
          capacityBytes: 1024 * 1024,
        ),
      );

      expect(error, isA<CryptoError_DisabledFormat>());
      expect(
        (error as CryptoError_DisabledFormat).field0,
        contains('.mvex archive import'),
      );
    });
  });

  group('encrypted stream methods', () {
    final calls = <String, Stream<double> Function()>{
      'encryptFile': () => StreamingService.encryptFile(
        inputPath: '/definitely/not/there/in.bin',
        outputPath: '/definitely/not/writable/out.bin',
        cipher: cipher,
      ),
      'decryptFile': () => StreamingService.decryptFile(
        inputPath: '/definitely/not/there/in.bin',
        outputPath: '/definitely/not/writable/out.bin',
        cipher: cipher,
      ),
      'compressAndEncryptFile': () => CompressionService.compressAndEncryptFile(
        inputPath: '/definitely/not/there/in.bin',
        outputPath: '/definitely/not/writable/out.bin',
        cipher: cipher,
        config: const CompressionConfig(algorithm: CompressionAlgorithm.zstd),
      ),
      'decryptAndDecompressFile': () =>
          CompressionService.decryptAndDecompressFile(
            inputPath: '/definitely/not/there/in.bin',
            outputPath: '/definitely/not/writable/out.bin',
            cipher: cipher,
          ),
    };

    for (final entry in calls.entries) {
      test('${entry.key} emits exactly one disabled-format error', () async {
        final outcome = await drain(entry.value());

        expect(outcome.values, isEmpty);
        expect(outcome.errors, hasLength(1));
        expect(outcome.errors.single, isA<CryptoError_DisabledFormat>());
      });
    }
  });

  group('the policy enum', () {
    // A Dart function type carries no default values, so nothing here can see
    // which value `create` and `open` fall back to. That default is pinned by
    // the source scan in the Rust suite and by the device tests, which are the
    // only two places a flip is caught.
    test('denial is the first variant, so a zeroed wire value denies', () {
      expect(UnsafeLegacyEvfsPolicy.values.first, UnsafeLegacyEvfsPolicy.deny);
      expect(UnsafeLegacyEvfsPolicy.deny.index, 0);
      expect(UnsafeLegacyEvfsPolicy.values, hasLength(2));
    });
  });
}
