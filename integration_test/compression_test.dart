import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:m_security/src/rust/api/compression.dart';
import 'package:m_security/src/rust/api/encryption.dart';
import 'package:m_security/src/rust/core/error.dart';
import 'package:m_security/src/rust/frb_generated.dart';
import 'package:m_security/src/compression/compression_service.dart';

/// Drain a progress stream, keeping the values and the errors apart.
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
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async => await RustLib.init());

  group('Compression', () {
    test('compressAndEncryptFile is disabled for every algorithm', () async {
      final tempDir = await Directory.systemTemp.createTemp('zstd_test');
      addTearDown(() => tempDir.delete(recursive: true));
      final input = File('${tempDir.path}/input.bin');
      final encrypted = File('${tempDir.path}/encrypted.bin');

      await input.writeAsBytes(
        Uint8List.fromList(List.generate(100000, (i) => i % 256)),
      );
      final cipher = await createAes256Gcm(key: await generateAes256GcmKey());

      for (final algorithm in CompressionAlgorithm.values) {
        final outcome = await drain(
          CompressionService.compressAndEncryptFile(
            inputPath: input.path,
            outputPath: encrypted.path,
            cipher: cipher,
            config: CompressionConfig(algorithm: algorithm),
          ),
        );

        expect(outcome.values, isEmpty, reason: '$algorithm reported progress');
        expect(outcome.errors, hasLength(1));
        expect(outcome.errors.single, isA<CryptoError_DisabledFormat>());
        expect(encrypted.existsSync(), isFalse);
      }
    });

    test('compressAndEncryptFile is disabled at a custom level', () async {
      final tempDir = await Directory.systemTemp.createTemp('level_test');
      addTearDown(() => tempDir.delete(recursive: true));
      final input = File('${tempDir.path}/input.bin');
      final encrypted = File('${tempDir.path}/encrypted.bin');

      await input.writeAsBytes(Uint8List(4096));
      final cipher = await createAes256Gcm(key: await generateAes256GcmKey());

      final outcome = await drain(
        CompressionService.compressAndEncryptFile(
          inputPath: input.path,
          outputPath: encrypted.path,
          cipher: cipher,
          config: const CompressionConfig(
            algorithm: CompressionAlgorithm.zstd,
            level: 19,
          ),
        ),
      );

      expect(outcome.errors.single, isA<CryptoError_DisabledFormat>());
      expect(encrypted.existsSync(), isFalse);
    });

    test('decryptAndDecompressFile is disabled and writes nothing', () async {
      final tempDir = await Directory.systemTemp.createTemp('decomp_test');
      addTearDown(() => tempDir.delete(recursive: true));
      final encrypted = File('${tempDir.path}/encrypted.bin');
      final decrypted = File('${tempDir.path}/decrypted.bin');

      // Bytes that start like an MSSE stream, so nothing but the refusal keeps
      // the parser away from them.
      await encrypted.writeAsBytes(
        Uint8List.fromList([0x4D, 0x53, 0x53, 0x45, 1, 0, 0, 1]),
      );
      final cipher = await createAes256Gcm(key: await generateAes256GcmKey());

      final outcome = await drain(
        CompressionService.decryptAndDecompressFile(
          inputPath: encrypted.path,
          outputPath: decrypted.path,
          cipher: cipher,
        ),
      );

      expect(outcome.values, isEmpty);
      expect(outcome.errors, hasLength(1));
      expect(outcome.errors.single, isA<CryptoError_DisabledFormat>());
      expect(decrypted.existsSync(), isFalse);
    });

    test('the refusal arrives before either path is touched', () async {
      final tempDir = await Directory.systemTemp.createTemp('untouched_test');
      addTearDown(() => tempDir.delete(recursive: true));
      final missing = '${tempDir.path}/absent.bin';
      final output = '${tempDir.path}/nested/deeper/out.bin';
      final cipher = await createAes256Gcm(key: await generateAes256GcmKey());

      // A missing input and an unreachable output would both fail with an I/O
      // error further in, so a disabled-format error means neither was tried.
      for (final progress in [
        CompressionService.compressAndEncryptFile(
          inputPath: missing,
          outputPath: output,
          cipher: cipher,
        ),
        CompressionService.decryptAndDecompressFile(
          inputPath: missing,
          outputPath: output,
          cipher: cipher,
        ),
      ]) {
        final outcome = await drain(progress);

        expect(outcome.errors.single, isA<CryptoError_DisabledFormat>());
      }

      expect(Directory('${tempDir.path}/nested').existsSync(), isFalse);
    });

    test('an already-compressed name is refused the same way', () async {
      final tempDir = await Directory.systemTemp.createTemp('jpg_test');
      addTearDown(() => tempDir.delete(recursive: true));
      final input = File('${tempDir.path}/photo.jpg');
      final encrypted = File('${tempDir.path}/photo.enc');

      await input.writeAsBytes(Uint8List.fromList([0xFF, 0xD8, 0xFF, 0xE0]));
      final cipher = await createAes256Gcm(key: await generateAes256GcmKey());

      final outcome = await drain(
        CompressionService.compressAndEncryptFile(
          inputPath: input.path,
          outputPath: encrypted.path,
          cipher: cipher,
        ),
      );

      expect(outcome.errors.single, isA<CryptoError_DisabledFormat>());
      expect(encrypted.existsSync(), isFalse);
    });
  });
}
