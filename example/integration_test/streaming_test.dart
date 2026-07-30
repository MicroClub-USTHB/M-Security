import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:m_security/src/rust/api/encryption.dart';
import 'package:m_security/src/rust/core/error.dart';
import 'package:m_security/src/rust/frb_generated.dart';
import 'package:m_security/src/streaming/streaming_service.dart';
import 'package:m_security/src/rust/api/hashing.dart';

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

  group('Streaming', () {
    test('streaming hash matches one-shot hash', () async {
      final tempDir = await Directory.systemTemp.createTemp('hash_test');
      final file = File('${tempDir.path}/test.bin');

      final data = Uint8List.fromList(List.generate(50000, (i) => i % 256));
      await file.writeAsBytes(data);

      // streaming hash
      final hasher = await createBlake3();
      final streamDigest = await StreamingService.hashFile(
        filePath: file.path,
        hasher: hasher,
      );

      // one-shot hash
      final oneshotDigest = await blake3Hash(data: data);

      expect(streamDigest, oneshotDigest);

      await tempDir.delete(recursive: true);
    });

    test(
      'encryptFile emits one disabled-format error and writes nothing',
      () async {
        final tempDir = await Directory.systemTemp.createTemp('stream_test');
        final inputFile = File('${tempDir.path}/input.bin');
        final encrypted = File('${tempDir.path}/encrypted.bin');

        await inputFile.writeAsBytes(
          Uint8List.fromList(List.generate(100000, (i) => i % 256)),
        );
        final cipher = await createAes256Gcm(key: await generateAes256GcmKey());

        final outcome = await drain(
          StreamingService.encryptFile(
            inputPath: inputFile.path,
            outputPath: encrypted.path,
            cipher: cipher,
          ),
        );

        expect(outcome.values, isEmpty);
        expect(outcome.errors, hasLength(1));
        expect(outcome.errors.single, isA<CryptoError_DisabledFormat>());
        expect(encrypted.existsSync(), isFalse);
        expect(File('${encrypted.path}.tmp').existsSync(), isFalse);

        await tempDir.delete(recursive: true);
      },
    );

    test(
      'decryptFile emits one disabled-format error and writes nothing',
      () async {
        final tempDir = await Directory.systemTemp.createTemp('stream_test');
        final encrypted = File('${tempDir.path}/encrypted.bin');
        final decrypted = File('${tempDir.path}/decrypted.bin');

        // Bytes that start like an MSSE stream, so nothing but the refusal keeps
        // the parser away from them.
        await encrypted.writeAsBytes(
          Uint8List.fromList([0x4D, 0x53, 0x53, 0x45, 1, 0, 0, 0]),
        );
        final cipher = await createAes256Gcm(key: await generateAes256GcmKey());

        final outcome = await drain(
          StreamingService.decryptFile(
            inputPath: encrypted.path,
            outputPath: decrypted.path,
            cipher: cipher,
          ),
        );

        expect(outcome.values, isEmpty);
        expect(outcome.errors, hasLength(1));
        expect(outcome.errors.single, isA<CryptoError_DisabledFormat>());
        expect(decrypted.existsSync(), isFalse);

        await tempDir.delete(recursive: true);
      },
    );

    test('the refusal arrives before either path is touched', () async {
      final tempDir = await Directory.systemTemp.createTemp('stream_test');
      final missing = '${tempDir.path}/absent.bin';
      final output = '${tempDir.path}/nested/deeper/out.bin';
      final cipher = await createAes256Gcm(key: await generateAes256GcmKey());

      // A missing input and an unreachable output would both fail with an I/O
      // error further in, so a disabled-format error means neither was tried.
      for (final progress in [
        StreamingService.encryptFile(
          inputPath: missing,
          outputPath: output,
          cipher: cipher,
        ),
        StreamingService.decryptFile(
          inputPath: missing,
          outputPath: output,
          cipher: cipher,
        ),
      ]) {
        final outcome = await drain(progress);

        expect(outcome.errors.single, isA<CryptoError_DisabledFormat>());
      }

      expect(Directory('${tempDir.path}/nested').existsSync(), isFalse);
      await tempDir.delete(recursive: true);
    });
  });
}
