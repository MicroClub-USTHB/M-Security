import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:m_security/src/rust/api/compression.dart';
import 'package:m_security/src/rust/api/encryption.dart';
import 'package:m_security/src/rust/frb_generated.dart';
import 'package:m_security/src/compression/compression_service.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async => await RustLib.init());

  group('Compression', () {
    test('zstd compress-then-encrypt roundtrip', () async {
      final tempDir = await Directory.systemTemp.createTemp('zstd_test');
      addTearDown(() => tempDir.delete(recursive: true));
      final input = File('${tempDir.path}/input.bin');
      final encrypted = File('${tempDir.path}/encrypted.bin');
      final decrypted = File('${tempDir.path}/decrypted.bin');

      final originalData = Uint8List.fromList(
        List.generate(100000, (i) => i % 256),
      );
      await input.writeAsBytes(originalData);

      final key = await generateAes256GcmKey();
      final cipher = await createAes256Gcm(key: key);

      await for (final _ in CompressionService.compressAndEncryptFile(
        inputPath: input.path,
        outputPath: encrypted.path,
        cipher: cipher,
        config: const CompressionConfig(algorithm: CompressionAlgorithm.zstd),
      )) {}

      await for (final _ in CompressionService.decryptAndDecompressFile(
        inputPath: encrypted.path,
        outputPath: decrypted.path,
        cipher: cipher,
      )) {}

      final result = await decrypted.readAsBytes();
      expect(result, originalData);
    });

    test('brotli compress-then-encrypt roundtrip', () async {
      final tempDir = await Directory.systemTemp.createTemp('brotli_test');
      addTearDown(() => tempDir.delete(recursive: true));
      final input = File('${tempDir.path}/input.bin');
      final encrypted = File('${tempDir.path}/encrypted.bin');
      final decrypted = File('${tempDir.path}/decrypted.bin');

      final originalData = Uint8List.fromList(
        List.generate(100000, (i) => i % 256),
      );
      await input.writeAsBytes(originalData);

      final key = await generateAes256GcmKey();
      final cipher = await createAes256Gcm(key: key);

      await for (final _ in CompressionService.compressAndEncryptFile(
        inputPath: input.path,
        outputPath: encrypted.path,
        cipher: cipher,
        config: const CompressionConfig(algorithm: CompressionAlgorithm.brotli),
      )) {}

      await for (final _ in CompressionService.decryptAndDecompressFile(
        inputPath: encrypted.path,
        outputPath: decrypted.path,
        cipher: cipher,
      )) {}

      final result = await decrypted.readAsBytes();
      expect(result, originalData);
    });

    test('compression none roundtrips correctly', () async {
      final tempDir = await Directory.systemTemp.createTemp('none_test');
      addTearDown(() => tempDir.delete(recursive: true));
      final input = File('${tempDir.path}/input.bin');
      final encrypted = File('${tempDir.path}/encrypted.bin');
      final decrypted = File('${tempDir.path}/decrypted.bin');

      final originalData = Uint8List.fromList(
        List.generate(50000, (i) => i % 256),
      );
      await input.writeAsBytes(originalData);

      final key = await generateAes256GcmKey();
      final cipher = await createAes256Gcm(key: key);

      await for (final _ in CompressionService.compressAndEncryptFile(
        inputPath: input.path,
        outputPath: encrypted.path,
        cipher: cipher,
        config: const CompressionConfig(algorithm: CompressionAlgorithm.none),
      )) {}

      await for (final _ in CompressionService.decryptAndDecompressFile(
        inputPath: encrypted.path,
        outputPath: decrypted.path,
        cipher: cipher,
      )) {}

      expect(await decrypted.readAsBytes(), originalData);
    });

    test('jpg file auto-skips compression', () async {
      final tempDir = await Directory.systemTemp.createTemp('jpg_test');
      addTearDown(() => tempDir.delete(recursive: true));
      // Use .jpg extension to trigger MIME-aware skip
      final input = File('${tempDir.path}/photo.jpg');
      final encrypted = File('${tempDir.path}/encrypted.bin');
      final decrypted = File('${tempDir.path}/decrypted.jpg');

      final originalData = Uint8List.fromList(
        List.generate(50000, (i) => i % 256),
      );
      await input.writeAsBytes(originalData);

      final key = await generateAes256GcmKey();
      final cipher = await createAes256Gcm(key: key);

      // Even though we request zstd, .jpg should trigger skip
      await for (final _ in CompressionService.compressAndEncryptFile(
        inputPath: input.path,
        outputPath: encrypted.path,
        cipher: cipher,
        config: const CompressionConfig(algorithm: CompressionAlgorithm.zstd),
      )) {}

      await for (final _ in CompressionService.decryptAndDecompressFile(
        inputPath: encrypted.path,
        outputPath: decrypted.path,
        cipher: cipher,
      )) {}

      final result = await decrypted.readAsBytes();
      expect(result, originalData);
    });

    test('custom compression level works', () async {
      final tempDir = await Directory.systemTemp.createTemp('level_test');
      addTearDown(() => tempDir.delete(recursive: true));
      final input = File('${tempDir.path}/input.bin');
      final encrypted = File('${tempDir.path}/encrypted.bin');
      final decrypted = File('${tempDir.path}/decrypted.bin');

      final originalData = Uint8List.fromList(
        List.generate(100000, (i) => i % 256),
      );
      await input.writeAsBytes(originalData);

      final key = await generateAes256GcmKey();
      final cipher = await createAes256Gcm(key: key);

      // Zstd with level 19 (high compression)
      await for (final _ in CompressionService.compressAndEncryptFile(
        inputPath: input.path,
        outputPath: encrypted.path,
        cipher: cipher,
        config: const CompressionConfig(
          algorithm: CompressionAlgorithm.zstd,
          level: 19,
        ),
      )) {}

      await for (final _ in CompressionService.decryptAndDecompressFile(
        inputPath: encrypted.path,
        outputPath: decrypted.path,
        cipher: cipher,
      )) {}

      final result = await decrypted.readAsBytes();
      expect(result, originalData);
    });
  });
}
