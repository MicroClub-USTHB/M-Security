import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:m_security/src/rust/api/encryption.dart';
import 'package:m_security/src/rust/frb_generated.dart';
import 'package:m_security/src/streaming/streaming_service.dart';
import 'package:m_security/src/rust/api/hashing.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async => await RustLib.init());

  group('Streaming', () {
    test('encrypt then decrypt file roundtrip', () async {
      //Create temp file with known content
      //→ encrypt → decrypt → compare bytes identical
      final tempDir = await Directory.systemTemp.createTemp('stream_test');
      final inputFile = File('${tempDir.path}/input.bin');
      final encrypted = File('${tempDir.path}/encrypted.bin');
      final decrypted = File('${tempDir.path}/decrypted.bin');

      final originalData = Uint8List.fromList(
        List.generate(100000, (i) => i % 256),
      );
      await inputFile.writeAsBytes(originalData);

      //generate key and create cipher
      final key = await generateAes256GcmKey();
      final cipher = await createAes256Gcm(key: key);

      //Encrypt
      await for (final _ in StreamingService.encryptFile(
        inputPath: inputFile.path,
        outputPath: encrypted.path,
        cipher: cipher,
      )) {
        //wait for completion
      }
      //Decrypt
      await for (final _ in StreamingService.decryptFile(
        inputPath: encrypted.path,
        outputPath: decrypted.path,
        cipher: cipher,
      )) {
        //wait for completion
      }
      //verify
      final result = await decrypted.readAsBytes();
      expect(result, originalData);

      //cleanup
      await tempDir.delete(recursive: true);
    });

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

    test('progress reports from 0 to 1', () async {
      final tempDir = await Directory.systemTemp.createTemp('progress_test');
      final inputFile = File('${tempDir.path}/input.bin');
      final encrypted = File('${tempDir.path}/encrypted.bin');

      // create 1MB file
      final data = Uint8List(1024 * 1024);
      await inputFile.writeAsBytes(data);

      final key = await generateAes256GcmKey();
      final cipher = await createAes256Gcm(key: key);

      final progressValues = <double>[];

      await for (final progress in StreamingService.encryptFile(
        inputPath: inputFile.path,
        outputPath: encrypted.path,
        cipher: cipher,
      )) {
        progressValues.add(progress);
      }

      //verify progress goes from ~0 to 1
      expect(progressValues.first, lessThan(0.1));
      expect(progressValues.last, closeTo(1.0, 0.01));

      // verify monotonically increasing
      for (int i = 1; i < progressValues.length; i++) {
        expect(progressValues[i], greaterThanOrEqualTo(progressValues[i - 1]));
      }

      await tempDir.delete(recursive: true);
    });

    test('wrong key fails decryption', () async {
      final tempDir = await Directory.systemTemp.createTemp('wrongkey_test');
      final inputFile = File('${tempDir.path}/input.bin');
      final encrypted = File('${tempDir.path}/encrypted.bin');
      final decrypted = File('${tempDir.path}/decrypted.bin');

      await inputFile.writeAsBytes(Uint8List.fromList([1, 2, 3, 4, 5]));

      final keyA = await generateAes256GcmKey();
      final cipherA = await createAes256Gcm(key: keyA);

      await for (final _ in StreamingService.encryptFile(
        inputPath: inputFile.path,
        outputPath: encrypted.path,
        cipher: cipherA,
      )) {}

      final keyB = await generateAes256GcmKey();
      final cipherB = await createAes256Gcm(key: keyB);

      bool errorThrown = false;
      try {
        await for (final _ in StreamingService.decryptFile(
          inputPath: encrypted.path,
          outputPath: decrypted.path,
          cipher: cipherB,
        )) {}
      } catch (e) {
        errorThrown = true;
      }
      expect(errorThrown, true);

      await tempDir.delete(recursive: true);
    });

    test('empty file roundtrip', () async {
      final tempDir = await Directory.systemTemp.createTemp('empty_test');
      final inputFile = File('${tempDir.path}/empty.bin');
      final encrypted = File('${tempDir.path}/encrypted.bin');
      final decrypted = File('${tempDir.path}/decrypted.bin');

      await inputFile.writeAsBytes(Uint8List(0)); // Empty file

      final key = await generateAes256GcmKey();
      final cipher = await createAes256Gcm(key: key);

      await for (final _ in StreamingService.encryptFile(
        inputPath: inputFile.path,
        outputPath: encrypted.path,
        cipher: cipher,
      )) {}

      await for (final _ in StreamingService.decryptFile(
        inputPath: encrypted.path,
        outputPath: decrypted.path,
        cipher: cipher,
      )) {}

      final result = await decrypted.readAsBytes();
      expect(result.length, 0);

      await tempDir.delete(recursive: true);
    });

    test('small file padding stripped correctly', () async {
      final tempDir = await Directory.systemTemp.createTemp('padding_test');
      final inputFile = File('${tempDir.path}/small.bin');
      final encrypted = File('${tempDir.path}/encrypted.bin');
      final decrypted = File('${tempDir.path}/decrypted.bin');
      
      final originalData = Uint8List(100); // exactly 100 bytes
      await inputFile.writeAsBytes(originalData);
      
      final key = await generateAes256GcmKey();
      final cipher = await createAes256Gcm(key: key);
      
      await for (final _ in StreamingService.encryptFile(
        inputPath: inputFile.path,
        outputPath: encrypted.path,
        cipher: cipher,
      )) {}
      
      await for (final _ in StreamingService.decryptFile(
        inputPath: encrypted.path,
        outputPath: decrypted.path,
        cipher: cipher,
      )) {}
      
      final result = await decrypted.readAsBytes();
      expect(result.length, 100, reason: 'Padding should be stripped, output should be exactly 100 bytes, not 64KB');
      
      await tempDir.delete(recursive: true);
    });

    test('encrypted chunks are uniform size', () async {
      final tempDir = await Directory.systemTemp.createTemp('uniform_test');
      final inputFile = File('${tempDir.path}/input.bin');
      final encrypted = File('${tempDir.path}/encrypted.bin');
      
      // Create file that doesn't fill last chunk 
      final data = Uint8List(150);
      await inputFile.writeAsBytes(data);
      
      final key = await generateAes256GcmKey();
      final cipher = await createAes256Gcm(key: key);
      
      await for (final _ in StreamingService.encryptFile(
        inputPath: inputFile.path,
        outputPath: encrypted.path,
        cipher: cipher,
      )) {}
      
      final encryptedSize = await encrypted.length();
      const streamHeaderSize = 16;
      const encryptedChunkSize = 65564;
      
      final dataPortionSize = encryptedSize - streamHeaderSize;
      
      expect(
        dataPortionSize % encryptedChunkSize,
        0,
        reason: 'All encrypted chunks should be uniform size. Got file size $encryptedSize',
      );
      
      await tempDir.delete(recursive: true);
    });

    test('tampered padding detected end-to-end', () async {
      final tempDir = await Directory.systemTemp.createTemp('tamper_test');
      final inputFile = File('${tempDir.path}/input.bin');
      final encrypted = File('${tempDir.path}/encrypted.bin');
      final tampered = File('${tempDir.path}/tampered.bin');
      final decrypted = File('${tempDir.path}/decrypted.bin');

      final data = Uint8List(100);
      await inputFile.writeAsBytes(data);

      final key = await generateAes256GcmKey();
      final cipher = await createAes256Gcm(key: key);

      await for (final _ in StreamingService.encryptFile(
        inputPath: inputFile.path,
        outputPath: encrypted.path,
        cipher: cipher,
      )) {}

      final encryptedBytes = await encrypted.readAsBytes();
      final tamperedBytes = Uint8List.fromList(encryptedBytes);
      tamperedBytes[tamperedBytes.length - 100] ^= 0xFF;
      await tampered.writeAsBytes(tamperedBytes);

      await expectLater(
        Future(() async {
          await for (final _ in StreamingService.decryptFile(
            inputPath: tampered.path,
            outputPath: decrypted.path,
            cipher: cipher,
          )) {}
        }),
        throwsA(anything),
        reason: 'Tampered padding should be detected and throw error',
      );

      await tempDir.delete(recursive: true);
    });

  });
}
