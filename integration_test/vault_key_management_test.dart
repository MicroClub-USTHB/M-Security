import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:m_security/src/rust/api/encryption.dart';
import 'package:m_security/src/rust/frb_generated.dart';
import 'package:m_security/src/evfs/vault_service.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async => await RustLib.init());

  group('Key Management', () {
    late Directory tempDir;
    setUp(() async {
      tempDir = await Directory.systemTemp.createTemp('key_mgmt_test');
    });
    tearDown(() async {
      await tempDir.delete(recursive: true);
    });

    test('rotateKey roundtrip: write, rotate, read back', () async {
      final path = '${tempDir.path}/rotate.vault';
      final key = await generateAes256GcmKey();
      final newKey = await generateAes256GcmKey();

      var handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 2 * 1024 * 1024,
      );

      final dataA = Uint8List.fromList(List.generate(500, (i) => i % 256));
      final dataB = Uint8List.fromList(List.generate(1000, (i) => (i * 7) % 256));
      await VaultService.write(handle: handle, name: 'a.bin', data: dataA);
      await VaultService.write(handle: handle, name: 'b.bin', data: dataB);

      // Rotate
      handle = await VaultService.rotateKey(handle: handle, newKey: newKey);

      // All segments readable with new handle
      expect(await VaultService.read(handle: handle, name: 'a.bin'), dataA);
      expect(await VaultService.read(handle: handle, name: 'b.bin'), dataB);

      await VaultService.close(handle: handle);
    });

    test('old key rejected after rotation', () async {
      final path = '${tempDir.path}/oldkey.vault';
      final key = await generateAes256GcmKey();
      final newKey = await generateAes256GcmKey();

      var handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 1024 * 1024,
      );

      await VaultService.write(
        handle: handle,
        name: 'secret.bin',
        data: Uint8List.fromList([1, 2, 3]),
      );

      handle = await VaultService.rotateKey(handle: handle, newKey: newKey);
      await VaultService.close(handle: handle);

      // Old key must fail
      expect(
        () async => await VaultService.open(path: path, key: key),
        throwsA(isA<Exception>()),
      );

      // New key works
      final reopened = await VaultService.open(path: path, key: newKey);
      expect(
        await VaultService.read(handle: reopened, name: 'secret.bin'),
        Uint8List.fromList([1, 2, 3]),
      );
      await VaultService.close(handle: reopened);
    });

    test('export-import roundtrip: data matches byte-for-byte', () async {
      final vaultPath = '${tempDir.path}/source.vault';
      final archivePath = '${tempDir.path}/export.mvex';
      final importPath = '${tempDir.path}/imported.vault';
      final key = await generateAes256GcmKey();
      final wrappingKey = await generateAes256GcmKey();
      final importKey = await generateAes256GcmKey();

      var handle = await VaultService.create(
        path: vaultPath,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 2 * 1024 * 1024,
      );

      final data1 = Uint8List.fromList(List.generate(800, (i) => i % 256));
      final data2 = Uint8List.fromList(List.generate(1200, (i) => (i * 3) % 256));
      await VaultService.write(handle: handle, name: 'file1.dat', data: data1);
      await VaultService.write(handle: handle, name: 'file2.dat', data: data2);

      // Export
      await VaultService.export(
        handle: handle,
        wrappingKey: wrappingKey,
        exportPath: archivePath,
      );
      await VaultService.close(handle: handle);

      expect(File(archivePath).existsSync(), isTrue);

      // Import into new vault
      final imported = await VaultService.importVault(
        archivePath: archivePath,
        wrappingKey: wrappingKey,
        destPath: importPath,
        newMasterKey: importKey,
        algorithm: 'aes-256-gcm',
        capacityBytes: 2 * 1024 * 1024,
      );

      expect(await VaultService.read(handle: imported, name: 'file1.dat'), data1);
      expect(await VaultService.read(handle: imported, name: 'file2.dat'), data2);

      await VaultService.close(handle: imported);
    });

    test('import with wrong wrapping key throws', () async {
      final vaultPath = '${tempDir.path}/wk.vault';
      final archivePath = '${tempDir.path}/wk.mvex';
      final key = await generateAes256GcmKey();
      final wrappingKey = await generateAes256GcmKey();
      final wrongKey = await generateAes256GcmKey();

      var handle = await VaultService.create(
        path: vaultPath,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 1024 * 1024,
      );
      await VaultService.write(
        handle: handle,
        name: 'x.bin',
        data: Uint8List.fromList([42]),
      );
      await VaultService.export(
        handle: handle,
        wrappingKey: wrappingKey,
        exportPath: archivePath,
      );
      await VaultService.close(handle: handle);

      expect(
        () async => await VaultService.importVault(
          archivePath: archivePath,
          wrappingKey: wrongKey,
          destPath: '${tempDir.path}/bad.vault',
          newMasterKey: await generateAes256GcmKey(),
          algorithm: 'aes-256-gcm',
          capacityBytes: 1024 * 1024,
        ),
        throwsA(isA<Exception>()),
      );
    });

    test('large segment (1MB+) survives export-import', () async {
      final vaultPath = '${tempDir.path}/big.vault';
      final archivePath = '${tempDir.path}/big.mvex';
      final importPath = '${tempDir.path}/big_imported.vault';
      final key = await generateAes256GcmKey();
      final wrappingKey = await generateAes256GcmKey();

      var handle = await VaultService.create(
        path: vaultPath,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 5 * 1024 * 1024,
      );

      final bigData = Uint8List.fromList(
        List.generate(1024 * 1024 + 37, (i) => (i * 13) % 256),
      );
      await VaultService.write(handle: handle, name: 'big.bin', data: bigData);

      await VaultService.export(
        handle: handle,
        wrappingKey: wrappingKey,
        exportPath: archivePath,
      );
      await VaultService.close(handle: handle);

      final imported = await VaultService.importVault(
        archivePath: archivePath,
        wrappingKey: wrappingKey,
        destPath: importPath,
        newMasterKey: await generateAes256GcmKey(),
        algorithm: 'aes-256-gcm',
        capacityBytes: 5 * 1024 * 1024,
      );

      expect(await VaultService.read(handle: imported, name: 'big.bin'), bigData);
      await VaultService.close(handle: imported);
    });

    test('multiple sequential rotations', () async {
      final path = '${tempDir.path}/multi_rot.vault';
      final key1 = await generateAes256GcmKey();
      final key2 = await generateAes256GcmKey();
      final key3 = await generateAes256GcmKey();

      var handle = await VaultService.create(
        path: path,
        key: key1,
        algorithm: 'aes-256-gcm',
        capacityBytes: 2 * 1024 * 1024,
      );

      final data = Uint8List.fromList([10, 20, 30, 40, 50]);
      await VaultService.write(handle: handle, name: 'data.bin', data: data);

      // Rotate twice
      handle = await VaultService.rotateKey(handle: handle, newKey: key2);
      expect(await VaultService.read(handle: handle, name: 'data.bin'), data);

      handle = await VaultService.rotateKey(handle: handle, newKey: key3);
      expect(await VaultService.read(handle: handle, name: 'data.bin'), data);

      await VaultService.close(handle: handle);

      // Only key3 works
      final reopened = await VaultService.open(path: path, key: key3);
      expect(await VaultService.read(handle: reopened, name: 'data.bin'), data);
      await VaultService.close(handle: reopened);
    });

    test('rotate then export-import the rotated vault', () async {
      final vaultPath = '${tempDir.path}/rot_exp.vault';
      final archivePath = '${tempDir.path}/rot_exp.mvex';
      final importPath = '${tempDir.path}/rot_exp_imported.vault';
      final key = await generateAes256GcmKey();
      final rotatedKey = await generateAes256GcmKey();
      final wrappingKey = await generateAes256GcmKey();
      final importKey = await generateAes256GcmKey();

      var handle = await VaultService.create(
        path: vaultPath,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 2 * 1024 * 1024,
      );

      final data = Uint8List.fromList(List.generate(256, (i) => i));
      await VaultService.write(handle: handle, name: 'payload.bin', data: data);

      // Rotate first
      handle = await VaultService.rotateKey(handle: handle, newKey: rotatedKey);

      // Then export
      await VaultService.export(
        handle: handle,
        wrappingKey: wrappingKey,
        exportPath: archivePath,
      );
      await VaultService.close(handle: handle);

      // Import
      final imported = await VaultService.importVault(
        archivePath: archivePath,
        wrappingKey: wrappingKey,
        destPath: importPath,
        newMasterKey: importKey,
        algorithm: 'aes-256-gcm',
        capacityBytes: 2 * 1024 * 1024,
      );

      expect(
        await VaultService.read(handle: imported, name: 'payload.bin'),
        data,
      );
      await VaultService.close(handle: imported);
    });
  });
}
