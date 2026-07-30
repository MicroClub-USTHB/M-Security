import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:m_security/src/rust/api/encryption.dart';
import 'package:m_security/src/rust/frb_generated.dart';
import 'package:m_security/src/evfs/vault_service.dart';
import 'package:m_security/src/rust/api/evfs/types.dart';
import 'package:m_security/src/rust/core/error.dart';

// Every vault here is the unauthenticated v1/v2 format, which VaultService
// refuses unless the caller says so.
const _unsafeLegacy = UnsafeLegacyEvfsPolicy.allowUnauthenticatedV1V2;

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
        unsafeLegacyPolicy: _unsafeLegacy,
      );

      final dataA = Uint8List.fromList(List.generate(500, (i) => i % 256));
      final dataB = Uint8List.fromList(List.generate(1000, (i) => (i * 7) % 256));
      await VaultService.write(handle: handle, name: 'a.bin', data: dataA);
      await VaultService.write(handle: handle, name: 'b.bin', data: dataB);

      // Rotate
      handle = await VaultService.rotateKey(handle: handle, newKey: newKey);

      // All segments readable with new handle
      expect((await VaultService.read(handle: handle, name: 'a.bin')).data, dataA);
      expect((await VaultService.read(handle: handle, name: 'b.bin')).data, dataB);

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
        unsafeLegacyPolicy: _unsafeLegacy,
      );

      await VaultService.write(
        handle: handle,
        name: 'secret.bin',
        data: Uint8List.fromList([1, 2, 3]),
      );

      handle = await VaultService.rotateKey(handle: handle, newKey: newKey);
      await VaultService.close(handle: handle);

      // Old key must fail. Awaited, because an attempt still in flight holds
      // the vault lock the next open needs.
      await expectLater(
        VaultService.open(
          path: path,
          key: key,
          unsafeLegacyPolicy: _unsafeLegacy,
        ),
        throwsA(isA<Exception>()),
      );

      // New key works
      final reopened = await VaultService.open(
        path: path,
        key: newKey,
        unsafeLegacyPolicy: _unsafeLegacy,
      );
      expect(
        (await VaultService.read(handle: reopened, name: 'secret.bin')).data,
        Uint8List.fromList([1, 2, 3]),
      );
      await VaultService.close(handle: reopened);
    });

    test('export is disabled and writes no archive', () async {
      final vaultPath = '${tempDir.path}/source.vault';
      final archivePath = '${tempDir.path}/export.mvex';
      final key = await generateAes256GcmKey();
      final wrappingKey = await generateAes256GcmKey();

      final handle = await VaultService.create(
        path: vaultPath,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 2 * 1024 * 1024,
        unsafeLegacyPolicy: _unsafeLegacy,
      );
      final data = Uint8List.fromList(List.generate(800, (i) => i % 256));
      await VaultService.write(handle: handle, name: 'file1.dat', data: data);

      await expectLater(
        VaultService.export(
          handle: handle,
          wrappingKey: wrappingKey,
          exportPath: archivePath,
        ),
        throwsA(isA<CryptoError_DisabledFormat>()),
      );

      expect(File(archivePath).existsSync(), isFalse);
      // The vault itself is untouched by the refusal.
      expect((await VaultService.read(handle: handle, name: 'file1.dat')).data, data);
      await VaultService.close(handle: handle);
    });

    test('import is disabled and writes no destination vault', () async {
      final archivePath = '${tempDir.path}/absent.mvex';
      final importPath = '${tempDir.path}/imported.vault';

      await expectLater(
        VaultService.importVault(
          archivePath: archivePath,
          wrappingKey: await generateAes256GcmKey(),
          destPath: importPath,
          newMasterKey: await generateAes256GcmKey(),
          algorithm: 'aes-256-gcm',
          capacityBytes: 2 * 1024 * 1024,
        ),
        throwsA(isA<CryptoError_DisabledFormat>()),
      );

      expect(File(importPath).existsSync(), isFalse);
      expect(File('$importPath.lock').existsSync(), isFalse);
      expect(File('$importPath.wal').existsSync(), isFalse);
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
        unsafeLegacyPolicy: _unsafeLegacy,
      );

      final data = Uint8List.fromList([10, 20, 30, 40, 50]);
      await VaultService.write(handle: handle, name: 'data.bin', data: data);

      // Rotate twice
      handle = await VaultService.rotateKey(handle: handle, newKey: key2);
      expect((await VaultService.read(handle: handle, name: 'data.bin')).data, data);

      handle = await VaultService.rotateKey(handle: handle, newKey: key3);
      expect((await VaultService.read(handle: handle, name: 'data.bin')).data, data);

      await VaultService.close(handle: handle);

      // Only key3 works
      final reopened = await VaultService.open(
        path: path,
        key: key3,
        unsafeLegacyPolicy: _unsafeLegacy,
      );
      expect((await VaultService.read(handle: reopened, name: 'data.bin')).data, data);
      await VaultService.close(handle: reopened);
    });

    test('a rotated vault stays readable after export is refused', () async {
      final vaultPath = '${tempDir.path}/rot_exp.vault';
      final archivePath = '${tempDir.path}/rot_exp.mvex';
      final key = await generateAes256GcmKey();
      final rotatedKey = await generateAes256GcmKey();
      final wrappingKey = await generateAes256GcmKey();

      var handle = await VaultService.create(
        path: vaultPath,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 2 * 1024 * 1024,
        unsafeLegacyPolicy: _unsafeLegacy,
      );

      final data = Uint8List.fromList(List.generate(256, (i) => i));
      await VaultService.write(handle: handle, name: 'payload.bin', data: data);

      handle = await VaultService.rotateKey(handle: handle, newKey: rotatedKey);

      await expectLater(
        VaultService.export(
          handle: handle,
          wrappingKey: wrappingKey,
          exportPath: archivePath,
        ),
        throwsA(isA<CryptoError_DisabledFormat>()),
      );

      expect(File(archivePath).existsSync(), isFalse);
      expect(
        (await VaultService.read(handle: handle, name: 'payload.bin')).data,
        data,
      );
      await VaultService.close(handle: handle);
    });
  });
}
