import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:m_security/m_security.dart';
import 'package:m_security/src/rust/api/evfs.dart' as bridge;
import 'package:m_security/src/rust/core/error.dart';

import 'released_surface_consumer.dart' as released;

/// The `.lock`, `.wal` and rotation files a vault path can grow.
List<String> sidecars(String path) => [
  path,
  '$path.lock',
  '$path.wal',
  '$path.rotating',
  '$path.defrag',
].where((candidate) => File(candidate).existsSync()).toList();

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async => await RustLib.init());

  group('unsafe legacy vault policy', () {
    late Directory tempDir;
    late Uint8List key;

    setUp(() async {
      tempDir = await Directory.systemTemp.createTemp('evfs_policy_test');
      key = await generateAes256GcmKey();
    });
    tearDown(() async => await tempDir.delete(recursive: true));

    test('released source denies creation and writes nothing', () async {
      final path = '${tempDir.path}/denied.vault';

      await expectLater(
        released.createVault(
          path: path,
          key: key,
          algorithm: 'aes-256-gcm',
          capacityBytes: 1024 * 1024,
        ),
        throwsA(isA<CryptoError_UnsafeLegacyFormatDenied>()),
      );

      expect(sidecars(path), isEmpty);
      expect(tempDir.listSync(), isEmpty);
    });

    test(
      'released source denies opening and leaves the vault byte-identical',
      () async {
        final path = '${tempDir.path}/existing.vault';
        final handle = await released.createVaultWithOptIn(
          path: path,
          key: key,
          algorithm: 'aes-256-gcm',
          capacityBytes: 1024 * 1024,
        );
        await released.writeSegment(
          handle: handle,
          name: 'note.txt',
          data: Uint8List.fromList([7, 7, 7]),
        );
        await VaultService.close(handle: handle);

        final before = await File(path).readAsBytes();
        final beforeSidecars = sidecars(path);

        await expectLater(
          released.openVault(path: path, key: key),
          throwsA(isA<CryptoError_UnsafeLegacyFormatDenied>()),
        );

        expect(await File(path).readAsBytes(), before);
        expect(sidecars(path), beforeSidecars);
      },
    );

    test(
      'the generated entry denies on its own, not just the wrapper',
      () async {
        final path = '${tempDir.path}/raw.vault';

        // Straight at the bridge function, with the wrapper out of the way.
        await expectLater(
          bridge.vaultCreate(
            path: path,
            key: key,
            algorithm: 'aes-256-gcm',
            capacityBytes: BigInt.from(1024 * 1024),
            unsafeLegacyPolicy: UnsafeLegacyEvfsPolicy.deny,
          ),
          throwsA(isA<CryptoError_UnsafeLegacyFormatDenied>()),
        );
        expect(sidecars(path), isEmpty);

        await expectLater(
          bridge.vaultOpen(
            path: path,
            key: key,
            unsafeLegacyPolicy: UnsafeLegacyEvfsPolicy.deny,
          ),
          throwsA(isA<CryptoError_UnsafeLegacyFormatDenied>()),
        );
        expect(sidecars(path), isEmpty);
      },
    );

    test('the generated entry accepts the opt-in', () async {
      final path = '${tempDir.path}/raw_optin.vault';

      final handle = await bridge.vaultCreate(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: BigInt.from(1024 * 1024),
        unsafeLegacyPolicy: UnsafeLegacyEvfsPolicy.allowUnauthenticatedV1V2,
      );
      await VaultService.close(handle: handle);

      expect(File(path).existsSync(), isTrue);

      final reopened = await bridge.vaultOpen(
        path: path,
        key: key,
        unsafeLegacyPolicy: UnsafeLegacyEvfsPolicy.allowUnauthenticatedV1V2,
      );
      await VaultService.close(handle: reopened);
    });

    test('an opt-in round trip still denies the next default call', () async {
      final path = '${tempDir.path}/roundtrip.vault';
      final payload = Uint8List.fromList(List.generate(2048, (i) => i % 256));

      final handle = await released.createVaultWithOptIn(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 1024 * 1024,
      );
      await released.writeSegment(
        handle: handle,
        name: 'payload.bin',
        data: payload,
      );
      await VaultService.close(handle: handle);

      final reopened = await released.openVaultWithOptIn(path: path, key: key);
      expect(
        await released.readSegment(handle: reopened, name: 'payload.bin'),
        payload,
      );
      await VaultService.close(handle: reopened);

      for (var attempt = 0; attempt < 3; attempt++) {
        await expectLater(
          released.openVault(path: path, key: key),
          throwsA(isA<CryptoError_UnsafeLegacyFormatDenied>()),
          reason: 'attempt $attempt was authorized by an earlier opt-in',
        );
      }
    });

    test('a live opted-in handle does not authorize a default call', () async {
      final held = await released.createVaultWithOptIn(
        path: '${tempDir.path}/held.vault',
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 1024 * 1024,
      );
      addTearDown(() => VaultService.close(handle: held));

      await expectLater(
        released.createVault(
          path: '${tempDir.path}/second.vault',
          key: await generateAes256GcmKey(),
          algorithm: 'aes-256-gcm',
          capacityBytes: 1024 * 1024,
        ),
        throwsA(isA<CryptoError_UnsafeLegacyFormatDenied>()),
      );
      expect(File('${tempDir.path}/second.vault').existsSync(), isFalse);
    });

    test('a rotated vault still needs the opt-in to reopen', () async {
      final path = '${tempDir.path}/rotated.vault';
      final newKey = await generateAes256GcmKey();

      var handle = await released.createVaultWithOptIn(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 1024 * 1024,
      );
      await released.writeSegment(
        handle: handle,
        name: 'a.bin',
        data: Uint8List.fromList([1, 2, 3]),
      );
      handle = await VaultService.rotateKey(handle: handle, newKey: newKey);
      expect(
        await released.readSegment(handle: handle, name: 'a.bin'),
        Uint8List.fromList([1, 2, 3]),
      );
      await VaultService.close(handle: handle);

      await expectLater(
        released.openVault(path: path, key: newKey),
        throwsA(isA<CryptoError_UnsafeLegacyFormatDenied>()),
      );
      final reopened = await released.openVaultWithOptIn(
        path: path,
        key: newKey,
      );
      await VaultService.close(handle: reopened);
    });

    test('denial does not depend on the arguments being usable', () async {
      final path = '${tempDir.path}/bad_args.vault';

      // An empty key and an unknown algorithm are both rejected further in, so
      // seeing the denial means the check ran before either.
      await expectLater(
        released.createVault(
          path: path,
          key: Uint8List(0),
          algorithm: 'not-an-algorithm',
          capacityBytes: 1024 * 1024,
        ),
        throwsA(isA<CryptoError_UnsafeLegacyFormatDenied>()),
      );
      expect(sidecars(path), isEmpty);

      // Both really are rejected, so the case is not vacuous.
      await expectLater(
        released.createVaultWithOptIn(
          path: path,
          key: Uint8List(0),
          algorithm: 'aes-256-gcm',
          capacityBytes: 1024 * 1024,
        ),
        throwsA(isA<CryptoError>()),
      );
      await expectLater(
        released.createVaultWithOptIn(
          path: path,
          key: key,
          algorithm: 'not-an-algorithm',
          capacityBytes: 1024 * 1024,
        ),
        throwsA(isA<CryptoError>()),
      );
    });
  });
}
