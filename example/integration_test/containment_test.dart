/// The subset a packaged consumer runs against the native library.
///
/// Everything here goes through `package:m_security/m_security.dart` and
/// nothing else, so the same file runs from this example against the checkout
/// and from a throwaway app that depends only on the assembled publish payload.
/// Adding a `package:m_security/src/...` import would quietly break the second
/// one, which is the run that matters.
library;

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:m_security/m_security.dart';

/// A released mobile-preset hash of 'preset_vector'.
const String releasedMobileVector =
    r'$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$rUYVKsKrcBrgqxhUdNkDIkzdd3Df9gC3RP6cEdFyM8k';

/// The same hash with memory raised past the verification ceiling.
const String overLimitVector =
    r'$argon2id$v=19$m=1048576,t=3,p=4$c29tZXNhbHQ$rUYVKsKrcBrgqxhUdNkDIkzdd3Df9gC3RP6cEdFyM8k';

/// The error's variant name, e.g. `CryptoError.unsafeLegacyFormatDenied`.
///
/// The package barrel exports the calls but not the error type, so a consumer
/// that imports only the barrel cannot write `isA<CryptoError_...>()`. The
/// generated `toString` starts with the variant, which is as close as this
/// vantage point gets.
String kindOf(Object error) => error.toString().split('(').first;

Future<Object?> errorFrom(Future<void> call) async {
  try {
    await call;
  } catch (error) {
    return error;
  }
  return null;
}

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

  late Directory tempDir;
  setUp(() async {
    tempDir = await Directory.systemTemp.createTemp('m_security_containment');
  });
  tearDown(() async => await tempDir.delete(recursive: true));

  group('one-shot ciphers', () {
    test('AES-256-GCM round trips through the native library', () async {
      final cipher = await createAes256Gcm(key: await generateAes256GcmKey());
      final plaintext = Uint8List.fromList(
        List.generate(4096, (i) => (i * 31) % 256),
      );
      final aad = Uint8List.fromList([9, 8, 7]);

      final ciphertext = await encrypt(
        cipher: cipher,
        plaintext: plaintext,
        aad: aad,
      );

      expect(ciphertext, isNot(plaintext));
      expect(
        await decrypt(cipher: cipher, ciphertext: ciphertext, aad: aad),
        plaintext,
      );
    });

    test('AES-256-GCM rejects a wrong AAD', () async {
      final cipher = await createAes256Gcm(key: await generateAes256GcmKey());
      final ciphertext = await encrypt(
        cipher: cipher,
        plaintext: Uint8List.fromList([1, 2, 3]),
        aad: Uint8List.fromList([4]),
      );

      final error = await errorFrom(
        decrypt(
          cipher: cipher,
          ciphertext: ciphertext,
          aad: Uint8List.fromList([5]),
        ),
      );

      expect(kindOf(error!), 'CryptoError.authenticationFailed');
    });

    test('ChaCha20-Poly1305 round trips through the native library', () async {
      final cipher = await createChacha20Poly1305(
        key: await generateChacha20Poly1305Key(),
      );
      final plaintext = Uint8List.fromList(
        List.generate(4096, (i) => (i * 17) % 256),
      );
      final aad = Uint8List(0);

      final ciphertext = await encrypt(
        cipher: cipher,
        plaintext: plaintext,
        aad: aad,
      );

      expect(ciphertext, isNot(plaintext));
      expect(
        await decrypt(cipher: cipher, ciphertext: ciphertext, aad: aad),
        plaintext,
      );
    });

    test('an empty plaintext still round trips', () async {
      final cipher = await createAes256Gcm(key: await generateAes256GcmKey());
      final ciphertext = await encrypt(
        cipher: cipher,
        plaintext: Uint8List(0),
        aad: Uint8List(0),
      );

      expect(ciphertext, isNotEmpty);
      expect(
        await decrypt(
          cipher: cipher,
          ciphertext: ciphertext,
          aad: Uint8List(0),
        ),
        isEmpty,
      );
    });
  });

  group('Argon2id verification limits', () {
    test('the released mobile vector verifies', () async {
      await argon2IdVerify(
        phcHash: releasedMobileVector,
        password: 'preset_vector',
      );
    });

    test('a wrong password is an authentication failure', () async {
      final error = await errorFrom(
        argon2IdVerify(phcHash: releasedMobileVector, password: 'wrong'),
      );

      expect(kindOf(error!), 'CryptoError.authenticationFailed');
    });

    test('work factors above the ceiling are a policy violation', () async {
      final error = await errorFrom(
        argon2IdVerify(phcHash: overLimitVector, password: 'preset_vector'),
      );

      expect(kindOf(error!), 'CryptoError.argon2PolicyViolation');
    });

    // This one stops in the Dart wrapper, before the bridge. The native
    // boundary enforces the same ceiling and the Rust suite covers it there.
    test('a password over the ceiling is a policy violation', () async {
      final error = await errorFrom(
        argon2IdVerify(
          phcHash: releasedMobileVector,
          password: 'a' * (maxArgon2VerifyPasswordBytes + 1),
        ),
      );

      expect(kindOf(error!), 'CryptoError.argon2PolicyViolation');
    });

    test('a password at the ceiling reaches the verifier', () async {
      final error = await errorFrom(
        argon2IdVerify(
          phcHash: releasedMobileVector,
          password: 'a' * maxArgon2VerifyPasswordBytes,
        ),
      );

      expect(kindOf(error!), 'CryptoError.authenticationFailed');
    });

    test('overlapping verifications are refused, never queued', () async {
      // The bridge dispatches all four before the first finishes, so three come
      // back refused rather than waiting their turn. Measured at two, four and
      // eight callers: one success every time and the rest refused.
      final outcomes = await Future.wait([
        for (var i = 0; i < 4; i++)
          errorFrom(
            argon2IdVerify(
              phcHash: releasedMobileVector,
              password: 'preset_vector',
            ),
          ),
      ]);
      final kinds = outcomes.map((o) => o == null ? 'ok' : kindOf(o)).toList();

      expect(kinds, contains('ok'));
      expect(kinds, contains('CryptoError.argon2VerificationBusy'));
      expect(
        kinds.where((k) => k != 'ok' && k != 'CryptoError.argon2VerificationBusy'),
        isEmpty,
        reason: 'overlap produced an outcome other than success or busy',
      );

      // The permit comes back, so a caller arriving afterwards is not stuck
      // with the refusal.
      await argon2IdVerify(
        phcHash: releasedMobileVector,
        password: 'preset_vector',
      );
    });

    test('hashing still produces a verifiable PHC string', () async {
      final hash = await argon2IdHash(
        password: 'fresh_password',
        preset: Argon2Preset.mobile,
      );

      expect(hash, startsWith(r'$argon2id$v=19$m=65536,t=3,p=4$'));
      await argon2IdVerify(phcHash: hash, password: 'fresh_password');
    });
  });

  group('vault format policy', () {
    test('creation is denied and writes nothing', () async {
      final path = '${tempDir.path}/denied.vault';

      final error = await errorFrom(
        VaultService.create(
          path: path,
          key: await generateAes256GcmKey(),
          algorithm: 'aes-256-gcm',
          capacityBytes: 1024 * 1024,
        ),
      );

      expect(kindOf(error!), 'CryptoError.unsafeLegacyFormatDenied');
      expect(sidecars(path), isEmpty);
      expect(tempDir.listSync(), isEmpty);
    });

    test('the explicit opt-in round trips a segment', () async {
      final path = '${tempDir.path}/optin.vault';
      final key = await generateAes256GcmKey();
      final payload = Uint8List.fromList(List.generate(2048, (i) => i % 256));

      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 1024 * 1024,
        unsafeLegacyPolicy: UnsafeLegacyEvfsPolicy.allowUnauthenticatedV1V2,
      );
      await VaultService.write(
        handle: handle,
        name: 'payload.bin',
        data: payload,
      );
      await VaultService.close(handle: handle);

      final reopened = await VaultService.open(
        path: path,
        key: key,
        unsafeLegacyPolicy: UnsafeLegacyEvfsPolicy.allowUnauthenticatedV1V2,
      );
      final read = await VaultService.read(
        handle: reopened,
        name: 'payload.bin',
      );
      expect(read.data, payload);
      await VaultService.close(handle: reopened);
    });

    test('an earlier opt-in does not authorize the next default open', () async {
      final path = '${tempDir.path}/reopen.vault';
      final key = await generateAes256GcmKey();

      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 1024 * 1024,
        unsafeLegacyPolicy: UnsafeLegacyEvfsPolicy.allowUnauthenticatedV1V2,
      );
      await VaultService.close(handle: handle);

      final before = await File(path).readAsBytes();
      final error = await errorFrom(VaultService.open(path: path, key: key));

      expect(kindOf(error!), 'CryptoError.unsafeLegacyFormatDenied');
      expect(await File(path).readAsBytes(), before);
    });

    test('denial does not depend on the arguments being usable', () async {
      final path = '${tempDir.path}/bad_args.vault';

      // An empty key and an unknown algorithm are both rejected further in, so
      // the denial arriving first means the check ran before either.
      final error = await errorFrom(
        VaultService.create(
          path: path,
          key: Uint8List(0),
          algorithm: 'not-an-algorithm',
          capacityBytes: 1024 * 1024,
        ),
      );

      expect(kindOf(error!), 'CryptoError.unsafeLegacyFormatDenied');
      expect(sidecars(path), isEmpty);
    });
  });

  // These six stubs refuse in Dart and never reach the bridge, so what a
  // packaged consumer gets to check is the shape of the refusal, not an
  // ordering against filesystem access. The Rust suite owns that.
  group('disabled formats', () {
    test('archive export refuses before reading the vault', () async {
      final out = '${tempDir.path}/out.mvex';
      final handle = await VaultService.create(
        path: '${tempDir.path}/source.vault',
        key: await generateAes256GcmKey(),
        algorithm: 'aes-256-gcm',
        capacityBytes: 1024 * 1024,
        unsafeLegacyPolicy: UnsafeLegacyEvfsPolicy.allowUnauthenticatedV1V2,
      );
      addTearDown(() => VaultService.close(handle: handle));

      final error = await errorFrom(
        VaultService.export(
          handle: handle,
          wrappingKey: Uint8List(32),
          exportPath: out,
        ),
      );

      expect(kindOf(error!), 'CryptoError.disabledFormat');
      expect(File(out).existsSync(), isFalse);
    });

    test('archive import refuses before touching either path', () async {
      final dest = '${tempDir.path}/imported.vault';

      final error = await errorFrom(
        VaultService.importVault(
          archivePath: '${tempDir.path}/absent.mvex',
          wrappingKey: Uint8List(32),
          destPath: dest,
          newMasterKey: await generateAes256GcmKey(),
          algorithm: 'aes-256-gcm',
          capacityBytes: 1024 * 1024,
        ),
      );

      expect(kindOf(error!), 'CryptoError.disabledFormat');
      expect(File(dest).existsSync(), isFalse);
    });

    test('each encrypted stream method emits exactly one refusal', () async {
      final input = File('${tempDir.path}/input.bin');
      await input.writeAsBytes(
        Uint8List.fromList(List.generate(65536, (i) => i % 256)),
      );
      final output = '${tempDir.path}/nested/deeper/out.bin';
      final cipher = await createAes256Gcm(key: await generateAes256GcmKey());

      final calls = <String, Stream<double> Function()>{
        'encryptFile': () => StreamingService.encryptFile(
          inputPath: input.path,
          outputPath: output,
          cipher: cipher,
        ),
        'decryptFile': () => StreamingService.decryptFile(
          inputPath: input.path,
          outputPath: output,
          cipher: cipher,
        ),
        'compressAndEncryptFile': () =>
            CompressionService.compressAndEncryptFile(
              inputPath: input.path,
              outputPath: output,
              cipher: cipher,
              config: const CompressionConfig(
                algorithm: CompressionAlgorithm.zstd,
              ),
            ),
        'decryptAndDecompressFile': () =>
            CompressionService.decryptAndDecompressFile(
              inputPath: input.path,
              outputPath: output,
              cipher: cipher,
            ),
      };

      for (final entry in calls.entries) {
        final outcome = await drain(entry.value());

        expect(outcome.values, isEmpty, reason: entry.key);
        expect(outcome.errors, hasLength(1), reason: entry.key);
        expect(
          kindOf(outcome.errors.single),
          'CryptoError.disabledFormat',
          reason: entry.key,
        );
      }

      expect(Directory('${tempDir.path}/nested').existsSync(), isFalse);
    });
  });

  group('stream hashing', () {
    test('streaming BLAKE3 matches the one-shot digest', () async {
      final file = File('${tempDir.path}/hash_me.bin');
      final data = Uint8List.fromList(List.generate(200000, (i) => i % 256));
      await file.writeAsBytes(data);

      final streamed = await StreamingService.hashFile(
        filePath: file.path,
        hasher: await createBlake3(),
      );

      expect(streamed, await blake3Hash(data: data));
      expect(streamed, hasLength(32));
    });

    test('an empty file hashes without reading past it', () async {
      final file = File('${tempDir.path}/empty.bin');
      await file.writeAsBytes(Uint8List(0));

      expect(
        await StreamingService.hashFile(
          filePath: file.path,
          hasher: await createBlake3(),
        ),
        await blake3Hash(data: Uint8List(0)),
      );
    });
  });
}
