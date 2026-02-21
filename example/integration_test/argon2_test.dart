import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:m_security/src/rust/api/hashing/argon2.dart';
import 'package:m_security/src/rust/frb_generated.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async => await RustLib.init());

  group('Argon2id', () {
    test('hash with Mobile preset produces PHC string', () async {
      final hash = await argon2IdHash(
        password: 'test_password',
        preset: Argon2Preset.mobile,
      );

      expect(hash, startsWith(r'$argon2id$'));
      expect(hash, contains('m=65536'));
      expect(hash, contains('t=3'));
      expect(hash, contains('p=4'));
    });

    test('hash with Desktop preset produces PHC string', () async {
      final hash = await argon2IdHash(
        password: 'test_password',
        preset: Argon2Preset.desktop,
      );

      expect(hash, startsWith(r'$argon2id$'));
      expect(hash, contains('m=262144'));
      expect(hash, contains('t=4'));
      expect(hash, contains('p=8'));
    });

    test('verify correct password returns Ok', () async {
      final hash = await argon2IdHash(
        password: 'correct_password',
        preset: Argon2Preset.mobile,
      );

      // Should not throw
      await argon2IdVerify(phcHash: hash, password: 'correct_password');
    });

    test('verify wrong password returns CryptoError', () async {
      final hash = await argon2IdHash(
        password: 'correct_password',
        preset: Argon2Preset.mobile,
      );

      expect(
        () => argon2IdVerify(phcHash: hash, password: 'wrong_password'),
        throwsA(isA<Exception>()),
      );
    });

    test('hash with salt is deterministic', () async {
      const salt = 'c29tZXNhbHQ'; // "somesalt" base64 no-pad

      final hash1 = await argon2IdHashWithSalt(
        password: 'password',
        salt: salt,
        preset: Argon2Preset.mobile,
      );
      final hash2 = await argon2IdHashWithSalt(
        password: 'password',
        salt: salt,
        preset: Argon2Preset.mobile,
      );

      expect(hash1, hash2);
    });

    test('random salt produces unique hashes', () async {
      final hash1 = await argon2IdHash(
        password: 'same_password',
        preset: Argon2Preset.mobile,
      );
      final hash2 = await argon2IdHash(
        password: 'same_password',
        preset: Argon2Preset.mobile,
      );

      expect(hash1, isNot(hash2));
    });
  });
}
