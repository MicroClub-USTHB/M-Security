import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:m_security/src/hashing/argon2.dart';
import 'package:m_security/src/rust/core/error.dart';
import 'package:m_security/src/rust/frb_generated.dart';

// A released mobile-preset hash of 'preset_vector'.
const String releasedMobileVector =
    r'$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$rUYVKsKrcBrgqxhUdNkDIkzdd3Df9gC3RP6cEdFyM8k';

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

    test('released mobile vector still verifies', () async {
      await argon2IdVerify(
        phcHash: releasedMobileVector,
        password: 'preset_vector',
      );
    });

    test('password over the ceiling is a policy violation', () async {
      await expectLater(
        argon2IdVerify(
          phcHash: releasedMobileVector,
          password: 'a' * (maxArgon2VerifyPasswordBytes + 1),
        ),
        throwsA(isA<CryptoError_Argon2PolicyViolation>()),
      );
    });

    test('password at the ceiling reaches the verifier', () async {
      await expectLater(
        argon2IdVerify(
          phcHash: releasedMobileVector,
          password: 'a' * maxArgon2VerifyPasswordBytes,
        ),
        throwsA(isA<CryptoError_AuthenticationFailed>()),
      );
    });

    test('work factors above the ceiling are a policy violation', () async {
      const overLimit =
          r'$argon2id$v=19$m=1048576,t=3,p=4$c29tZXNhbHQ$rUYVKsKrcBrgqxhUdNkDIkzdd3Df9gC3RP6cEdFyM8k';

      await expectLater(
        argon2IdVerify(phcHash: overLimit, password: 'preset_vector'),
        throwsA(isA<CryptoError_Argon2PolicyViolation>()),
      );
    });

    test('a non-argon2id variant is a policy violation', () async {
      const argon2i =
          r'$argon2i$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$rUYVKsKrcBrgqxhUdNkDIkzdd3Df9gC3RP6cEdFyM8k';

      await expectLater(
        argon2IdVerify(phcHash: argon2i, password: 'preset_vector'),
        throwsA(isA<CryptoError_Argon2PolicyViolation>()),
      );
    });
  });
}
