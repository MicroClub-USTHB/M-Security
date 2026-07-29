import 'package:flutter_test/flutter_test.dart';
import 'package:m_security/src/hashing/argon2.dart';
import 'package:m_security/src/rust/core/error.dart';
import 'package:m_security/src/rust/frb_generated.io.dart'
    show MAX_VERIFY_PASSWORD_BYTES;

// A released mobile-preset hash of 'preset_vector'.
const String _vector =
    r'$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$rUYVKsKrcBrgqxhUdNkDIkzdd3Df9gC3RP6cEdFyM8k';

Future<Object?> _verifyError(String password) async {
  try {
    await argon2IdVerify(phcHash: _vector, password: password);
  } catch (error) {
    return error;
  }
  return null;
}

void main() {
  // RustLib is deliberately never initialised. An over-ceiling password has to
  // be rejected before the call reaches the bridge, so these cases pass without
  // a native library, and the sizes that are allowed through fail for the
  // missing library instead.
  group('argon2IdVerify password ceiling', () {
    // The Dart ceiling is a separate literal from the native one, so nothing but
    // this keeps the two boundaries from drifting apart.
    test('matches the ceiling the native side enforces', () {
      expect(maxArgon2VerifyPasswordBytes, MAX_VERIFY_PASSWORD_BYTES);
    });

    test('one byte over the ceiling is a policy violation', () async {
      final error = await _verifyError('a' * (maxArgon2VerifyPasswordBytes + 1));

      expect(error, isA<CryptoError_Argon2PolicyViolation>());
      expect(
        (error as CryptoError_Argon2PolicyViolation).field0,
        contains('$maxArgon2VerifyPasswordBytes UTF-8 bytes'),
      );
    });

    test('the ceiling and one byte under it are passed on', () async {
      for (final length in [
        maxArgon2VerifyPasswordBytes - 1,
        maxArgon2VerifyPasswordBytes,
      ]) {
        final error = await _verifyError('a' * length);

        expect(error, isNotNull, reason: '$length bytes reached no bridge');
        expect(
          error,
          isNot(isA<CryptoError_Argon2PolicyViolation>()),
          reason: '$length bytes was rejected by the Dart check',
        );
      }
    });

    test('the ceiling counts UTF-8 bytes, not characters', () async {
      // 512 characters, 512 UTF-16 code units, 1536 UTF-8 bytes.
      final error = await _verifyError('€' * 512);

      expect(error, isA<CryptoError_Argon2PolicyViolation>());
    });

    test('an empty password is passed on', () async {
      final error = await _verifyError('');

      expect(error, isNot(isA<CryptoError_Argon2PolicyViolation>()));
    });
  });
}
