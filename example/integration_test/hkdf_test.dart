import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:m_security/src/kdf/hkdf.dart';
import 'package:m_security/src/rust/frb_generated.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async => await RustLib.init());

  group('HKDF', () {
    Uint8List hexToBytes(String hex) {
      hex = hex.replaceAll(RegExp(r'\s+'), '');
      return Uint8List.fromList(
        List.generate(
          hex.length ~/ 2,
          (i) => int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16),
        ),
      );
    }

    bool bytesEqual(Uint8List a, Uint8List b) {
      if (a.length != b.length) return false;
      for (int i = 0; i < a.length; i++) {
        if (a[i] != b[i]) return false;
      }
      return true;
    }

    test('derive returns requested number of bytes', () {
      final ikm = Uint8List.fromList([1, 2, 3, 4, 5]);
      final salt = Uint8List.fromList([6, 7, 8]);
      final info = Uint8List.fromList([9, 10]);

      for (final len in [16, 32, 48, 64]) {
        final result = MHKDF.derive(
          ikm: ikm,
          salt: salt,
          info: info,
          outputLen: len,
        );

        expect(result.length, len);
      }
    });

    test('same inputs produce same output', () {
      final ikm = Uint8List.fromList([1, 2, 3, 4, 5]);
      final salt = Uint8List.fromList([6, 7, 8]);
      final info = Uint8List.fromList([9, 10]);

      final result1 = MHKDF.derive(
        ikm: ikm,
        salt: salt,
        info: info,
        outputLen: 32,
      );

      final result2 = MHKDF.derive(
        ikm: ikm,
        salt: salt,
        info: info,
        outputLen: 32,
      );

      expect(bytesEqual(result1, result2), true);
    });

    test('different info strings produce different keys', () {
      final ikm = Uint8List.fromList([1, 2, 3, 4, 5]);
      final salt = Uint8List.fromList([6, 7, 8]);

      final key1 = MHKDF.derive(
        ikm: ikm,
        salt: salt,
        info: Uint8List.fromList([9, 10]),
        outputLen: 32,
      );

      final key2 = MHKDF.derive(
        ikm: ikm,
        salt: salt,
        info: Uint8List.fromList([11, 12]),
        outputLen: 32,
      );

      expect(bytesEqual(key1, key2), false);
    });

    test('extract then expand matches one-shot derive', () async {
      final ikm = Uint8List.fromList([1, 2, 3, 4, 5]);
      final salt = Uint8List.fromList([6, 7, 8]);
      final info = Uint8List.fromList([9, 10]);

      final derivedKey = MHKDF.derive(
        ikm: ikm,
        salt: salt,
        info: info,
        outputLen: 32,
      );

      final prk = MHKDF.extract(ikm: ikm, salt: salt);
      final expandedKey = await MHKDF.expand(
        prk: prk,
        info: info,
        outputLen: 32,
      );

      expect(bytesEqual(derivedKey, expandedKey), true);
    });
    test('zero output length throws error', () {
      final ikm = Uint8List.fromList([1, 2, 3]);
      final salt = Uint8List.fromList([4, 5, 6]);
      final info = Uint8List.fromList([7, 8, 9]);

      expect(
        () => MHKDF.derive(ikm: ikm, salt: salt, info: info, outputLen: 0),
        throwsA(isA<Exception>()),
      );
    });

    test('empty salt works', () {
      final ikm = Uint8List.fromList([1, 2, 3, 4, 5]);
      final info = Uint8List.fromList([9, 10]);

      final result = MHKDF.derive(
        ikm: ikm,
        salt: null,
        info: info,
        outputLen: 32,
      );

      expect(result.length, 32);
    });

    test('RFC 5869 Test Case 1', () {
      final ikm = hexToBytes('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
      final salt = hexToBytes('000102030405060708090a0b0c');
      final info = hexToBytes('f0f1f2f3f4f5f6f7f8f9');
      final expectedOkm = hexToBytes(
        '3cb25f25faacd57a90434f64d0362f2a'
        '2d2d0a90cf1a5a4c5db02d56ecc4c5bf'
        '34007208d5b887185865',
      );

      final result = MHKDF.derive(
        ikm: ikm,
        salt: salt,
        info: info,
        outputLen: 42,
      );

      expect(bytesEqual(result, expectedOkm), true);
    });

    test('RFC 5869 Test Case 2', () {
      final ikm = hexToBytes(
        '000102030405060708090a0b0c0d0e0f'
        '101112131415161718191a1b1c1d1e1f'
        '202122232425262728292a2b2c2d2e2f'
        '303132333435363738393a3b3c3d3e3f'
        '404142434445464748494a4b4c4d4e4f',
      );
      final salt = hexToBytes(
        '606162636465666768696a6b6c6d6e6f'
        '707172737475767778797a7b7c7d7e7f'
        '808182838485868788898a8b8c8d8e8f'
        '909192939495969798999a9b9c9d9e9f'
        'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
      );
      final info = hexToBytes(
        'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
        'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'
        'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf'
        'e0e1e2e3e4e5e6e7e8e9eaebecedeeef'
        'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
      );
      final expectedOkm = hexToBytes(
        'b11e398dc80327a1c8e7f78c596a4934'
        '4f012eda2d4efad8a050cc4c19afa97c'
        '59045a99cac7827271cb41c65e590e09'
        'da3275600c2f09b8367793a9aca3db71'
        'cc30c58179ec3e87c14c01d5c1f3434f'
        '1d87',
      );

      final result = MHKDF.derive(
        ikm: ikm,
        salt: salt,
        info: info,
        outputLen: 82,
      );

      expect(bytesEqual(result, expectedOkm), true);
    });

    test('RFC 5869 Test Case 3', () {
      final ikm = hexToBytes('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
      final salt = Uint8List(0);
      final info = Uint8List(0);
      final expectedOkm = hexToBytes(
        '8da4e775a563c18f715f802a063c5a31'
        'b8a11f5c5ee1879ec3454e5f3c738d2d'
        '9d201395faa4b61a96c8',
      );

      final result = MHKDF.derive(
        ikm: ikm,
        salt: salt,
        info: info,
        outputLen: 42,
      );

      expect(bytesEqual(result, expectedOkm), true);
    });
  });
}
