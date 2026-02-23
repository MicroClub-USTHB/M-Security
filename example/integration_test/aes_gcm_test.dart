import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:m_security/src/encryption/aes_gcm.dart';
import 'package:m_security/src/rust/api/encryption/aes_gcm.dart' as rust;
import 'package:m_security/src/rust/frb_generated.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async => await RustLib.init());

  group('AES-GCM', () {
    test('encrypt then decrypt returns original data', () async {
      final service = AesGcmService();
      await service.initWithRandomKey();

      final original = Uint8List.fromList('hello AES-GCM'.codeUnits);
      final encrypted = await service.encrypt(original);
      final decrypted = await service.decrypt(encrypted);

      expect(decrypted, equals(original));
    });

    test('wrong key throws error', () async {
      final service1 = AesGcmService();
      await service1.initWithRandomKey();

      final service2 = AesGcmService();
      await service2.initWithRandomKey();

      final encrypted = await service1.encrypt(
        Uint8List.fromList('secret data'.codeUnits),
      );

      expect(
        () => service2.decrypt(encrypted),
        throwsA(anything),
      );
    });

    test('tampered data throws error', () async {
      final service = AesGcmService();
      await service.initWithRandomKey();

      final encrypted = await service.encrypt(
        Uint8List.fromList('tamper test'.codeUnits),
      );

      // Flip a byte in the ciphertext
      encrypted[encrypted.length - 1] ^= 0xFF;

      expect(
        () => service.decrypt(encrypted),
        throwsA(anything),
      );
    });

    test('encrypting/decrypting empty data works', () async {
      final service = AesGcmService();
      await service.initWithRandomKey();

      final empty = Uint8List(0);
      final encrypted = await service.encrypt(empty);
      final decrypted = await service.decrypt(encrypted);

      expect(decrypted, equals(empty));
    });

    test('key generation returns 32 bytes', () async {
      final key = await rust.generateAesKey();
      expect(key.length, equals(32));
    });

    test('same data encrypted twice gives different output', () async {
      final service = AesGcmService();
      await service.initWithRandomKey();

      final data = Uint8List.fromList('same data'.codeUnits);
      final enc1 = await service.encrypt(data);
      final enc2 = await service.encrypt(data);

      expect(enc1, isNot(equals(enc2)));
    });
  });
}
