import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:m_security/src/encryption/chacha20.dart';
import 'package:m_security/src/encryption/aes_gcm.dart';
import 'package:m_security/src/rust/api/encryption/chacha20.dart' as rust_chacha;
import 'package:m_security/src/rust/frb_generated.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async => await RustLib.init());

  group('ChaCha20-Poly1305', () {
    test('encrypt then decrypt returns original data', () async {
      final service = Chacha20Service();
      await service.initWithRandomKey();

      final original = Uint8List.fromList('hello ChaCha20'.codeUnits);
      final encrypted = await service.encrypt(original);
      final decrypted = await service.decrypt(encrypted);

      expect(decrypted, equals(original));
    });

    test('wrong key throws error', () async {
      final service1 = Chacha20Service();
      await service1.initWithRandomKey();

      final service2 = Chacha20Service();
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
      final service = Chacha20Service();
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
      final service = Chacha20Service();
      await service.initWithRandomKey();

      final empty = Uint8List(0);
      final encrypted = await service.encrypt(empty);
      final decrypted = await service.decrypt(encrypted);

      expect(decrypted, equals(empty));
    });

    test('key generation returns 32 bytes', () async {
      final key = await rust_chacha.generateChachaKey();
      expect(key.length, equals(32));
    });

    test('same data encrypted twice gives different output', () async {
      final service = Chacha20Service();
      await service.initWithRandomKey();

      final data = Uint8List.fromList('same data'.codeUnits);
      final enc1 = await service.encrypt(data);
      final enc2 = await service.encrypt(data);

      expect(enc1, isNot(equals(enc2)));
    });

    test('AES-GCM ciphertext cannot be decrypted with ChaCha20', () async {

      //encrypt with AES-GCM
      final aesService = AesGcmService();
      await aesService.initWithRandomKey();
      final aesEncrypted = await aesService.encrypt(
        Uint8List.fromList('cross test'.codeUnits),
      );

      final chachaService = Chacha20Service();
      await chachaService.initWithRandomKey();

      //try to decrypt with chacha
      expect(
        () => chachaService.decrypt(aesEncrypted),
        throwsA(anything),
      );
    });
  });
}