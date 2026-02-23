import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:m_security/src/encryption/aes_gcm.dart';
import 'package:m_security/src/rust/frb_generated.dart';

void main() {

  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  
  late AesGcmService service; 

  setUpAll(() async {


    try {
      await RustLib.init();
      print('RustLib initialized successfully');
    } catch (e, st) {
      print('Error initializing RustLib: $e\n$st');
    }
  });

  group('AES-GCM', () {

    test('encrypt then decrypt returns original data', () async {

        final original = 'Hello Nayla';
        final encrypted = await service.encryptString(original);
        final decrypted = await service.decryptString(encrypted);

        expect(decrypted, original);

      }
    );

    test('verify Key, throws error if wrong', () async {

        final original = 'Hello Nayla';
        final wrongService = AesGcmService();
        await wrongService.initWithRandomKey();  

        final encrypted = await service.encryptString(original);

        expect(
          () async => await wrongService.decryptString(encrypted),
          throwsA(isA<Exception>()),
        );

      }
    );

    test('throws error if data is tempered', () async {
       }
     );

    test('encrypting/decrypting empty data works', () async {
       }
    );

    test('key generation returns 32 bytes', () async {
      }
    );

    test('same data encrypted twice gives different output', () async {
      }
    );

  });
}