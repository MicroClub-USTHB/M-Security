import 'dart:typed_data';
import 'package:m_security/src/rust/api/encryption/aes_gcm.dart' as rust_aes_gcm;

class AesGcmService {

  rust_aes_gcm.Aes256GcmCipher? _cipher;

  Future<void> initWithRandomKey() async {
    final key = await rust_aes_gcm.generateAesKey();
    _cipher = await rust_aes_gcm.Aes256GcmCipher.newInstance(key: key);
  }

  Future<Uint8List> encrypt(Uint8List data) async {

    if (_cipher == null) {
      throw Exception("cipher is not initialized. ");
    }

    return _cipher!.encrypt(
      plaintext: data,
      //AAD = Additional Authenticated Data (optional extra data to verify integrity, empty for now)
      aad: Uint8List(0),
    );
  }

  Future<Uint8List> decrypt(Uint8List encrypted) async {

    if (_cipher == null) {
      throw Exception("cipher is not initialized.");
    }

    return _cipher!.decrypt(
      ciphertext: encrypted,
      aad: Uint8List(0),
    );

  }

  //helper functions to avoid repeating string-to-bytes conversion each time

  Future<Uint8List> encryptString(String text) async {
    final bytes = Uint8List.fromList(text.codeUnits);
    return encrypt(bytes);
  }

  Future<String> decryptString(Uint8List encrypted) async {
    final bytes = await decrypt(encrypted);
    return String.fromCharCodes(bytes);
  }



}