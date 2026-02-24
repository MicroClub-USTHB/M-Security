import 'dart:typed_data';
import 'package:m_security/src/rust/api/encryption.dart' as rust_encryption;

class AesGcmService {

  rust_encryption.CipherHandle? _cipher;

  Future<void> initWithRandomKey() async {
    final key = await rust_encryption.generateAes256GcmKey();
    _cipher = await rust_encryption.createAes256Gcm(key: key);
  }

  Future<Uint8List> encrypt(Uint8List data) async {
    if (_cipher == null) {
      throw Exception("cipher is not initialized.");
    }

    return rust_encryption.encrypt(
      cipher: _cipher!,
      plaintext: data,
      aad: Uint8List(0),
    );
  }

  Future<Uint8List> decrypt(Uint8List encrypted) async {
    if (_cipher == null) {
      throw Exception("cipher is not initialized.");
    }

    return rust_encryption.decrypt(
      cipher: _cipher!,
      ciphertext: encrypted,
      aad: Uint8List(0),
    );
  }

  Future<Uint8List> encryptString(String text) async {
    final bytes = Uint8List.fromList(text.codeUnits);
    return encrypt(bytes);
  }

  Future<String> decryptString(Uint8List encrypted) async {
    final bytes = await decrypt(encrypted);
    return String.fromCharCodes(bytes);
  }
}
