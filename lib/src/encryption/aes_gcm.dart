import 'dart:convert';
import 'dart:typed_data';
import 'package:m_security/src/rust/api/encryption.dart' as rust_encryption;

class AesGcmService {
  rust_encryption.CipherHandle? _cipher;

  Future<void> initWithRandomKey() async {
    final key = await rust_encryption.generateAes256GcmKey();
    _cipher = await rust_encryption.createAes256Gcm(key: key);
  }

  Future<Uint8List> encrypt(Uint8List data) async {
    final cipher = _cipher;
    if (cipher == null) {
      throw StateError(
        'Cipher not initialized. Call initWithRandomKey() first.',
      );
    }

    return rust_encryption.encrypt(
      cipher: cipher,
      plaintext: data,
      aad: Uint8List(0),
    );
  }

  Future<Uint8List> decrypt(Uint8List encrypted) async {
    final cipher = _cipher;
    if (cipher == null) {
      throw StateError(
        'Cipher not initialized. Call initWithRandomKey() first.',
      );
    }

    return rust_encryption.decrypt(
      cipher: cipher,
      ciphertext: encrypted,
      aad: Uint8List(0),
    );
  }

  Future<Uint8List> encryptString(String text) async {
    final bytes = Uint8List.fromList(utf8.encode(text));
    return encrypt(bytes);
  }

  Future<String> decryptString(Uint8List encrypted) async {
    final bytes = await decrypt(encrypted);
    return utf8.decode(bytes);
  }
}
