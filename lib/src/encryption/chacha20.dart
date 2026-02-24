import 'dart:typed_data';
import 'package:m_security/src/rust/api/encryption.dart' as rust_encryption;

class Chacha20Service {

  rust_encryption.CipherHandle? _cipher;

  Future<void> initWithRandomKey() async {
    final key = await rust_encryption.generateChacha20Poly1305Key();
    _cipher = await rust_encryption.createChacha20Poly1305(key: key);
  }

  Future<Uint8List> encrypt(Uint8List plaintext, {Uint8List? aad}) async {
    if (_cipher == null) throw Exception('Cipher not initialized');

    return rust_encryption.encrypt(
      cipher: _cipher!,
      plaintext: plaintext,
      aad: aad ?? Uint8List(0),
    );
  }

  Future<Uint8List> decrypt(Uint8List ciphertext, {Uint8List? aad}) async {
    if (_cipher == null) throw Exception('Cipher not initialized');

    return rust_encryption.decrypt(
      cipher: _cipher!,
      ciphertext: ciphertext,
      aad: aad ?? Uint8List(0),
    );
  }

  Future<Uint8List> encryptString(String plaintext, {String? aad}) async {
    return encrypt(
      Uint8List.fromList(plaintext.codeUnits),
      aad: aad != null ? Uint8List.fromList(aad.codeUnits) : null,
    );
  }

  Future<String> decryptString(Uint8List ciphertext, {String? aad}) async {
    final decrypted = await decrypt(
      ciphertext,
      aad: aad != null ? Uint8List.fromList(aad.codeUnits) : null,
    );
    return String.fromCharCodes(decrypted);
  }
}
