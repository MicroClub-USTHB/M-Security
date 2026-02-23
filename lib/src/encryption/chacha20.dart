import 'dart:typed_data';
import 'package:m_security/src/rust/api/encryption/chacha20.dart' as rust_chacha;

class Chacha20Service {

  rust_chacha.ChaCha20Poly1305Cipher? _cipher;

  Future<void> initWithRandomKey() async {

    final key = await rust_chacha.generateChachaKey();
    _cipher = await rust_chacha.ChaCha20Poly1305Cipher.newInstance(key: key);

  }

  Future<Uint8List> encrypt(Uint8List plaintext, {Uint8List? aad}) async {

    if (_cipher == null) throw Exception('Cipher not initialized');

    return await _cipher!.encrypt(
      plaintext: plaintext,
      aad: aad ?? Uint8List(0),
    );

  }

  Future<Uint8List> decrypt(Uint8List ciphertext, {Uint8List? aad}) async {

    if (_cipher == null) throw Exception('Cipher not initialized');

    return await _cipher!.decrypt(
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