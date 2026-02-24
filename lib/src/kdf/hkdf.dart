import 'dart:typed_data';
import 'package:m_security/src/rust/api/kdf/hkdf.dart' as rust_hkdf;

/// HKDF-SHA256 key derivation functions.
///
/// HKDF (HMAC-based Extract-and-Expand Key Derivation Function) derives
/// strong cryptographic keys from input key material (RFC 5869).
class MHKDF {
  MHKDF._();

  /// Performs full HKDF (extract + expand) in one step.
  static Uint8List derive({
    required Uint8List ikm,
    Uint8List? salt,
    required Uint8List info,
    required int outputLen,
  }) {
    _validateOutputLen(outputLen);
    return rust_hkdf.hkdfDerive(
      ikm: ikm,
      salt: salt ?? Uint8List(0),
      info: info,
      outputLen: BigInt.from(outputLen),
    );
  }

  /// Performs HKDF-Extract.
  /// Produces a pseudorandom key (PRK) from input key material.
  static Uint8List extract({
    required Uint8List ikm,
    Uint8List? salt,
  }) {
    return rust_hkdf.hkdfExtract(
      ikm: ikm,
      salt: salt ?? Uint8List(0),
    );
  }

  /// Performs HKDF-Expand.
  /// Expands a PRK into a derived key of the requested length.
  static Future<Uint8List> expand({
    required Uint8List prk,
    required Uint8List info,
    required int outputLen,
  }) async {
    _validateOutputLen(outputLen);
    return rust_hkdf.hkdfExpand(
      prk: prk,
      info: info,
      outputLen: BigInt.from(outputLen),
    );
  }

  static void _validateOutputLen(int outputLen) {
    if (outputLen <= 0) {
      throw ArgumentError.value(outputLen, 'outputLen', 'must be positive');
    }
    // SHA-256 HKDF max: 255 * 32 = 8160
    if (outputLen > 8160) {
      throw ArgumentError.value(
        outputLen, 'outputLen', 'must be <= 8160 bytes (RFC 5869 limit for SHA-256)',
      );
    }
  }
}
