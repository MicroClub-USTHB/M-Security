import 'dart:typed_data';
import 'package:m_security/src/rust/api/kdf/hkdf.dart' as rust_hkdf;

/// HKDF-SHA256 key derivation functions.
///
/// HKDF (HMAC-based Extract-and-Expand Key Derivation Function) is a
/// cryptographic key derivation function that converts weak key material
/// (like passwords) into strong cryptographic keys.

class MHKDF {
  MHKDF._();

  /// Performs full HKDF (extract + expand) in one step.
  static Uint8List derive({
    required Uint8List ikm,
    Uint8List? salt,
    required Uint8List info,
    required int outputLen,
  }){
    // Validate output length bounds (RFC 5869 limit for SHA-256).
    if (outputLen<=0){
      throw Exception('Output length must be positive');
    }
    if(outputLen>8160){
      throw Exception('Output length must be less than 8160 bytes, got $outputLen',);
    }
    try{
      return rust_hkdf.hkdfDerive(
        ikm: ikm,
        salt: salt ?? Uint8List(0),
        info: info,
        outputLen: BigInt.from(outputLen),
      );
    }catch(e){
      throw Exception('MHKDF derive failed: $e');
    }
  }
  /// Performs HKDF-Extract.
  /// Produces a pseudorandom key (PRK) from input key material.
  static Uint8List extract({
    required Uint8List ikm,
    Uint8List? salt,
  }){
    try {
      return rust_hkdf.hkdfExtract(  
        ikm: ikm,
        salt: salt ?? Uint8List(0),
      );
    }catch(e){
      throw Exception('MHKDF extract failed: $e');
    }
  }
  /// Performs HKDF-Expand.
  ///Expands a prk into a derived key
  static Future<Uint8List> expand({
    required Uint8List prk,
    required Uint8List info,
    required int outputLen,
  })async{
    if(outputLen<=0){
      throw Exception('Output length must be positive, got $outputLen');
    }
    if(outputLen>8160){
      throw Exception(
        'Output length must be less than 8160 bytes, got $outputLen',
      );
    }
    try {
      return await rust_hkdf.hkdfExpand(
        prk: prk,
        info:info,
        outputLen: BigInt.from(outputLen),
      );
    } catch(e){
      throw Exception('MHKDF expand failed: $e');
    }
  }
}
