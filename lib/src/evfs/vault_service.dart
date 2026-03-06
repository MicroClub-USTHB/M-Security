import 'package:m_security/src/rust/api/evfs.dart' as rust_evfs;
import 'package:m_security/src/rust/api/compression.dart';
import 'dart:typed_data';

/// Encrypted Virtual File System — named segment storage in a .vault container.
///
/// Compression is optional on write (pass [CompressionConfig]) and
/// automatic on read (algorithm stored per-segment in the vault index).
class VaultService {
  VaultService._();

  /// Create a new vault file.
  ///
  /// [algorithm] must be "aes-256-gcm" or "chacha20-poly1305".
  static Future<rust_evfs.VaultHandle> create({
    required String path,
    required Uint8List key,
    required String algorithm,
    required int capacityBytes,
  }) {
    return rust_evfs.vaultCreate(
      path: path,
      key: key,
      algorithm: algorithm,
      capacityBytes: BigInt.from(capacityBytes),
    );
  }

  /// Open an existing vault (runs WAL recovery if needed).
  static Future<rust_evfs.VaultHandle> open({
    required String path,
    required Uint8List key,
  }) {
    return rust_evfs.vaultOpen(path: path, key: key);
  }
  
  /// Write (or overwrite) a named segment.
  ///
  /// [compression] is optional — defaults to no compression.
  /// MIME-aware skip: if [name] has an already-compressed extension
  /// (e.g., ".jpg"), compression is bypassed automatically.
  static Future<void> write({
    required rust_evfs.VaultHandle handle,
    required String name,
    required Uint8List data,
    CompressionConfig? compression,
  }) {
    return rust_evfs.vaultWrite(
      handle: handle,
      name: name,
      data: data,
      compression: compression,
    );
  }

  /// Read a named segment. Decompression is automatic.
  static Future<Uint8List> read({
    required rust_evfs.VaultHandle handle,
    required String name,
  }) {
    return rust_evfs.vaultRead(handle: handle, name: name);
  }

  /// Delete a named segment (securely erased from disk).
  static Future<void> delete({
    required rust_evfs.VaultHandle handle,
    required String name,
  }) {
    return rust_evfs.vaultDelete(handle: handle, name: name);
  }

  /// List all segment names.
  static Future<List<String>> list({
    required rust_evfs.VaultHandle handle,
  }) {
    return rust_evfs.vaultList(handle: handle);
  }

  /// Get vault capacity info.
  static Future<rust_evfs.VaultCapacityInfo> capacity({
    required rust_evfs.VaultHandle handle,
  }) {
    return rust_evfs.vaultCapacity(handle: handle);
  }

  /// Close the vault (release lock, zeroize keys).
  static Future<void> close({
    required rust_evfs.VaultHandle handle,
  }) {
    return rust_evfs.vaultClose(handle: handle);
  }
}