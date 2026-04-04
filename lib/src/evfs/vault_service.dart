import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_rust_bridge/flutter_rust_bridge.dart'
    show RustStreamSink;
import 'package:m_security/src/rust/api/evfs.dart' as rust_evfs;
import 'package:m_security/src/rust/api/evfs/types.dart' as rust_types;
import 'package:m_security/src/rust/api/compression.dart';

/// Encrypted Virtual File System — named segment storage in a .vault container.
///
/// Compression is optional on write (pass [CompressionConfig]) and
/// automatic on read (algorithm stored per-segment in the vault index).
class VaultService {
  VaultService._();

  /// Create a new vault file.
  ///
  /// [algorithm] must be "aes-256-gcm" or "chacha20-poly1305".
  static Future<rust_types.VaultHandle> create({
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
  static Future<rust_types.VaultHandle> open({
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
    required rust_types.VaultHandle handle,
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

  /// Write a named segment from a Dart [Stream<Uint8List>].
  ///
  /// Pipes [data] through a temporary file on disk so that Dart RAM usage
  /// is bounded to a single chunk. [totalSize] must equal the exact number
  /// of bytes that [data] will emit.
  ///
  /// [onProgress] is called with values in (0.0, 1.0] as chunks are encrypted.
  static Future<void> writeStream({
    required rust_types.VaultHandle handle,
    required String name,
    required int totalSize,
    required Stream<Uint8List> data,
    void Function(double progress)? onProgress,
  }) async {
    final tempDir = await Directory.systemTemp.createTemp('vault_write_stream');
    final tempFile = File('${tempDir.path}/payload.bin');

    try {
      // Write each incoming chunk straight to disk — only one chunk lives in
      // Dart memory at a time.
      final raf = await tempFile.open(mode: FileMode.writeOnly);
      int bytesReceived = 0;

      try {
        await for (final chunk in data) {
          final prevBytes = bytesReceived;
          bytesReceived += chunk.length;
          if (bytesReceived > totalSize) {
            throw ArgumentError(
              'writeStream: stream overflow — '
              'received $bytesReceived bytes '
              '(chunk of ${chunk.length} at offset $prevBytes) '
              'but totalSize is $totalSize',
            );
          }
          await raf.writeFrom(chunk);
        }
      } finally {
        await raf.close();
      }

      if (bytesReceived != totalSize) {
        throw ArgumentError(
          'writeStream: stream underflow — '
          'received $bytesReceived bytes but totalSize is $totalSize',
        );
      }

      // Delegate to vaultWriteFile which reads the temp file in 64 KB chunks
      // inside Rust — keeping the end-to-end memory footprint bounded.
      final progressStream = _guardedStream(
        () => rust_evfs.vaultWriteFile(
          handle: handle,
          name: name,
          filePath: tempFile.path,
        ),
      );

      if (onProgress != null) {
        await for (final p in progressStream) {
          onProgress(p);
        }
      } else {
        await progressStream.drain<void>();
      }
    } finally {
      await tempDir.delete(recursive: true);
    }
  }

  /// Read a named segment. Decompression is automatic.
  static Future<Uint8List> read({
    required rust_types.VaultHandle handle,
    required String name,
  }) {
    return rust_evfs.vaultRead(handle: handle, name: name);
  }

  /// Read a named segment as a stream of decrypted chunks.
  ///
  /// [onProgress] is called with values in (0.0, 1.0] as chunks are decrypted.
  static Stream<Uint8List> readStream({
    required rust_types.VaultHandle handle,
    required String name,
    void Function(double progress)? onProgress,
  }) {
    StreamSubscription<Uint8List>? dataSub;
    StreamSubscription<double>? progressSub;

    final controller = StreamController<Uint8List>(
      onCancel: () {
        dataSub?.cancel();
        progressSub?.cancel();
      },
    );

    runZonedGuarded(
      () {
        final dataSink = RustStreamSink<Uint8List>();
        final progressSink = RustStreamSink<double>();

        // Kick off the Rust call first — this triggers setupAndSerialize
        // on both sinks, initializing their internal streams.
        final rustFuture = rust_evfs.vaultReadStream(
          handle: handle,
          name: name,
          verifyChecksum: true,
          sink: dataSink,
          onProgress: progressSink,
        );

        // Now that FRB has serialized the sinks, .stream is available.
        dataSub = dataSink.stream.listen(
          controller.add,
          onError: (Object e, StackTrace s) {
            if (!controller.isClosed) {
              controller.addError(e, s);
              controller.close();
            }
          },
          onDone: () {
            // Schedule the close one event-loop turn later so that any
            // pending error arriving from the vaultReadStream Future
            // can still be forwarded before the controller is closed.
            Future<void>(() {
              if (!controller.isClosed) controller.close();
            });
          },
          cancelOnError: true,
        );

        if (onProgress != null) {
          progressSub = progressSink.stream.listen(onProgress);
        }

        rustFuture.catchError((Object e, StackTrace s) {
          if (!controller.isClosed) {
            controller.addError(e, s);
            controller.close();
          }
        });
      },
      // Safety net for any unexpected zone errors (e.g. internal FRB bugs).
      (Object e, StackTrace s) {
        if (!controller.isClosed) {
          controller.addError(e, s);
          controller.close();
        }
      },
    );

    return controller.stream;
  }

  /// Delete a named segment (securely erased from disk).
  static Future<void> delete({
    required rust_types.VaultHandle handle,
    required String name,
  }) {
    return rust_evfs.vaultDelete(handle: handle, name: name);
  }

  /// List all segment names.
  static Future<List<String>> list({required rust_types.VaultHandle handle}) {
    return rust_evfs.vaultList(handle: handle);
  }

  /// Get vault capacity info.
  static Future<rust_types.VaultCapacityInfo> capacity({
    required rust_types.VaultHandle handle,
  }) {
    return rust_evfs.vaultCapacity(handle: handle);
  }

  /// Get vault health and diagnostic info (read-only, no I/O).
  static Future<rust_types.VaultHealthInfo> health({
    required rust_types.VaultHandle handle,
  }) {
    return rust_evfs.vaultHealth(handle: handle);
  }

  /// Defragment the vault: compact segments, coalesce free space.
  ///
  /// Each segment move is WAL-protected for crash safety.
  /// Returns a [DefragResult] with move count and bytes reclaimed.
  static Future<rust_types.DefragResult> defragment({
    required rust_types.VaultHandle handle,
  }) {
    return rust_evfs.vaultDefragment(handle: handle);
  }

  /// Resize the vault data region capacity.
  ///
  /// Grow: extends file with CSPRNG-filled space.
  /// Shrink: validates segments fit, then truncates.
  /// Throws if shrinking below used space.
  static Future<void> resize({
    required rust_types.VaultHandle handle,
    required int newCapacityBytes,
  }) {
    return rust_evfs.vaultResize(
      handle: handle,
      newCapacity: BigInt.from(newCapacityBytes),
    );
  }

  /// Rotate the vault's master key (re-encrypts all data).
  ///
  /// Returns a new [VaultHandle] — the old handle is invalidated.
  /// If interrupted, open the vault with the old key to recover.
  static Future<rust_types.VaultHandle> rotateKey({
    required rust_types.VaultHandle handle,
    required Uint8List newKey,
  }) {
    return rust_evfs.vaultRotateKey(handle: handle, newKey: newKey);
  }

  /// Export the vault to a portable encrypted archive (.mvex).
  ///
  /// The archive is encrypted with a random ephemeral key wrapped by
  /// [wrappingKey]. Share the wrapping key out-of-band for import.
  static Future<void> export({
    required rust_types.VaultHandle handle,
    required Uint8List wrappingKey,
    required String exportPath,
  }) {
    return rust_evfs.vaultExport(
      handle: handle,
      wrappingKey: wrappingKey,
      exportPath: exportPath,
    );
  }

  /// Import a vault from an encrypted archive (.mvex).
  ///
  /// Creates a new vault at [destPath] re-encrypted under [newMasterKey].
  static Future<rust_types.VaultHandle> importVault({
    required String archivePath,
    required Uint8List wrappingKey,
    required String destPath,
    required Uint8List newMasterKey,
    required String algorithm,
    required int capacityBytes,
  }) {
    return rust_evfs.vaultImport(
      archivePath: archivePath,
      wrappingKey: wrappingKey,
      destPath: destPath,
      newMasterKey: newMasterKey,
      algorithm: algorithm,
      capacityBytes: BigInt.from(capacityBytes),
    );
  }

  /// Close the vault (release lock, zeroize keys).
  static Future<void> close({required rust_types.VaultHandle handle}) {
    return rust_evfs.vaultClose(handle: handle);
  }

  // Same one from compression_service.dart
  static Stream<double> _guardedStream(Stream<double> Function() factory) {
    final controller = StreamController<double>();
    runZonedGuarded(
      () {
        factory().listen(
          controller.add,
          onError: controller.addError,
          onDone: () {
            // FRB delivers zone errors after the stream closes; delay the
            // controller close by one event-loop turn so they arrive first.
            Future<void>(() {
              if (!controller.isClosed) controller.close();
            });
          },
        );
      },
      (Object error, StackTrace stack) {
        if (!controller.isClosed) {
          controller.addError(error, stack);
          controller.close();
        }
      },
    );
    return controller.stream;
  }
}
