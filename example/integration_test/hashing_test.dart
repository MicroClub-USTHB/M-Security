import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:m_security/src/rust/api/hashing.dart';
import 'package:m_security/src/rust/frb_generated.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async => await RustLib.init());

  // -- BLAKE3 tests --

  group('BLAKE3', () {
    test('one-shot hash matches known vector', () async {
      final digest = await blake3Hash(data: utf8.encode('hello world'));
      final hex = _toHex(digest);
      expect(hex,
          'd74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24');
    });

    test('incremental hasher produces same result as one-shot', () async {
      final data = utf8.encode('hello world');

      // One-shot
      final oneshot = await blake3Hash(data: data);

      // Incremental
      final handle = await createBlake3();
      await hasherUpdate(handle: handle, data: data);
      final incremental = await hasherFinalize(handle: handle);

      expect(incremental, oneshot);
    });

    test('algorithm id is blake3', () async {
      final handle = await createBlake3();
      final id = await hasherAlgorithmId(handle: handle);
      expect(id, 'blake3');
    });

    test('reset produces empty hash', () async {
      final handle = await createBlake3();
      await hasherUpdate(handle: handle, data: utf8.encode('some data'));
      await hasherReset(handle: handle);
      final digest = await hasherFinalize(handle: handle);

      // Should match BLAKE3 empty input
      final emptyDigest = await blake3Hash(data: []);
      expect(digest, emptyDigest);
    });
  });

  // -- SHA-3 tests --

  group('SHA-3', () {
    test('one-shot hash matches NIST vector', () async {
      final digest = await sha3Hash(data: utf8.encode('abc'));
      final hex = _toHex(digest);
      expect(hex,
          '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532');
    });

    test('incremental hasher produces same result as one-shot', () async {
      final data = utf8.encode('abc');

      final oneshot = await sha3Hash(data: data);

      final handle = await createSha3();
      await hasherUpdate(handle: handle, data: data);
      final incremental = await hasherFinalize(handle: handle);

      expect(incremental, oneshot);
    });

    test('algorithm id is sha3-256', () async {
      final handle = await createSha3();
      final id = await hasherAlgorithmId(handle: handle);
      expect(id, 'sha3');
    });

    test('reset produces empty hash', () async {
      final handle = await createSha3();
      await hasherUpdate(handle: handle, data: utf8.encode('some data'));
      await hasherReset(handle: handle);
      final digest = await hasherFinalize(handle: handle);

      final emptyDigest = await sha3Hash(data: []);
      expect(digest, emptyDigest);
    });
  });

  // -- Streaming chunk-size tests --

  group('Streaming chunked hashing', () {
    test('BLAKE3: different chunk sizes produce same digest', () async {
      final data = utf8.encode(
          'The quick brown fox jumps over the lazy dog and some more data');

      // One-shot reference
      final reference = await blake3Hash(data: data);

      // Feed in various chunk sizes
      for (final chunkSize in [1, 3, 7, 16, 64, data.length]) {
        final handle = await createBlake3();
        for (var i = 0; i < data.length; i += chunkSize) {
          final end = (i + chunkSize > data.length) ? data.length : i + chunkSize;
          await hasherUpdate(handle: handle, data: data.sublist(i, end));
        }
        final digest = await hasherFinalize(handle: handle);
        expect(digest, reference, reason: 'chunk size $chunkSize');
      }
    });

    test('SHA-3: different chunk sizes produce same digest', () async {
      final data = utf8.encode(
          'The quick brown fox jumps over the lazy dog and some more data');

      final reference = await sha3Hash(data: data);

      for (final chunkSize in [1, 3, 7, 16, 64, data.length]) {
        final handle = await createSha3();
        for (var i = 0; i < data.length; i += chunkSize) {
          final end = (i + chunkSize > data.length) ? data.length : i + chunkSize;
          await hasherUpdate(handle: handle, data: data.sublist(i, end));
        }
        final digest = await hasherFinalize(handle: handle);
        expect(digest, reference, reason: 'chunk size $chunkSize');
      }
    });
  });
}

String _toHex(Uint8List bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}
