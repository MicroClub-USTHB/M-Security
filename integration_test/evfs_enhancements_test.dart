import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:m_security/src/rust/api/encryption.dart';
import 'package:m_security/src/rust/frb_generated.dart';
import 'package:m_security/src/evfs/vault_service.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async => await RustLib.init());

  group('Segment Metadata', () {
    late Directory tempDir;
    setUp(() async {
      tempDir = await Directory.systemTemp.createTemp('meta_test');
    });
    tearDown(() async {
      await tempDir.delete(recursive: true);
    });

    test('write with metadata, read back matches', () async {
      final path = '${tempDir.path}/meta.vault';
      final key = await generateAes256GcmKey();

      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 2 * 1024 * 1024,
      );

      final data = Uint8List.fromList([1, 2, 3, 4, 5]);
      final metadata = {'mime': 'application/octet-stream', 'author': 'test'};

      await VaultService.write(
        handle: handle,
        name: 'doc.bin',
        data: data,
        metadata: metadata,
      );

      final result = await VaultService.read(handle: handle, name: 'doc.bin');
      expect(result.data, data);
      expect(result.metadata, metadata);

      await VaultService.close(handle: handle);
    });

    test('write without metadata returns empty map', () async {
      final path = '${tempDir.path}/nometa.vault';
      final key = await generateAes256GcmKey();

      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 2 * 1024 * 1024,
      );

      final data = Uint8List.fromList([10, 20, 30]);
      await VaultService.write(handle: handle, name: 'plain.bin', data: data);

      final result = await VaultService.read(
        handle: handle,
        name: 'plain.bin',
      );
      expect(result.data, data);
      expect(result.metadata, isEmpty);

      await VaultService.close(handle: handle);
    });

    test('overwrite with different metadata replaces old', () async {
      final path = '${tempDir.path}/overwrite_meta.vault';
      final key = await generateAes256GcmKey();

      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 2 * 1024 * 1024,
      );

      final data = Uint8List.fromList([1, 2, 3]);
      await VaultService.write(
        handle: handle,
        name: 'file.bin',
        data: data,
        metadata: {'version': '1'},
      );

      // Overwrite with new metadata
      final newData = Uint8List.fromList([4, 5, 6]);
      await VaultService.write(
        handle: handle,
        name: 'file.bin',
        data: newData,
        metadata: {'version': '2', 'updated': 'true'},
      );

      final result = await VaultService.read(handle: handle, name: 'file.bin');
      expect(result.data, newData);
      expect(result.metadata, {'version': '2', 'updated': 'true'});

      await VaultService.close(handle: handle);
    });

    test('metadata survives close and reopen', () async {
      final path = '${tempDir.path}/persist_meta.vault';
      final key = await generateAes256GcmKey();

      var handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 2 * 1024 * 1024,
      );

      final data = Uint8List.fromList([7, 8, 9]);
      await VaultService.write(
        handle: handle,
        name: 'persist.bin',
        data: data,
        metadata: {'created': '2026-04-09'},
      );
      await VaultService.close(handle: handle);

      // Reopen and verify
      handle = await VaultService.open(path: path, key: key);
      final result = await VaultService.read(
        handle: handle,
        name: 'persist.bin',
      );
      expect(result.data, data);
      expect(result.metadata['created'], '2026-04-09');

      await VaultService.close(handle: handle);
    });
  });

  group('Segment Rename', () {
    late Directory tempDir;
    setUp(() async {
      tempDir = await Directory.systemTemp.createTemp('rename_test');
    });
    tearDown(() async {
      await tempDir.delete(recursive: true);
    });

    test('rename then read under new name', () async {
      final path = '${tempDir.path}/rename.vault';
      final key = await generateAes256GcmKey();

      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 2 * 1024 * 1024,
      );

      final data = Uint8List.fromList([1, 2, 3, 4, 5]);
      await VaultService.write(handle: handle, name: 'old.bin', data: data);

      await VaultService.renameSegment(
        handle: handle,
        oldName: 'old.bin',
        newName: 'new.bin',
      );

      // Readable under new name
      final result = await VaultService.read(handle: handle, name: 'new.bin');
      expect(result.data, data);

      // Old name gone
      expect(
        () async =>
            await VaultService.read(handle: handle, name: 'old.bin'),
        throwsA(isA<Exception>()),
      );

      // List reflects rename
      final names = await VaultService.list(handle: handle);
      expect(names, contains('new.bin'));
      expect(names, isNot(contains('old.bin')));

      await VaultService.close(handle: handle);
    });

    test('rename to existing name throws DuplicateSegment', () async {
      final path = '${tempDir.path}/dup.vault';
      final key = await generateAes256GcmKey();

      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 2 * 1024 * 1024,
      );

      await VaultService.write(
        handle: handle,
        name: 'a.bin',
        data: Uint8List(10),
      );
      await VaultService.write(
        handle: handle,
        name: 'b.bin',
        data: Uint8List(10),
      );

      expect(
        () async => await VaultService.renameSegment(
          handle: handle,
          oldName: 'a.bin',
          newName: 'b.bin',
        ),
        throwsA(
          predicate((e) => e.toString().contains('duplicateSegment')),
        ),
      );

      await VaultService.close(handle: handle);
    });

    test('rename nonexistent segment throws SegmentNotFound', () async {
      final path = '${tempDir.path}/notfound.vault';
      final key = await generateAes256GcmKey();

      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 1024 * 1024,
      );

      expect(
        () async => await VaultService.renameSegment(
          handle: handle,
          oldName: 'ghost.bin',
          newName: 'new.bin',
        ),
        throwsA(
          predicate((e) => e.toString().contains('segmentNotFound')),
        ),
      );

      await VaultService.close(handle: handle);
    });

    test('rename preserves metadata', () async {
      final path = '${tempDir.path}/rename_meta.vault';
      final key = await generateAes256GcmKey();

      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 2 * 1024 * 1024,
      );

      final data = Uint8List.fromList([42]);
      await VaultService.write(
        handle: handle,
        name: 'before.bin',
        data: data,
        metadata: {'tag': 'important'},
      );

      await VaultService.renameSegment(
        handle: handle,
        oldName: 'before.bin',
        newName: 'after.bin',
      );

      final result = await VaultService.read(handle: handle, name: 'after.bin');
      expect(result.data, data);
      expect(result.metadata['tag'], 'important');

      await VaultService.close(handle: handle);
    });
  });

  group('Flush', () {
    late Directory tempDir;
    setUp(() async {
      tempDir = await Directory.systemTemp.createTemp('flush_test');
    });
    tearDown(() async {
      await tempDir.delete(recursive: true);
    });

    test('explicit flush after write succeeds', () async {
      final path = '${tempDir.path}/flush.vault';
      final key = await generateAes256GcmKey();

      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 2 * 1024 * 1024,
      );

      await VaultService.write(
        handle: handle,
        name: 'data.bin',
        data: Uint8List.fromList([1, 2, 3]),
      );

      // Flush should not throw
      await VaultService.flush(handle: handle);

      // Data still readable
      final result = await VaultService.read(handle: handle, name: 'data.bin');
      expect(result.data, Uint8List.fromList([1, 2, 3]));

      await VaultService.close(handle: handle);
    });

    test('flush on clean handle is no-op', () async {
      final path = '${tempDir.path}/noop_flush.vault';
      final key = await generateAes256GcmKey();

      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 1024 * 1024,
      );

      // No writes — flush should be a safe no-op
      await VaultService.flush(handle: handle);

      await VaultService.close(handle: handle);
    });
  });

  group('Parallel Read', () {
    late Directory tempDir;
    setUp(() async {
      tempDir = await Directory.systemTemp.createTemp('parallel_test');
    });
    tearDown(() async {
      await tempDir.delete(recursive: true);
    });

    test('parallel read 5 segments matches sequential', () async {
      final path = '${tempDir.path}/parallel.vault';
      final key = await generateAes256GcmKey();

      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 5 * 1024 * 1024,
      );

      // Write 5 segments
      final segments = <String, Uint8List>{};
      for (var i = 0; i < 5; i++) {
        final name = 'seg_$i.bin';
        final data = Uint8List.fromList(
          List.generate(1000 + i * 100, (j) => (j * (i + 1)) % 256),
        );
        segments[name] = data;
        await VaultService.write(handle: handle, name: name, data: data);
      }

      // Parallel read all
      final results = await VaultService.readParallel(
        handle: handle,
        names: segments.keys.toList(),
      );

      expect(results.length, 5);
      for (final r in results) {
        expect(r.error, isNull, reason: 'segment ${r.name} had error: ${r.error}');
        expect(r.data, segments[r.name], reason: 'data mismatch for ${r.name}');
      }

      await VaultService.close(handle: handle);
    });

    test('parallel read with missing name returns per-segment error', () async {
      final path = '${tempDir.path}/partial.vault';
      final key = await generateAes256GcmKey();

      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 2 * 1024 * 1024,
      );

      await VaultService.write(
        handle: handle,
        name: 'exists.bin',
        data: Uint8List.fromList([1, 2, 3]),
      );

      final results = await VaultService.readParallel(
        handle: handle,
        names: ['exists.bin', 'missing.bin'],
      );

      expect(results.length, 2);

      final existing = results.firstWhere((r) => r.name == 'exists.bin');
      expect(existing.error, isNull);
      expect(existing.data, Uint8List.fromList([1, 2, 3]));

      final missing = results.firstWhere((r) => r.name == 'missing.bin');
      expect(missing.error, isNotNull);
      expect(missing.data, isEmpty);

      await VaultService.close(handle: handle);
    });

    test('parallel read empty list returns empty result', () async {
      final path = '${tempDir.path}/empty.vault';
      final key = await generateAes256GcmKey();

      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 1024 * 1024,
      );

      final results = await VaultService.readParallel(
        handle: handle,
        names: [],
      );
      expect(results, isEmpty);

      await VaultService.close(handle: handle);
    });
  });

  group('Combined Workflows', () {
    late Directory tempDir;
    setUp(() async {
      tempDir = await Directory.systemTemp.createTemp('combined_test');
    });
    tearDown(() async {
      await tempDir.delete(recursive: true);
    });

    test('write with metadata, rename, parallel read — metadata preserved',
        () async {
      final path = '${tempDir.path}/combined.vault';
      final key = await generateAes256GcmKey();

      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 5 * 1024 * 1024,
      );

      final data = Uint8List.fromList(List.generate(500, (i) => i % 256));

      // Write with metadata
      await VaultService.write(
        handle: handle,
        name: 'original.bin',
        data: data,
        metadata: {'type': 'document', 'priority': 'high'},
      );

      // Rename
      await VaultService.renameSegment(
        handle: handle,
        oldName: 'original.bin',
        newName: 'renamed.bin',
      );

      // Write another segment (no metadata)
      await VaultService.write(
        handle: handle,
        name: 'extra.bin',
        data: Uint8List.fromList([99]),
      );

      // Parallel read both
      final results = await VaultService.readParallel(
        handle: handle,
        names: ['renamed.bin', 'extra.bin'],
      );

      expect(results.length, 2);
      final renamed = results.firstWhere((r) => r.name == 'renamed.bin');
      expect(renamed.data, data);
      expect(renamed.error, isNull);

      // Verify metadata via single read (parallel read doesn't return metadata)
      final detailed = await VaultService.read(
        handle: handle,
        name: 'renamed.bin',
      );
      expect(detailed.metadata['type'], 'document');
      expect(detailed.metadata['priority'], 'high');

      await VaultService.close(handle: handle);
    });

    test('write 10 segments, parallel read all, verify data', () async {
      final path = '${tempDir.path}/bulk.vault';
      final key = await generateAes256GcmKey();

      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 10 * 1024 * 1024,
      );

      final segments = <String, Uint8List>{};
      for (var i = 0; i < 10; i++) {
        final name = 'bulk_$i.dat';
        final data = Uint8List.fromList(
          List.generate(2048, (j) => (j + i * 17) % 256),
        );
        segments[name] = data;
        await VaultService.write(handle: handle, name: name, data: data);
      }

      // Flush before parallel read
      await VaultService.flush(handle: handle);

      final results = await VaultService.readParallel(
        handle: handle,
        names: segments.keys.toList(),
      );

      expect(results.length, 10);
      for (final r in results) {
        expect(r.error, isNull, reason: '${r.name} failed: ${r.error}');
        expect(r.data, segments[r.name], reason: 'data mismatch: ${r.name}');
      }

      await VaultService.close(handle: handle);
    });
  });
}
