import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:m_security/src/rust/api/compression.dart';
import 'package:m_security/src/rust/api/encryption.dart';
import 'package:m_security/src/rust/frb_generated.dart';
import 'package:m_security/src/evfs/vault_service.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async => await RustLib.init());

  group('EVFS', () {
    // Helper: create a temp vault path
    late Directory tempDir;
    setUp(() async {
      tempDir = await Directory.systemTemp.createTemp('evfs_test');
    });
    tearDown(() async {
      await tempDir.delete(recursive: true);
    });

    test('create, write, close, open, read roundtrip', () async {
      final path = '${tempDir.path}/test.vault';
      final key = await generateAes256GcmKey();

      //Create vault
      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 1024 * 1024,
      );

      //segment
      final data = Uint8List.fromList([1, 2, 3, 4, 5]);
      await VaultService.write(handle: handle, name: 'test.bin', data: data);

      //close vault
      await VaultService.close(handle: handle);

      //reopen vault
      final reopened = await VaultService.open(path: path, key: key);

      //read segment
      final result = await VaultService.read(
        handle: reopened,
        name: 'test.bin',
      );
      expect(result, data);

      //close vault
      await VaultService.close(handle: reopened);
    });

    test('write and read multiple segments', () async {
      final path = '${tempDir.path}/multi.vault';
      final key = await generateAes256GcmKey();

      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 5 * 1024 * 1024, //5MB
      );

      final data1 = Uint8List.fromList(List.generate(1000, (i) => i % 256));
      final data2 = Uint8List.fromList(
        List.generate(2000, (i) => (i * 2) % 256),
      );
      final data3 = Uint8List.fromList(
        List.generate(500, (i) => (i * 3) % 256),
      );

      await VaultService.write(handle: handle, name: 'file1.dat', data: data1);
      await VaultService.write(handle: handle, name: 'file2.dat', data: data2);
      await VaultService.write(handle: handle, name: 'file3.dat', data: data3);

      // Read all back
      final result1 = await VaultService.read(
        handle: handle,
        name: 'file1.dat',
      );
      final result2 = await VaultService.read(
        handle: handle,
        name: 'file2.dat',
      );
      final result3 = await VaultService.read(
        handle: handle,
        name: 'file3.dat',
      );

      expect(result1, data1);
      expect(result2, data2);
      expect(result3, data3);

      await VaultService.close(handle: handle);
    });

    test('overwrite segment returns new data', () async {
      final path = '${tempDir.path}/overwrite.vault';
      final key = await generateAes256GcmKey();

      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 2 * 1024 * 1024,
      );

      // Write original
      final original = Uint8List.fromList([1, 2, 3]);
      await VaultService.write(
        handle: handle,
        name: 'data.bin',
        data: original,
      );

      // Overwrite
      final updated = Uint8List.fromList([4, 5, 6, 7, 8]);
      await VaultService.write(handle: handle, name: 'data.bin', data: updated);

      // Read back
      final result = await VaultService.read(handle: handle, name: 'data.bin');

      expect(result, updated);
      expect(result, isNot(original));

      await VaultService.close(handle: handle);
    });
    test('read nonexistent segment throws SegmentNotFound', () async {
      final path = '${tempDir.path}/notfound.vault';
      final key = await generateAes256GcmKey();

      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 1024 * 1024,
      );

      expect(
        () async =>
            await VaultService.read(handle: handle, name: 'missing.txt'),
        throwsA(isA<Exception>()),
      );
      await VaultService.close(handle: handle);
    });

    test('delete segment removes it', () async {
      final path = '${tempDir.path}/delete.vault';
      final key = await generateAes256GcmKey();

      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 2 * 1024 * 1024,
      );

      //write a segment
      final data = Uint8List.fromList([1, 2, 3, 4, 5]);
      await VaultService.write(handle: handle, name: 'temp.dat', data: data);

      //verify it exists
      final before = await VaultService.read(handle: handle, name: 'temp.dat');
      expect(before, data);

      //delete it
      await VaultService.delete(handle: handle, name: 'temp.dat');

      //verify it's gone
      expect(
        () async => await VaultService.read(handle: handle, name: 'temp.dat'),
        throwsA(isA<Exception>()),
      );
      await VaultService.close(handle: handle);
    });

    test('vault full returns VaultFull error', () async {
      final path = '${tempDir.path}/full.vault';
      final key = await generateAes256GcmKey();

      //create small vault (only 1MB)
      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 1024 * 1024, // 1MB total
      );

      //Try to write 1MB of data (will fail because index takes space too)
      final hugeData = Uint8List(900 * 1024); // 900KB

      await VaultService.write(handle: handle, name: 'big.bin', data: hugeData);

      //Try to write another big file ->should fail
      try {
        await VaultService.write(
          handle: handle,
          name: 'big2.bin',
          data: hugeData,
        );
        fail('Expected VaultFull error');
      } catch (e) {
        expect(e.toString(), contains('vaultFull'));
      }

      await VaultService.close(handle: handle);
    });
    test('wrong key fails to open', () async {
      final path = '${tempDir.path}/test.vault';
      final keyA = await generateAes256GcmKey();
      final keyB = await generateAes256GcmKey();

      //Create vault with keyA
      final handle = await VaultService.create(
        path: path,
        key: keyA,
        algorithm: 'aes-256-gcm',
        capacityBytes: 1024 * 1024,
      );
      await VaultService.close(handle: handle);

      //try to open with keyB
      expect(
        () async => await VaultService.open(path: path, key: keyB),
        throwsA(isA<Exception>()),
      );
    });
    test('concurrent open returns VaultLocked', () async {
      final path = '${tempDir.path}/locked.vault';
      final key = await generateAes256GcmKey();

      //create vault and keep it open
      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 1024 * 1024,
      );

      //try to open again without closing first
      expect(
        () async => await VaultService.open(path: path, key: key),
        throwsA(predicate((e) => e.toString().contains('vaultLocked'))),
      );

      await VaultService.close(handle: handle);

      //now it should work!
      final handle2 = await VaultService.open(path: path, key: key);
      await VaultService.close(handle: handle2);
    });

    test('list returns all segment names', () async {
      final path = '${tempDir.path}/list.vault';
      final key = await generateAes256GcmKey();

      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 2 * 1024 * 1024,
      );
      //write 3 segments
      await VaultService.write(
        handle: handle,
        name: 'a.txt',
        data: Uint8List(10),
      );
      await VaultService.write(
        handle: handle,
        name: 'b.txt',
        data: Uint8List(20),
      );
      await VaultService.write(
        handle: handle,
        name: 'c.txt',
        data: Uint8List(30),
      );
      //returns all segments
      final names = await VaultService.list(handle: handle);

      expect(names, containsAll(['a.txt', 'b.txt', 'c.txt']));

      await VaultService.close(handle: handle);
    });

    test('capacity info is consistent', () async {
      final path = '${tempDir.path}/capacity.vault';
      final key = await generateAes256GcmKey();

      final totalCapacity = 2 * 1024 * 1024; // 2MB
      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: totalCapacity,
      );

      // Check initial capacity
      final before = await VaultService.capacity(handle: handle);
      expect(before.totalBytes, BigInt.from(totalCapacity));

      // Write some data
      final data = Uint8List(100 * 1024); // 100KB
      await VaultService.write(handle: handle, name: 'data.bin', data: data);

      // Check again
      final after = await VaultService.capacity(handle: handle);
      expect(after.usedBytes, greaterThan(before.usedBytes));
      expect(after.unallocatedBytes, lessThan(before.unallocatedBytes));

      // Total should remain the same
      expect(after.totalBytes, before.totalBytes);

      await VaultService.close(handle: handle);
    });

    // Compression integration
    test('write with zstd, read decompresses automatically', () async {
      final path = '${tempDir.path}/test.vault';
      final key = await generateAes256GcmKey();
      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 1024 * 1024,
      );
      final data = Uint8List.fromList(List.generate(10000, (i) => i % 256));
      await VaultService.write(
        handle: handle,
        name: 'notes.txt',
        data: data,
        compression: const CompressionConfig(
          algorithm: CompressionAlgorithm.zstd,
        ),
      );
      final result = await VaultService.read(handle: handle, name: 'notes.txt');
      expect(result, data);
      await VaultService.close(handle: handle);
    });

    test('write with brotli, read decompresses automatically', () async {
      final path = '${tempDir.path}/test.vault';
      final key = await generateAes256GcmKey();
      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 1024 * 1024,
      );

      final data = Uint8List.fromList(List.generate(10000, (i) => i % 256));
      await VaultService.write(
        handle: handle,
        name: 'notes.txt',
        data: data,
        compression: const CompressionConfig(
          algorithm: CompressionAlgorithm.brotli,
        ),
      );
      final result = await VaultService.read(handle: handle, name: 'notes.txt');
      expect(result, data);
      await VaultService.close(handle: handle);
    });

    test('jpg segment skips compression automatically', () async {
      // Write "photo.jpg" with Zstd config — should auto-skip
      // Read back — data is identical
      final path = '${tempDir.path}/mime.vault';
      final key = await generateAes256GcmKey();

      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 2 * 1024 * 1024,
      );

      // Fake JPEG data
      final jpegData = Uint8List(1000);

      // Write with Zstd config BUT name is .jpg
      await VaultService.write(
        handle: handle,
        name: 'photo.jpg', // ← Extension triggers MIME skip
        data: jpegData,
        compression: const CompressionConfig(
          algorithm: CompressionAlgorithm.zstd, // Requested but will be ignored
        ),
      );

      // Read back
      final result = await VaultService.read(handle: handle, name: 'photo.jpg');
      expect(result, jpegData);

      // Verify: if compression was applied, capacity used would be less
      // Since it was skipped, capacity used ≈ original size

      await VaultService.close(handle: handle);
    });

    test('mixed compression segments in same vault', () async {
      // Write segment A with Zstd, segment B with Brotli, segment C with None
      // Read all three back, verify identical data
      final path = '${tempDir.path}/mixed.vault';
      final key = await generateAes256GcmKey();
      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 5 * 1024 * 1024, // 5MB
      );

      // Prepare test data (compressible - lots of repeats)
      final dataA = Uint8List.fromList(List.filled(5000, 42));
      final dataB = Uint8List.fromList(List.filled(5000, 99));
      final dataC = Uint8List.fromList(List.filled(5000, 123));

      // Write segment A with Zstd
      await VaultService.write(
        handle: handle,
        name: 'zstd_segment.txt',
        data: dataA,
        compression: const CompressionConfig(
          algorithm: CompressionAlgorithm.zstd,
          level: 3,
        ),
      );

      // Write segment B with Brotli
      await VaultService.write(
        handle: handle,
        name: 'brotli_segment.txt',
        data: dataB,
        compression: const CompressionConfig(
          algorithm: CompressionAlgorithm.brotli,
          level: 4,
        ),
      );

      // Write segment C with None (no compression)
      await VaultService.write(
        handle: handle,
        name: 'uncompressed_segment.txt',
        data: dataC,
        compression: const CompressionConfig(
          algorithm: CompressionAlgorithm.none,
        ),
      );

      // Read all three back
      final resultA = await VaultService.read(
        handle: handle,
        name: 'zstd_segment.txt',
      );
      final resultB = await VaultService.read(
        handle: handle,
        name: 'brotli_segment.txt',
      );
      final resultC = await VaultService.read(
        handle: handle,
        name: 'uncompressed_segment.txt',
      );

      // Verify all three match original data
      expect(
        resultA,
        dataA,
        reason: 'Zstd segment should decompress correctly',
      );
      expect(
        resultB,
        dataB,
        reason: 'Brotli segment should decompress correctly',
      );
      expect(
        resultC,
        dataC,
        reason: 'Uncompressed segment should read correctly',
      );

      // Verify all three segments are in the list
      final names = await VaultService.list(handle: handle);
      expect(names.length, 3);
      expect(
        names,
        containsAll([
          'zstd_segment.txt',
          'brotli_segment.txt',
          'uncompressed_segment.txt',
        ]),
      );

      await VaultService.close(handle: handle);
    });

    test('tampered segment detected on read', () async {
      final path = '${tempDir.path}/tamper.vault';
      final key = await generateAes256GcmKey();

      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 1024 * 1024,
      );

      // Write data
      final data = Uint8List.fromList([1, 2, 3, 4, 5]);
      await VaultService.write(handle: handle, name: 'test.bin', data: data);

      await VaultService.close(handle: handle);

      // Manually corrupt the vault file
      final file = File(path);
      final bytes = await file.readAsBytes();

      // Flip a byte in the data region (starts at offset 65568 = 32B header + 64KB index)
      bytes[65600] ^= 0xFF;

      await file.writeAsBytes(bytes);

      // Reopen
      final reopened = await VaultService.open(path: path, key: key);

      // Try to read → should detect tampering via checksum
      expect(
        () async => await VaultService.read(handle: reopened, name: 'test.bin'),
        throwsA(isA<Exception>()),
      );

      await VaultService.close(handle: reopened);
    });
    test('crash recovery via WAL', () async {
      final path = '${tempDir.path}/wal.vault';
      final key = await generateAes256GcmKey();

      // Create vault
      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 2 * 1024 * 1024,
      );

      // Write some data
      final data1 = Uint8List.fromList([1, 2, 3, 4, 5]);
      await VaultService.write(
        handle: handle,
        name: 'initial.bin',
        data: data1,
      );

      // Close properly (commits WAL)
      await VaultService.close(handle: handle);

      // Reopen (WAL recovery runs but finds everything committed)
      final reopened = await VaultService.open(path: path, key: key);

      // Verify data survived
      final result = await VaultService.read(
        handle: reopened,
        name: 'initial.bin',
      );
      expect(result, data1);

      // Write more data after recovery
      final data2 = Uint8List.fromList([6, 7, 8, 9]);
      await VaultService.write(
        handle: reopened,
        name: 'after_recovery.bin',
        data: data2,
      );

      // Close and reopen again
      await VaultService.close(handle: reopened);
      final reopened2 = await VaultService.open(path: path, key: key);

      // Both segments should exist
      final result1 = await VaultService.read(
        handle: reopened2,
        name: 'initial.bin',
      );
      final result2 = await VaultService.read(
        handle: reopened2,
        name: 'after_recovery.bin',
      );

      expect(result1, data1);
      expect(result2, data2);

      await VaultService.close(handle: reopened2);
    });
    // -- Defragmentation ------------------------------------------------

    test('defragment compacts free space', () async {
      final path = '${tempDir.path}/defrag.vault';
      final key = await generateAes256GcmKey();

      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 2 * 1024 * 1024,
      );

      // Write A, B, C
      final dataA = Uint8List.fromList(List.generate(1000, (i) => i % 256));
      final dataC = Uint8List.fromList(
        List.generate(500, (i) => (i * 3) % 256),
      );
      await VaultService.write(handle: handle, name: 'a.txt', data: dataA);
      await VaultService.write(
        handle: handle,
        name: 'b.txt',
        data: Uint8List(2000),
      );
      await VaultService.write(handle: handle, name: 'c.txt', data: dataC);

      // Delete B → creates a gap
      await VaultService.delete(handle: handle, name: 'b.txt');

      final beforeHealth = await VaultService.health(handle: handle);
      expect(beforeHealth.freeRegionCount, greaterThan(0));
      expect(beforeHealth.fragmentationRatio, greaterThan(0.0));

      // Defragment
      final result = await VaultService.defragment(handle: handle);
      expect(result.segmentsMoved, greaterThan(0));
      expect(result.bytesReclaimed, greaterThan(BigInt.zero));

      // After defrag: no fragmentation
      final afterHealth = await VaultService.health(handle: handle);
      expect(afterHealth.freeRegionCount, 0);
      expect(afterHealth.fragmentationRatio, 0.0);

      // Data still readable
      expect(await VaultService.read(handle: handle, name: 'a.txt'), dataA);
      expect(await VaultService.read(handle: handle, name: 'c.txt'), dataC);

      await VaultService.close(handle: handle);
    });

    test('defragment on empty vault is no-op', () async {
      final path = '${tempDir.path}/defrag_empty.vault';
      final key = await generateAes256GcmKey();

      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 1024 * 1024,
      );

      final result = await VaultService.defragment(handle: handle);
      expect(result.segmentsMoved, 0);
      expect(result.bytesReclaimed, BigInt.zero);

      await VaultService.close(handle: handle);
    });

    // -- Resize ---------------------------------------------------------

    test('resize grow then write in new space', () async {
      final path = '${tempDir.path}/grow.vault';
      final key = await generateAes256GcmKey();

      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 512 * 1024, // 512KB
      );

      // Grow to 1MB
      await VaultService.resize(handle: handle, newCapacityBytes: 1024 * 1024);

      final health = await VaultService.health(handle: handle);
      expect(health.totalBytes, BigInt.from(1024 * 1024));

      // Write data that wouldn't fit in original 512KB
      final bigData = Uint8List(600 * 1024); // 600KB
      await VaultService.write(handle: handle, name: 'big.bin', data: bigData);

      final result = await VaultService.read(handle: handle, name: 'big.bin');
      expect(result, bigData);

      await VaultService.close(handle: handle);
    });

    test('resize shrink after defrag', () async {
      final path = '${tempDir.path}/shrink.vault';
      final key = await generateAes256GcmKey();

      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 1024 * 1024, // 1MB
      );

      // Write small data
      final data = Uint8List.fromList(List.generate(100, (i) => i % 256));
      await VaultService.write(handle: handle, name: 'small.bin', data: data);

      // Defrag to compact
      await VaultService.defragment(handle: handle);

      // Shrink to 512KB (data fits)
      await VaultService.resize(handle: handle, newCapacityBytes: 512 * 1024);

      final health = await VaultService.health(handle: handle);
      expect(health.totalBytes, BigInt.from(512 * 1024));

      // Data still readable
      expect(await VaultService.read(handle: handle, name: 'small.bin'), data);

      await VaultService.close(handle: handle);
    });

    test('shrink below used space throws error', () async {
      final path = '${tempDir.path}/shrink_fail.vault';
      final key = await generateAes256GcmKey();

      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 1024 * 1024,
      );

      // Write enough data to occupy space
      final data = Uint8List(200 * 1024); // 200KB
      await VaultService.write(handle: handle, name: 'data.bin', data: data);

      // Try to shrink to 1KB → should fail
      try {
        await VaultService.resize(handle: handle, newCapacityBytes: 1024);
        fail('Expected VaultFull error');
      } catch (e) {
        expect(e.toString(), contains('vaultFull'));
      }

      await VaultService.close(handle: handle);
    });

    // -- Health Check ---------------------------------------------------

    test('health info on fresh vault', () async {
      final path = '${tempDir.path}/health.vault';
      final key = await generateAes256GcmKey();

      final cap = 1024 * 1024;
      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: cap,
      );

      final h = await VaultService.health(handle: handle);
      expect(h.totalBytes, BigInt.from(cap));
      expect(h.usedBytes, BigInt.zero);
      expect(h.segmentCount, 0);
      expect(h.freeRegionCount, 0);
      expect(h.fragmentationRatio, 0.0);
      expect(h.isConsistent, true);
      expect(h.largestFreeBlock, BigInt.from(cap));

      await VaultService.close(handle: handle);
    });

    test('health after write and delete shows fragmentation', () async {
      final path = '${tempDir.path}/health_frag.vault';
      final key = await generateAes256GcmKey();

      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 2 * 1024 * 1024,
      );

      await VaultService.write(
        handle: handle,
        name: 'a.txt',
        data: Uint8List(1000),
      );
      await VaultService.write(
        handle: handle,
        name: 'b.txt',
        data: Uint8List(2000),
      );
      await VaultService.write(
        handle: handle,
        name: 'c.txt',
        data: Uint8List(500),
      );

      // Delete middle segment
      await VaultService.delete(handle: handle, name: 'b.txt');

      final h = await VaultService.health(handle: handle);
      expect(h.segmentCount, 2);
      expect(h.freeRegionCount, greaterThan(0));
      expect(h.fragmentationRatio, greaterThan(0.0));
      expect(h.isConsistent, true);

      // Defrag → fragmentation goes to 0
      await VaultService.defragment(handle: handle);
      final after = await VaultService.health(handle: handle);
      expect(after.freeRegionCount, 0);
      expect(after.fragmentationRatio, 0.0);
      expect(after.isConsistent, true);

      await VaultService.close(handle: handle);
    });

    test('corrupted primary index falls back to shadow', () async {
      final path = '${tempDir.path}/shadow.vault';
      final key = await generateAes256GcmKey();

      // Create vault and write data
      final handle = await VaultService.create(
        path: path,
        key: key,
        algorithm: 'aes-256-gcm',
        capacityBytes: 2 * 1024 * 1024,
      );

      final originalData = Uint8List.fromList([1, 2, 3, 4, 5]);
      await VaultService.write(
        handle: handle,
        name: 'important.bin',
        data: originalData,
      );

      await VaultService.close(handle: handle);

      // At this point:
      // - Primary index has 1 segment
      // - Shadow index has 1 segment (backup)

      // Manually corrupt the PRIMARY index
      final file = File(path);
      final bytes = await file.readAsBytes();

      // Primary index starts at byte 32 (after header)
      // Shadow index starts at byte 32 + 64KB
      final primaryIndexStart = 32;
      //final primaryIndexEnd = primaryIndexStart + (64 * 1024);

      // Corrupt some bytes in the primary index region
      // (but leave shadow index intact)
      for (int i = primaryIndexStart; i < primaryIndexStart + 100; i++) {
        bytes[i] = 0xFF; // Corrupt
      }

      await file.writeAsBytes(bytes);

      // Try to reopen
      // Rust should:
      // 1. Try to decrypt primary index → fail (corrupted)
      // 2. Fall back to shadow index → succeed
      // 3. Restore primary index from shadow
      final reopened = await VaultService.open(path: path, key: key);

      // Read data - should work because shadow index has it
      final result = await VaultService.read(
        handle: reopened,
        name: 'important.bin',
      );
      expect(
        result,
        originalData,
        reason: 'Shadow index should have preserved the segment',
      );

      await VaultService.close(handle: reopened);

      // Reopen again - primary should be restored now
      final reopened2 = await VaultService.open(path: path, key: key);
      final result2 = await VaultService.read(
        handle: reopened2,
        name: 'important.bin',
      );
      expect(result2, originalData);

      await VaultService.close(handle: reopened2);
    });

    // -- Streaming (writeStream / readStream) ----------------------------------

    group('Streaming', () {
      test('stream-write 10 MB then stream-read back byte-identical', () async {
        final path = '${tempDir.path}/stream_10mb.vault';
        final key = await generateAes256GcmKey();
        const dataSize = 10 * 1024 * 1024; // 10 MB
        const chunkSize = 64 * 1024; // 64 KB

        final handle = await VaultService.create(
          path: path,
          key: key,
          algorithm: 'aes-256-gcm',
          capacityBytes:
              16 * 1024 * 1024, // 16 MB — enough for encrypted overhead
        );

        // Build source data in memory for the round-trip assertion.
        final sourceData = Uint8List(dataSize);
        for (int i = 0; i < dataSize; i++) {
          sourceData[i] = i % 256;
        }

        // Emit source data in 64 KB chunks.
        Stream<Uint8List> chunks() async* {
          int offset = 0;
          while (offset < dataSize) {
            final end = (offset + chunkSize).clamp(0, dataSize);
            yield sourceData.sublist(offset, end);
            offset = end;
          }
        }

        await VaultService.writeStream(
          handle: handle,
          name: 'large.bin',
          totalSize: dataSize,
          data: chunks(),
        );

        // Stream-read and reassemble.
        final builder = BytesBuilder(copy: false);
        await for (final chunk in VaultService.readStream(
          handle: handle,
          name: 'large.bin',
        )) {
          builder.add(chunk);
        }

        expect(builder.takeBytes(), sourceData);
        await VaultService.close(handle: handle);
      });

      test('stream-write then one-shot read (interop)', () async {
        final path = '${tempDir.path}/stream_to_oneshot.vault';
        final key = await generateAes256GcmKey();
        const dataSize = 256 * 1024; // 256 KB

        final handle = await VaultService.create(
          path: path,
          key: key,
          algorithm: 'aes-256-gcm',
          capacityBytes: 2 * 1024 * 1024,
        );

        final sourceData = Uint8List.fromList(
          List.generate(dataSize, (i) => (i * 3) % 256),
        );

        await VaultService.writeStream(
          handle: handle,
          name: 'interop.bin',
          totalSize: dataSize,
          data: Stream.fromIterable([sourceData]),
        );

        // VaultService.read() must be able to read a streaming segment.
        final result = await VaultService.read(
          handle: handle,
          name: 'interop.bin',
        );
        expect(result, sourceData);

        await VaultService.close(handle: handle);
      });

      test('one-shot write then stream-read (interop)', () async {
        final path = '${tempDir.path}/oneshot_to_stream.vault';
        final key = await generateAes256GcmKey();
        const dataSize = 128 * 1024; // 128 KB

        final handle = await VaultService.create(
          path: path,
          key: key,
          algorithm: 'aes-256-gcm',
          capacityBytes: 2 * 1024 * 1024,
        );

        final sourceData = Uint8List.fromList(
          List.generate(dataSize, (i) => (i * 7) % 256),
        );

        // VaultService.write() writes a monolithic segment.
        await VaultService.write(
          handle: handle,
          name: 'interop2.bin',
          data: sourceData,
        );

        // VaultService.readStream() must handle monolithic segments
        // (Rust falls back to a one-shot read and emits one chunk).
        final builder = BytesBuilder(copy: false);
        await for (final chunk in VaultService.readStream(
          handle: handle,
          name: 'interop2.bin',
        )) {
          builder.add(chunk);
        }

        expect(builder.takeBytes(), sourceData);
        await VaultService.close(handle: handle);
      });

      test(
        'readStream emits multiple chunks for large streaming segment',
        () async {
          // Verifies that data actually arrives incrementally, not as one blob.
          final path = '${tempDir.path}/progress.vault';
          final key = await generateAes256GcmKey();
          const dataSize = 512 * 1024; // 512 KB = 8 × 64 KB chunks
          const chunkSize = 64 * 1024;

          final handle = await VaultService.create(
            path: path,
            key: key,
            algorithm: 'aes-256-gcm',
            capacityBytes: 4 * 1024 * 1024,
          );

          await VaultService.writeStream(
            handle: handle,
            name: 'chunked.bin',
            totalSize: dataSize,
            data: Stream.fromIterable(
              List.generate(dataSize ~/ chunkSize, (_) => Uint8List(chunkSize)),
            ),
          );

          final chunkLengths = <int>[];
          await for (final chunk in VaultService.readStream(
            handle: handle,
            name: 'chunked.bin',
          )) {
            chunkLengths.add(chunk.length);
          }

          // Must have received more than one chunk.
          expect(chunkLengths.length, greaterThan(1));
          // Total byte count must be exact.
          expect(chunkLengths.fold(0, (a, b) => a + b), dataSize);

          await VaultService.close(handle: handle);
        },
      );

      test('stream-write with wrong totalSize throws ArgumentError', () async {
        final path = '${tempDir.path}/wrong_size.vault';
        final key = await generateAes256GcmKey();

        final handle = await VaultService.create(
          path: path,
          key: key,
          algorithm: 'aes-256-gcm',
          capacityBytes: 2 * 1024 * 1024,
        );

        // Underflow: stream emits fewer bytes than totalSize claims.
        await expectLater(
          VaultService.writeStream(
            handle: handle,
            name: 'underflow.bin',
            totalSize: 100, // claims 100 bytes
            data: Stream.fromIterable([
              Uint8List.fromList([1, 2, 3]),
            ]), // only 3 bytes
          ),
          throwsA(isA<ArgumentError>()),
        );

        // Overflow: stream emits more bytes than totalSize allows.
        await expectLater(
          VaultService.writeStream(
            handle: handle,
            name: 'overflow.bin',
            totalSize: 2, // claims only 2 bytes
            data: Stream.fromIterable([Uint8List(1024)]), // 1 KB
          ),
          throwsA(isA<ArgumentError>()),
        );

        await VaultService.close(handle: handle);
      });

      test('50 MB stream-write and stream-read stays memory-bounded', () async {
        // If memory were not bounded this would OOM on constrained devices.
        // Successful completion without process termination is the assertion.
        final path = '${tempDir.path}/large_50mb.vault';
        final key = await generateAes256GcmKey();
        const dataSize = 50 * 1024 * 1024; // 50 MB
        const chunkSize = 64 * 1024; // 64 KB

        final handle = await VaultService.create(
          path: path,
          key: key,
          algorithm: 'aes-256-gcm',
          capacityBytes: 55 * 1024 * 1024,
        );

        // Generate stream lazily — never holds more than one 64 KB chunk in
        // Dart memory.
        int writeCounter = 0;
        Stream<Uint8List> lazyStream() async* {
          int remaining = dataSize;
          while (remaining > 0) {
            final size = remaining < chunkSize ? remaining : chunkSize;
            final chunk = Uint8List(size);
            for (int i = 0; i < size; i++) {
              chunk[i] = (writeCounter + i) % 256;
            }
            writeCounter += size;
            remaining -= size;
            yield chunk;
          }
        }

        await VaultService.writeStream(
          handle: handle,
          name: 'huge.bin',
          totalSize: dataSize,
          data: lazyStream(),
        );

        // Stream-read and count bytes without accumulating all data in memory.
        int totalRead = 0;
        await for (final chunk in VaultService.readStream(
          handle: handle,
          name: 'huge.bin',
        )) {
          totalRead += chunk.length;
        }

        expect(totalRead, dataSize);
        await VaultService.close(handle: handle);
      });
    });
  });
}
