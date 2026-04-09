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
      expect(result.data, data);

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

      expect(result1.data, data1);
      expect(result2.data, data2);
      expect(result3.data, data3);

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

      expect(result.data, updated);
      expect(result.data, isNot(original));

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
      expect(before.data, data);

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
      expect(result.data, data);
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
      expect(result.data, data);
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
      expect(result.data, jpegData);

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
        resultA.data,
        dataA,
        reason: 'Zstd segment should decompress correctly',
      );
      expect(
        resultB.data,
        dataB,
        reason: 'Brotli segment should decompress correctly',
      );
      expect(
        resultC.data,
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
      expect(result.data, data1);

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

      expect(result1.data, data1);
      expect(result2.data, data2);

      await VaultService.close(handle: reopened2);
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

      // primary index has 1 segment
      // shadow index has 1 segment (backup)

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
      final reopened = await VaultService.open(path: path, key: key);

      // Read data - should work because shadow index has it
      final result = await VaultService.read(
        handle: reopened,
        name: 'important.bin',
      );
      expect(
        result.data,
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
      expect(result2.data, originalData);

      await VaultService.close(handle: reopened2);
    });
  });
}
