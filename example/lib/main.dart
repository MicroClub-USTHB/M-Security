import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:m_security/m_security.dart' as msec;
import 'package:m_security/m_security.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await RustLib.init();
  runApp(const ExampleApp());
}

class ExampleApp extends StatelessWidget {
  const ExampleApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'M-Security v0.3.4',
      theme: ThemeData(colorSchemeSeed: Colors.blue, useMaterial3: true),
      home: const DemoHome(),
    );
  }
}

class DemoHome extends StatefulWidget {
  const DemoHome({super.key});

  @override
  State<DemoHome> createState() => _DemoHomeState();
}

class _DemoHomeState extends State<DemoHome> {
  int _tab = 0;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('M-Security v0.3.4')),
      body: IndexedStack(
        index: _tab,
        children: const [
          _HashingTab(),
          _EncryptionTab(),
          _KdfTab(),
          _StreamingTab(),
          _VaultTab(),
        ],
      ),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _tab,
        onDestinationSelected: (i) => setState(() => _tab = i),
        destinations: const [
          NavigationDestination(icon: Icon(Icons.tag), label: 'Hash'),
          NavigationDestination(icon: Icon(Icons.lock), label: 'Encrypt'),
          NavigationDestination(icon: Icon(Icons.key), label: 'KDF'),
          NavigationDestination(icon: Icon(Icons.stream), label: 'Stream'),
          NavigationDestination(icon: Icon(Icons.folder), label: 'Vault'),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Hashing Tab
// ---------------------------------------------------------------------------

class _HashingTab extends StatefulWidget {
  const _HashingTab();
  @override
  State<_HashingTab> createState() => _HashingTabState();
}

class _HashingTabState extends State<_HashingTab> {
  final _input = TextEditingController(text: 'Hello, M-Security!');
  final _results = <String, String>{};
  bool _loading = false;

  Future<void> _run(String name, Future<String> Function() fn) async {
    setState(() => _loading = true);
    try {
      _results[name] = await fn();
    } catch (e) {
      _results[name] = 'Error: $e';
    }
    setState(() => _loading = false);
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        TextField(
          controller: _input,
          decoration: const InputDecoration(
            labelText: 'Input text',
            border: OutlineInputBorder(),
          ),
        ),
        const SizedBox(height: 12),
        Wrap(
          spacing: 8,
          runSpacing: 8,
          children: [
            FilledButton(
              onPressed: _loading
                  ? null
                  : () => _run('BLAKE3', () async {
                      final h = await msec.blake3Hash(
                        data: utf8.encode(_input.text),
                      );
                      return _hex(h);
                    }),
              child: const Text('BLAKE3'),
            ),
            FilledButton(
              onPressed: _loading
                  ? null
                  : () => _run('SHA-3', () async {
                      final h = await msec.sha3Hash(
                        data: utf8.encode(_input.text),
                      );
                      return _hex(h);
                    }),
              child: const Text('SHA-3'),
            ),
            FilledButton(
              onPressed: _loading
                  ? null
                  : () => _run(
                      'Argon2id',
                      () => argon2IdHash(password: _input.text),
                    ),
              child: const Text('Argon2id'),
            ),
            FilledButton.tonal(
              onPressed: _loading
                  ? null
                  : () async {
                      final argonHash = _results['Argon2id'];
                      if (argonHash == null || argonHash.startsWith('Error')) {
                        _run('Verify', () async => 'Hash first with Argon2id');
                        return;
                      }
                      _run('Verify', () async {
                        try {
                          await argon2IdVerify(
                            phcHash: argonHash,
                            password: _input.text,
                          );
                          return 'PASS - password matches';
                        } catch (_) {
                          return 'FAIL - password does not match';
                        }
                      });
                    },
              child: const Text('Verify Argon2'),
            ),
          ],
        ),
        if (_loading) const _Loader(),
        ..._results.entries.map((e) => _ResultCard(e.key, e.value)),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// Encryption Tab
// ---------------------------------------------------------------------------

class _EncryptionTab extends StatefulWidget {
  const _EncryptionTab();
  @override
  State<_EncryptionTab> createState() => _EncryptionTabState();
}

class _EncryptionTabState extends State<_EncryptionTab> {
  final _input = TextEditingController(text: 'Secret message');
  String _algo = 'AES-256-GCM';
  Uint8List? _encrypted;
  msec.CipherHandle? _cipher;
  String _encHex = '';
  String _decrypted = '';
  bool _loading = false;

  Future<void> _encrypt() async {
    setState(() {
      _loading = true;
      _decrypted = '';
      _encHex = '';
    });
    try {
      final key = _algo == 'AES-256-GCM'
          ? await msec.generateAes256GcmKey()
          : await msec.generateChacha20Poly1305Key();
      _cipher = _algo == 'AES-256-GCM'
          ? await msec.createAes256Gcm(key: key)
          : await msec.createChacha20Poly1305(key: key);
      _encrypted = await msec.encrypt(
        cipher: _cipher!,
        plaintext: Uint8List.fromList(utf8.encode(_input.text)),
        aad: Uint8List(0),
      );
      _encHex = _hex(_encrypted!);
    } catch (e) {
      _encHex = 'Error: $e';
    }
    setState(() => _loading = false);
  }

  Future<void> _decrypt() async {
    if (_encrypted == null || _cipher == null) return;
    setState(() => _loading = true);
    try {
      final plain = await msec.decrypt(
        cipher: _cipher!,
        ciphertext: _encrypted!,
        aad: Uint8List(0),
      );
      _decrypted = utf8.decode(plain);
    } catch (e) {
      _decrypted = 'Error: $e';
    }
    setState(() => _loading = false);
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        TextField(
          controller: _input,
          decoration: const InputDecoration(
            labelText: 'Plaintext',
            border: OutlineInputBorder(),
          ),
        ),
        const SizedBox(height: 12),
        SegmentedButton<String>(
          segments: const [
            ButtonSegment(value: 'AES-256-GCM', label: Text('AES-GCM')),
            ButtonSegment(value: 'ChaCha20', label: Text('ChaCha20')),
          ],
          selected: {_algo},
          onSelectionChanged: (s) => setState(() => _algo = s.first),
        ),
        const SizedBox(height: 12),
        Row(
          children: [
            Expanded(
              child: FilledButton(
                onPressed: _loading ? null : _encrypt,
                child: const Text('Encrypt'),
              ),
            ),
            const SizedBox(width: 8),
            Expanded(
              child: FilledButton.tonal(
                onPressed: _encrypted == null || _loading ? null : _decrypt,
                child: const Text('Decrypt'),
              ),
            ),
          ],
        ),
        if (_loading) const _Loader(),
        if (_encHex.isNotEmpty)
          _ResultCard('Ciphertext (${_encrypted!.length}B)', _encHex),
        if (_decrypted.isNotEmpty) _ResultCard('Decrypted', _decrypted),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// KDF Tab (HKDF)
// ---------------------------------------------------------------------------

class _KdfTab extends StatefulWidget {
  const _KdfTab();
  @override
  State<_KdfTab> createState() => _KdfTabState();
}

class _KdfTabState extends State<_KdfTab> {
  final _ikmInput = TextEditingController(text: 'master-secret');
  final _infoInput = TextEditingController(text: 'subkey-1');
  final _lenInput = TextEditingController(text: '32');
  String _derived = '';
  String _prk = '';
  bool _loading = false;

  Future<void> _derive() async {
    setState(() => _loading = true);
    try {
      final ikm = Uint8List.fromList(utf8.encode(_ikmInput.text));
      final info = Uint8List.fromList(utf8.encode(_infoInput.text));
      final len = int.parse(_lenInput.text);
      final result = MHKDF.derive(ikm: ikm, info: info, outputLen: len);
      _derived = _hex(result);
    } catch (e) {
      _derived = 'Error: $e';
    }
    setState(() => _loading = false);
  }

  Future<void> _extract() async {
    setState(() => _loading = true);
    try {
      final ikm = Uint8List.fromList(utf8.encode(_ikmInput.text));
      final result = MHKDF.extract(ikm: ikm);
      _prk = _hex(result);
    } catch (e) {
      _prk = 'Error: $e';
    }
    setState(() => _loading = false);
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        TextField(
          controller: _ikmInput,
          decoration: const InputDecoration(
            labelText: 'Input Key Material (IKM)',
            border: OutlineInputBorder(),
          ),
        ),
        const SizedBox(height: 8),
        TextField(
          controller: _infoInput,
          decoration: const InputDecoration(
            labelText: 'Info (context string)',
            border: OutlineInputBorder(),
          ),
        ),
        const SizedBox(height: 8),
        TextField(
          controller: _lenInput,
          keyboardType: TextInputType.number,
          decoration: const InputDecoration(
            labelText: 'Output length (bytes)',
            border: OutlineInputBorder(),
          ),
        ),
        const SizedBox(height: 12),
        Row(
          children: [
            Expanded(
              child: FilledButton(
                onPressed: _loading ? null : _derive,
                child: const Text('HKDF Derive'),
              ),
            ),
            const SizedBox(width: 8),
            Expanded(
              child: FilledButton.tonal(
                onPressed: _loading ? null : _extract,
                child: const Text('HKDF Extract'),
              ),
            ),
          ],
        ),
        if (_loading) const _Loader(),
        if (_derived.isNotEmpty) _ResultCard('Derived Key', _derived),
        if (_prk.isNotEmpty) _ResultCard('PRK (Extract)', _prk),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// Streaming Tab (encrypt/decrypt/hash files + compression)
// ---------------------------------------------------------------------------

class _StreamingTab extends StatefulWidget {
  const _StreamingTab();
  @override
  State<_StreamingTab> createState() => _StreamingTabState();
}

class _StreamingTabState extends State<_StreamingTab> {
  String _status = '';
  double _progress = 0;
  bool _loading = false;
  String _algo = 'AES-256-GCM';
  String _compAlgo = 'None';
  final _sizeKb = TextEditingController(text: '256');

  Future<void> _testStreamEncryptDecrypt() async {
    setState(() {
      _loading = true;
      _status = 'Creating test file...';
      _progress = 0;
    });
    try {
      final dir = await Directory.systemTemp.createTemp('stream_test');
      final inputPath = '${dir.path}/input.bin';
      final encPath = '${dir.path}/encrypted.bin';
      final decPath = '${dir.path}/decrypted.bin';

      // Create test file
      final sizeBytes = int.parse(_sizeKb.text) * 1024;
      final data = Uint8List(sizeBytes);
      for (int i = 0; i < data.length; i++) {
        data[i] = i % 256;
      }
      await File(inputPath).writeAsBytes(data);

      // Create cipher
      final key = _algo == 'AES-256-GCM'
          ? await msec.generateAes256GcmKey()
          : await msec.generateChacha20Poly1305Key();
      final cipher = _algo == 'AES-256-GCM'
          ? await msec.createAes256Gcm(key: key)
          : await msec.createChacha20Poly1305(key: key);

      // Encrypt
      setState(() => _status = 'Encrypting ${_sizeKb.text}KB...');
      if (_compAlgo == 'None') {
        await StreamingService.encryptFile(
          inputPath: inputPath,
          outputPath: encPath,
          cipher: cipher,
        ).listen((p) => setState(() => _progress = p)).asFuture();
      } else {
        final comp = _compAlgo == 'Zstd'
            ? CompressionAlgorithm.zstd
            : CompressionAlgorithm.brotli;
        await CompressionService.compressAndEncryptFile(
          inputPath: inputPath,
          outputPath: encPath,
          cipher: cipher,
          config: CompressionConfig(algorithm: comp),
        ).listen((p) => setState(() => _progress = p)).asFuture();
      }

      final encSize = await File(encPath).length();
      setState(() {
        _status = 'Encrypted: ${encSize}B. Decrypting...';
        _progress = 0;
      });

      // Decrypt
      final cipher2 = _algo == 'AES-256-GCM'
          ? await msec.createAes256Gcm(key: key)
          : await msec.createChacha20Poly1305(key: key);

      if (_compAlgo == 'None') {
        await StreamingService.decryptFile(
          inputPath: encPath,
          outputPath: decPath,
          cipher: cipher2,
        ).listen((p) => setState(() => _progress = p)).asFuture();
      } else {
        await CompressionService.decryptAndDecompressFile(
          inputPath: encPath,
          outputPath: decPath,
          cipher: cipher2,
        ).listen((p) => setState(() => _progress = p)).asFuture();
      }

      // Verify
      final original = await File(inputPath).readAsBytes();
      final decrypted = await File(decPath).readAsBytes();
      final match = _bytesEqual(original, decrypted);

      setState(() {
        _progress = 1;
        _status =
            'Done! Roundtrip ${match ? "PASS" : "FAIL"}\n'
            'Input: ${original.length}B -> Encrypted: ${encSize}B -> Decrypted: ${decrypted.length}B';
      });

      await dir.delete(recursive: true);
    } catch (e) {
      setState(() => _status = 'Error: $e');
    }
    setState(() => _loading = false);
  }

  Future<void> _testStreamHash() async {
    setState(() {
      _loading = true;
      _status = 'Creating test file for msec...';
      _progress = 0;
    });
    try {
      final dir = await Directory.systemTemp.createTemp('hash_test');
      final filePath = '${dir.path}/input.bin';

      final sizeBytes = int.parse(_sizeKb.text) * 1024;
      final data = Uint8List(sizeBytes);
      for (int i = 0; i < data.length; i++) {
        data[i] = i % 256;
      }
      await File(filePath).writeAsBytes(data);

      // One-shot hash for comparison
      final oneshotHash = await msec.blake3Hash(data: data);

      // Streaming hash
      setState(() => _status = 'Streaming BLAKE3 hash...');
      final hasher = await msec.createBlake3();
      final streamHash = await StreamingService.hashFile(
        filePath: filePath,
        hasher: hasher,
      );

      final match = _bytesEqual(oneshotHash, streamHash);
      setState(() {
        _progress = 1;
        _status =
            'Streaming hash ${match ? "PASS" : "FAIL"}\n'
            'One-shot: ${_hex(oneshotHash).substring(0, 16)}...\n'
            'Stream:   ${_hex(streamHash).substring(0, 16)}...';
      });

      await dir.delete(recursive: true);
    } catch (e) {
      setState(() => _status = 'Error: $e');
    }
    setState(() => _loading = false);
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        TextField(
          controller: _sizeKb,
          keyboardType: TextInputType.number,
          decoration: const InputDecoration(
            labelText: 'Test file size (KB)',
            border: OutlineInputBorder(),
          ),
        ),
        const SizedBox(height: 12),
        Text('Cipher', style: Theme.of(context).textTheme.labelMedium),
        SegmentedButton<String>(
          segments: const [
            ButtonSegment(value: 'AES-256-GCM', label: Text('AES-GCM')),
            ButtonSegment(value: 'ChaCha20', label: Text('ChaCha20')),
          ],
          selected: {_algo},
          onSelectionChanged: (s) => setState(() => _algo = s.first),
        ),
        const SizedBox(height: 8),
        Text('Compression', style: Theme.of(context).textTheme.labelMedium),
        SegmentedButton<String>(
          segments: const [
            ButtonSegment(value: 'None', label: Text('None')),
            ButtonSegment(value: 'Zstd', label: Text('Zstd')),
            ButtonSegment(value: 'Brotli', label: Text('Brotli')),
          ],
          selected: {_compAlgo},
          onSelectionChanged: (s) => setState(() => _compAlgo = s.first),
        ),
        const SizedBox(height: 12),
        Row(
          children: [
            Expanded(
              child: FilledButton(
                onPressed: _loading ? null : _testStreamEncryptDecrypt,
                child: const Text('Encrypt/Decrypt'),
              ),
            ),
            const SizedBox(width: 8),
            Expanded(
              child: FilledButton.tonal(
                onPressed: _loading ? null : _testStreamHash,
                child: const Text('Stream Hash'),
              ),
            ),
          ],
        ),
        const SizedBox(height: 12),
        if (_loading || _progress > 0)
          LinearProgressIndicator(value: _loading ? _progress : 1),
        if (_loading) const _Loader(),
        if (_status.isNotEmpty) _ResultCard('Status', _status),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// Vault Tab (EVFS)
// ---------------------------------------------------------------------------

class _VaultTab extends StatefulWidget {
  const _VaultTab();
  @override
  State<_VaultTab> createState() => _VaultTabState();
}

class _VaultTabState extends State<_VaultTab> {
  final _vaultSizeMb = TextEditingController(text: '5');
  final _segName = TextEditingController(text: 'secret.txt');
  final _segData = TextEditingController(text: 'Vault data here');
  final _streamSizeKb = TextEditingController(text: '512');
  String _status = '';
  List<String> _segments = [];
  String _readResult = '';
  String _capacityInfo = '';
  String _healthInfo = '';
  String _defragInfo = '';
  double _streamProgress = 0;
  bool _loading = false;
  bool _vaultOpen = false;
  String _compAlgo = 'Zstd';
  final _resizeMb = TextEditingController(text: '10');
  String _keyMgmtInfo = '';
  String? _exportPath;

  msec.VaultHandle? _handle;
  Uint8List? _key;
  String? _vaultPath;

  Future<void> _createVault() async {
    setState(() => _loading = true);
    try {
      final dir = await Directory.systemTemp.createTemp('demo_vault');
      _vaultPath = '${dir.path}/demo.vault';
      _key = await msec.generateAes256GcmKey();
      final sizeMb = int.tryParse(_vaultSizeMb.text) ?? 5;
      _handle = await VaultService.create(
        path: _vaultPath!,
        key: _key!,
        algorithm: 'aes-256-gcm',
        capacityBytes: sizeMb * 1024 * 1024,
      );
      _vaultOpen = true;
      _status = 'Vault created (${sizeMb}MB, AES-256-GCM)';
      await _refreshList();
      await _refreshCapacity();
    } catch (e) {
      _status = 'Error: $e';
    }
    setState(() => _loading = false);
  }

  Future<void> _closeVault() async {
    if (!_vaultOpen || _handle == null) return;
    try {
      await VaultService.close(handle: _handle!);
      _handle = null;
      _vaultOpen = false;
      _segments = [];
      _readResult = '';
      _capacityInfo = '';
      _healthInfo = '';
      _defragInfo = '';
      _status = 'Vault closed';
    } catch (e) {
      _status = 'Error: $e';
    }
    setState(() {});
  }

  Future<void> _reopenVault() async {
    if (_vaultPath == null || _key == null) return;
    setState(() => _loading = true);
    try {
      _handle = await VaultService.open(path: _vaultPath!, key: _key!);
      _vaultOpen = true;
      _status = 'Vault reopened (WAL recovery ran)';
      await _refreshList();
      await _refreshCapacity();
    } catch (e) {
      _status = 'Error: $e';
    }
    setState(() => _loading = false);
  }

  Future<void> _writeSegment() async {
    if (!_vaultOpen || _handle == null) return;
    setState(() => _loading = true);
    try {
      final data = Uint8List.fromList(utf8.encode(_segData.text));
      CompressionConfig? comp;
      if (_compAlgo == 'Zstd') {
        comp = const CompressionConfig(algorithm: CompressionAlgorithm.zstd);
      } else if (_compAlgo == 'Brotli') {
        comp = const CompressionConfig(algorithm: CompressionAlgorithm.brotli);
      }
      await VaultService.write(
        handle: _handle!,
        name: _segName.text,
        data: data,
        compression: comp,
      );
      _status = 'Wrote "${_segName.text}" (${data.length}B, $_compAlgo)';
      await _refreshList();
      await _refreshCapacity();
    } catch (e) {
      _status = 'Error: $e';
    }
    setState(() => _loading = false);
  }

  Future<void> _readSegment(String name) async {
    if (!_vaultOpen || _handle == null) return;
    setState(() => _loading = true);
    try {
      final data = await VaultService.read(handle: _handle!, name: name);
      // Try decoding as UTF-8, fallback to hex
      try {
        _readResult = '[$name] ${utf8.decode(data)}';
      } catch (_) {
        _readResult = '[$name] ${_hex(data)}';
      }
    } catch (e) {
      _readResult = 'Error reading "$name": $e';
    }
    setState(() => _loading = false);
  }

  Future<void> _deleteSegment(String name) async {
    if (!_vaultOpen || _handle == null) return;
    setState(() => _loading = true);
    try {
      await VaultService.delete(handle: _handle!, name: name);
      _status = 'Deleted "$name" (securely erased)';
      _readResult = '';
      await _refreshList();
      await _refreshCapacity();
    } catch (e) {
      _status = 'Error: $e';
    }
    setState(() => _loading = false);
  }

  Future<void> _streamWrite() async {
    if (!_vaultOpen || _handle == null) return;
    setState(() {
      _loading = true;
      _streamProgress = 0;
    });
    try {
      final sizeBytes = int.parse(_streamSizeKb.text) * 1024;
      const chunkSize = 64 * 1024;

      // Generate data as a stream of 64KB chunks
      Stream<Uint8List> dataStream() async* {
        var remaining = sizeBytes;
        var offset = 0;
        while (remaining > 0) {
          final n = remaining < chunkSize ? remaining : chunkSize;
          final chunk = Uint8List(n);
          for (var i = 0; i < n; i++) {
            chunk[i] = (offset + i) % 256;
          }
          yield chunk;
          offset += n;
          remaining -= n;
        }
      }

      await VaultService.writeStream(
        handle: _handle!,
        name: 'stream-${_streamSizeKb.text}kb.bin',
        totalSize: sizeBytes,
        data: dataStream(),
        onProgress: (p) => setState(() => _streamProgress = p),
      );

      _status =
          'Stream-wrote ${_fmtBytes(BigInt.from(sizeBytes))} as '
          '"stream-${_streamSizeKb.text}kb.bin"';
      await _refreshList();
      await _refreshCapacity();
    } catch (e) {
      _status = 'Error: $e';
    }
    setState(() => _loading = false);
  }

  Future<void> _streamRead() async {
    if (!_vaultOpen || _handle == null) return;
    final name = 'stream-${_streamSizeKb.text}kb.bin';
    if (!_segments.contains(name)) {
      setState(() => _status = 'Write "$name" first');
      return;
    }
    setState(() {
      _loading = true;
      _streamProgress = 0;
    });
    try {
      final chunks = <Uint8List>[];
      await for (final chunk in VaultService.readStream(
        handle: _handle!,
        name: name,
        onProgress: (p) => setState(() => _streamProgress = p),
      )) {
        chunks.add(chunk);
      }
      final total = chunks.fold<int>(0, (sum, c) => sum + c.length);

      // Verify pattern
      var offset = 0;
      var match = true;
      for (final chunk in chunks) {
        for (var i = 0; i < chunk.length && match; i++) {
          if (chunk[i] != (offset + i) % 256) match = false;
        }
        offset += chunk.length;
      }

      _status =
          'Stream-read "$name": ${_fmtBytes(BigInt.from(total))} '
          'in ${chunks.length} chunks — ${match ? "PASS" : "FAIL"}';
    } catch (e) {
      _status = 'Error: $e';
    }
    setState(() => _loading = false);
  }

  Future<void> _refreshList() async {
    if (!_vaultOpen || _handle == null) return;
    _segments = await VaultService.list(handle: _handle!);
  }

  Future<void> _refreshCapacity() async {
    if (!_vaultOpen || _handle == null) return;
    final cap = await VaultService.capacity(handle: _handle!);
    _capacityInfo =
        'Total: ${_fmtBytes(cap.totalBytes)}  |  '
        'Used: ${_fmtBytes(cap.usedBytes)}  |  '
        'Free-list: ${_fmtBytes(cap.freeListBytes)}  |  '
        'Unallocated: ${_fmtBytes(cap.unallocatedBytes)}';
  }

  Future<void> _healthCheck() async {
    if (!_vaultOpen || _handle == null) return;
    setState(() => _loading = true);
    try {
      final h = await VaultService.health(handle: _handle!);
      final frag = (h.fragmentationRatio * 100).toStringAsFixed(1);
      _healthInfo =
          'Consistent: ${h.isConsistent}\n'
          'Segments: ${h.segmentCount}  |  Free regions: ${h.freeRegionCount}\n'
          'Used: ${_fmtBytes(h.usedBytes)}  |  Free-list: ${_fmtBytes(h.freeListBytes)}  |  Unalloc: ${_fmtBytes(h.unallocatedBytes)}\n'
          'Largest free block: ${_fmtBytes(h.largestFreeBlock)}  |  Fragmentation: $frag%';
      _status = 'Health check complete';
    } catch (e) {
      _healthInfo = 'Error: $e';
    }
    setState(() => _loading = false);
  }

  Future<void> _defragVault() async {
    if (!_vaultOpen || _handle == null) return;
    setState(() => _loading = true);
    try {
      final r = await VaultService.defragment(handle: _handle!);
      _defragInfo =
          'Moved: ${r.segmentsMoved} segments  |  '
          'Reclaimed: ${_fmtBytes(r.bytesReclaimed)}  |  '
          'Free regions before: ${r.freeRegionsBefore}';
      _status = 'Defragmentation complete';
      await _refreshCapacity();
    } catch (e) {
      _defragInfo = 'Error: $e';
    }
    setState(() => _loading = false);
  }

  Future<void> _resizeVault() async {
    if (!_vaultOpen || _handle == null) return;
    setState(() => _loading = true);
    try {
      final newMb = int.tryParse(_resizeMb.text) ?? 10;
      await VaultService.resize(
        handle: _handle!,
        newCapacityBytes: newMb * 1024 * 1024,
      );
      _status = 'Vault resized to ${newMb}MB';
      await _refreshCapacity();
    } catch (e) {
      _status = 'Error: $e';
    }
    setState(() => _loading = false);
  }

  Future<void> _rotateKey() async {
    if (!_vaultOpen || _handle == null) return;
    setState(() => _loading = true);
    try {
      final newKey = await msec.generateAes256GcmKey();
      _handle = await VaultService.rotateKey(handle: _handle!, newKey: newKey);
      _key = newKey;
      _keyMgmtInfo = 'Key rotated — all segments re-encrypted under new key';
      _status = 'Key rotation complete';
      await _refreshList();
      await _refreshCapacity();
    } catch (e) {
      _keyMgmtInfo = 'Rotation error: $e';
    }
    setState(() => _loading = false);
  }

  Future<void> _exportVault() async {
    if (!_vaultOpen || _handle == null) return;
    setState(() => _loading = true);
    try {
      final dir = Directory(_vaultPath!).parent;
      _exportPath = '${dir.path}/export.mvex';
      final wrappingKey = await msec.generateAes256GcmKey();
      await VaultService.export(
        handle: _handle!,
        wrappingKey: wrappingKey,
        exportPath: _exportPath!,
      );
      final size = await File(_exportPath!).length();
      _keyMgmtInfo =
          'Exported to ${_exportPath!.split('/').last} '
          '(${_fmtBytes(BigInt.from(size))})\n'
          'Wrapping key: ${_hex(wrappingKey).substring(0, 16)}...';
      _exportWrappingKey = wrappingKey;
      _status = 'Vault exported';
    } catch (e) {
      _keyMgmtInfo = 'Export error: $e';
    }
    setState(() => _loading = false);
  }

  Uint8List? _exportWrappingKey;

  Future<void> _importVault() async {
    if (_exportPath == null || _exportWrappingKey == null) {
      setState(() => _keyMgmtInfo = 'Export a vault first');
      return;
    }
    setState(() => _loading = true);
    try {
      if (_vaultOpen && _handle != null) {
        await VaultService.close(handle: _handle!);
      }

      final dir = Directory(_vaultPath!).parent;
      final importPath = '${dir.path}/imported.vault';
      final importKey = await msec.generateAes256GcmKey();

      _handle = await VaultService.importVault(
        archivePath: _exportPath!,
        wrappingKey: _exportWrappingKey!,
        destPath: importPath,
        newMasterKey: importKey,
        algorithm: 'aes-256-gcm',
        capacityBytes: (int.tryParse(_vaultSizeMb.text) ?? 5) * 1024 * 1024,
      );
      _key = importKey;
      _vaultPath = importPath;
      _vaultOpen = true;

      await _refreshList();
      await _refreshCapacity();
      _keyMgmtInfo =
          'Imported ${_segments.length} segments into new vault\n'
          'Path: ${importPath.split('/').last}';
      _status = 'Vault imported';
    } catch (e) {
      _keyMgmtInfo = 'Import error: $e';
    }
    setState(() => _loading = false);
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        // Vault size
        if (!_vaultOpen)
          Padding(
            padding: const EdgeInsets.only(bottom: 12),
            child: TextField(
              controller: _vaultSizeMb,
              keyboardType: TextInputType.number,
              decoration: const InputDecoration(
                labelText: 'Vault size (MB)',
                border: OutlineInputBorder(),
                isDense: true,
              ),
            ),
          ),

        // Vault lifecycle
        Row(
          children: [
            Expanded(
              child: FilledButton(
                onPressed: _vaultOpen || _loading ? null : _createVault,
                child: const Text('Create'),
              ),
            ),
            const SizedBox(width: 6),
            Expanded(
              child: FilledButton.tonal(
                onPressed: !_vaultOpen || _loading ? null : _closeVault,
                child: const Text('Close'),
              ),
            ),
            const SizedBox(width: 6),
            Expanded(
              child: OutlinedButton(
                onPressed: _vaultOpen || _vaultPath == null || _loading
                    ? null
                    : _reopenVault,
                child: const Text('Reopen'),
              ),
            ),
          ],
        ),
        const SizedBox(height: 8),

        if (_status.isNotEmpty)
          Card(
            color: Theme.of(context).colorScheme.primaryContainer,
            child: Padding(
              padding: const EdgeInsets.all(10),
              child: Text(
                _status,
                style: TextStyle(
                  fontSize: 13,
                  color: Theme.of(context).colorScheme.onPrimaryContainer,
                ),
              ),
            ),
          ),

        if (_capacityInfo.isNotEmpty)
          Card(
            color: Theme.of(context).colorScheme.tertiaryContainer,
            child: Padding(
              padding: const EdgeInsets.all(10),
              child: Text(
                _capacityInfo,
                style: TextStyle(
                  fontSize: 11,
                  fontFamily: 'monospace',
                  color: Theme.of(context).colorScheme.onTertiaryContainer,
                ),
              ),
            ),
          ),

        const SizedBox(height: 12),

        // Write segment
        if (_vaultOpen) ...[
          TextField(
            controller: _segName,
            decoration: const InputDecoration(
              labelText: 'Segment name',
              border: OutlineInputBorder(),
              isDense: true,
            ),
          ),
          const SizedBox(height: 8),
          TextField(
            controller: _segData,
            maxLines: 2,
            decoration: const InputDecoration(
              labelText: 'Segment data',
              border: OutlineInputBorder(),
              isDense: true,
            ),
          ),
          const SizedBox(height: 8),
          Text('Compression', style: Theme.of(context).textTheme.labelMedium),
          SegmentedButton<String>(
            segments: const [
              ButtonSegment(value: 'None', label: Text('None')),
              ButtonSegment(value: 'Zstd', label: Text('Zstd')),
              ButtonSegment(value: 'Brotli', label: Text('Brotli')),
            ],
            selected: {_compAlgo},
            onSelectionChanged: (s) => setState(() => _compAlgo = s.first),
          ),
          const SizedBox(height: 8),
          FilledButton.icon(
            onPressed: _loading ? null : _writeSegment,
            icon: const Icon(Icons.save, size: 18),
            label: const Text('Write Segment'),
          ),
          const Divider(height: 24),

          // Segment list
          Text(
            'Segments (${_segments.length})',
            style: Theme.of(context).textTheme.titleSmall,
          ),
          if (_segments.isEmpty)
            const Padding(
              padding: EdgeInsets.symmetric(vertical: 8),
              child: Text(
                'No segments yet',
                style: TextStyle(color: Colors.grey),
              ),
            ),
          ..._segments.map(
            (name) => ListTile(
              dense: true,
              leading: const Icon(Icons.insert_drive_file, size: 20),
              title: Text(name),
              trailing: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  IconButton(
                    icon: const Icon(Icons.visibility, size: 20),
                    tooltip: 'Read',
                    onPressed: () => _readSegment(name),
                  ),
                  IconButton(
                    icon: const Icon(Icons.delete, size: 20, color: Colors.red),
                    tooltip: 'Delete',
                    onPressed: () => _deleteSegment(name),
                  ),
                ],
              ),
            ),
          ),
          if (_readResult.isNotEmpty) _ResultCard('Read', _readResult),

          // Maintenance
          const Divider(height: 24),
          Text('Maintenance', style: Theme.of(context).textTheme.titleSmall),
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(
                child: FilledButton.tonal(
                  onPressed: _loading ? null : _healthCheck,
                  child: const Text('Health'),
                ),
              ),
              const SizedBox(width: 6),
              Expanded(
                child: FilledButton.tonal(
                  onPressed: _loading ? null : _defragVault,
                  child: const Text('Defrag'),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _resizeMb,
                  keyboardType: TextInputType.number,
                  decoration: const InputDecoration(
                    labelText: 'New size (MB)',
                    border: OutlineInputBorder(),
                    isDense: true,
                  ),
                ),
              ),
              const SizedBox(width: 6),
              FilledButton.tonal(
                onPressed: _loading ? null : _resizeVault,
                child: const Text('Resize'),
              ),
            ],
          ),
          if (_healthInfo.isNotEmpty) _ResultCard('Health', _healthInfo),
          if (_defragInfo.isNotEmpty) _ResultCard('Defrag', _defragInfo),

          const Divider(height: 24),

          // Key Management
          Text('Key Management', style: Theme.of(context).textTheme.titleSmall),
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(
                child: FilledButton.tonalIcon(
                  onPressed: _loading ? null : _rotateKey,
                  icon: const Icon(Icons.autorenew, size: 18),
                  label: const Text('Rotate Key'),
                ),
              ),
              const SizedBox(width: 6),
              Expanded(
                child: FilledButton.tonalIcon(
                  onPressed: _loading ? null : _exportVault,
                  icon: const Icon(Icons.upload_file, size: 18),
                  label: const Text('Export'),
                ),
              ),
              const SizedBox(width: 6),
              Expanded(
                child: FilledButton.tonalIcon(
                  onPressed: _loading || _exportPath == null
                      ? null
                      : _importVault,
                  icon: const Icon(Icons.download, size: 18),
                  label: const Text('Import'),
                ),
              ),
            ],
          ),
          if (_keyMgmtInfo.isNotEmpty) _ResultCard('Key Mgmt', _keyMgmtInfo),

          const Divider(height: 24),

          // Streaming segment I/O
          Text('Streaming I/O', style: Theme.of(context).textTheme.titleSmall),
          const SizedBox(height: 8),
          TextField(
            controller: _streamSizeKb,
            keyboardType: TextInputType.number,
            decoration: const InputDecoration(
              labelText: 'Stream size (KB)',
              border: OutlineInputBorder(),
              isDense: true,
            ),
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(
                child: FilledButton.icon(
                  onPressed: _loading ? null : _streamWrite,
                  icon: const Icon(Icons.upload, size: 18),
                  label: const Text('Stream Write'),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: FilledButton.tonalIcon(
                  onPressed: _loading ? null : _streamRead,
                  icon: const Icon(Icons.download, size: 18),
                  label: const Text('Stream Read'),
                ),
              ),
            ],
          ),
          if (_streamProgress > 0)
            Padding(
              padding: const EdgeInsets.only(top: 8),
              child: LinearProgressIndicator(
                value: _loading ? _streamProgress : 1,
              ),
            ),
        ],

        if (_loading) const _Loader(),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// Shared widgets & helpers
// ---------------------------------------------------------------------------

class _ResultCard extends StatelessWidget {
  final String label;
  final String value;
  const _ResultCard(this.label, this.value);

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.only(top: 10),
      child: Padding(
        padding: const EdgeInsets.all(10),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              label,
              style: Theme.of(
                context,
              ).textTheme.labelMedium?.copyWith(fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 4),
            SelectableText(
              value,
              style: Theme.of(
                context,
              ).textTheme.bodySmall?.copyWith(fontFamily: 'monospace'),
            ),
          ],
        ),
      ),
    );
  }
}

class _Loader extends StatelessWidget {
  const _Loader();
  @override
  Widget build(BuildContext context) => const Padding(
    padding: EdgeInsets.all(16),
    child: Center(child: CircularProgressIndicator()),
  );
}

String _hex(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

String _fmtBytes(BigInt bytes) {
  final b = bytes.toInt();
  if (b < 1024) return '${b}B';
  if (b < 1024 * 1024) return '${(b / 1024).toStringAsFixed(1)}KB';
  return '${(b / (1024 * 1024)).toStringAsFixed(1)}MB';
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (int i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
