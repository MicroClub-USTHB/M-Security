<div align="center">
  <img src="assets/m-security.png" alt="M-Security Logo" width="200">
</div>
<br />

# M-Security

[![pub package](https://img.shields.io/pub/v/m_security.svg)](https://pub.dev/packages/m_security)
[![pub points](https://img.shields.io/pub/points/m_security.svg?color=2E8B57)](https://pub.dev/packages/m_security/score)
[![pub downloads](https://img.shields.io/pub/dm/m_security.svg?color=blue)](https://pub.dev/packages/m_security/score)
[![Platforms](https://img.shields.io/badge/Platforms-Android%20|%20iOS%20|%20macOS%20|%20Linux%20|%20Windows-blueviolet)](#platform-support)
[![CI](https://github.com/MicroClub-USTHB/M-Security/actions/workflows/ci.yml/badge.svg)](https://github.com/MicroClub-USTHB/M-Security/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A native Rust security SDK for Flutter, providing high-performance cryptographic services, streaming encryption with compression, an encrypted virtual file system (EVFS), and secure memory management. All operations run in Rust through [Flutter Rust Bridge](https://cjycode.com/flutter_rust_bridge/). No Dart-level crypto, no platform channels.

Built and maintained by the **Dev Department** of [MicroClub](https://github.com/MicroClub-USTHB), the computer science club at USTHB (University of Science and Technology Houari Boumediene, Algiers).

## Features

| Category                 | Algorithm / Feature    | Highlights                                                  |
| ------------------------ | ---------------------- | ----------------------------------------------------------- |
| **AEAD Encryption**      | AES-256-GCM            | Industry-standard, hardware-accelerated on most CPUs        |
|                          | ChaCha20-Poly1305      | Optimized for mobile (no AES hardware needed)               |
| **Streaming Encryption** | AES-256-GCM / ChaCha20 | Chunk-based processing with progress callbacks              |
| **Compression**          | Zstd, Brotli           | Configurable levels, integrated into streaming and EVFS     |
| **Hashing**              | BLAKE3                 | Ultra-fast, one-shot and streaming                          |
|                          | SHA-3-256 (Keccak)     | NIST-standard, one-shot and streaming                       |
| **Password Hashing**     | Argon2id               | PHC winner, Mobile and Desktop presets                      |
| **Key Derivation**       | HKDF-SHA256            | RFC 5869, extract-then-expand with domain separation        |
| **Encrypted VFS (EVFS)** | `.vault` container     | Named segments, WAL recovery, shadow index, secure deletion |

**Security by design:**

- All key material lives in Rust behind opaque handles; raw keys never cross FFI
- Automatic memory zeroization on drop (`ZeroizeOnDrop`)
- Nonces generated internally via OS-level CSPRNG (`OsRng`)
- AEAD tag verification prevents silent decryption of tampered data
- `panic = "abort"` in release profile, preventing undefined behavior from panics crossing FFI
- `clippy::unwrap_used = "deny"`, ensuring all operations return `Result<T, CryptoError>`

## Installation

Add to your `pubspec.yaml`:

```yaml
dependencies:
  m_security: ^0.3.2
```

Then run:

```bash
flutter pub get
```

### Prerequisites

M-Security compiles Rust code during the Flutter build. You need:

- **Rust toolchain** (stable):

  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```

- **Platform-specific tools:**

  | Platform    | Requirements                                                  |
  | ----------- | ------------------------------------------------------------- |
  | Android     | Android NDK (r27c recommended)                                |
  | iOS / macOS | Xcode with command line tools                                 |
  | Linux       | `clang`, `cmake`, `ninja-build`, `pkg-config`, `libgtk-3-dev` |
  | Windows     | Visual Studio Build Tools + LLVM                              |

Rust compilation is handled automatically by [Cargokit](https://github.com/nickhudson/cargokit) during `flutter build` / `flutter run`.

## Getting Started

Initialize the Rust library once at app startup:

```dart
import 'package:m_security/m_security.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await RustLib.init();
  runApp(const MyApp());
}
```

## Usage

All examples below use a single import:

```dart
import 'package:m_security/m_security.dart';
```

### AES-256-GCM Encryption

```dart
final aes = AesGcmService();
await aes.initWithRandomKey();

// Encrypt and decrypt raw bytes
final encrypted = await aes.encrypt(plaintext);
final decrypted = await aes.decrypt(encrypted);

// Convenience: encrypt and decrypt UTF-8 strings
final ciphertext = await aes.encryptString('sensitive data');
final original = await aes.decryptString(ciphertext);
```

### ChaCha20-Poly1305 Encryption

```dart
final chacha = Chacha20Service();
await chacha.initWithRandomKey();

// Basic encrypt and decrypt
final encrypted = await chacha.encryptString('sensitive data');
final original = await chacha.decryptString(encrypted);

// With Associated Authenticated Data (AAD)
final ct = await chacha.encryptString('payload', aad: 'metadata');
final pt = await chacha.decryptString(ct, aad: 'metadata');
```

Both ciphers output `nonce || ciphertext || tag`. Nonces (12 bytes) are auto-generated and authentication tags (16 bytes) are appended automatically.

### Argon2id Password Hashing

```dart
// Hash a password (returns PHC-format string)
final hash = await argon2IdHash(password: 'hunter2');

// Verify a password against a hash
await argon2IdVerify(phcHash: hash, password: 'hunter2');

// Explicit preset selection
final hash = await argon2IdHash(
  password: 'hunter2',
  preset: Argon2Preset.desktop,  // 256 MiB, t=4, p=8
);
```

The default preset is selected at compile time: `Argon2Preset.mobile` (64 MiB, t=3, p=4) unless built with `-DIS_DESKTOP=true`.

### HKDF-SHA256 Key Derivation

```dart
// Derive a key from input key material
final key = MHKDF.derive(
  ikm: masterKeyBytes,
  salt: saltBytes,          // optional
  info: Uint8List.fromList('encryption-key'.codeUnits),
  outputLen: 32,
);

// Domain separation: same master key, different derived keys
final encKey = MHKDF.derive(ikm: master, info: utf8.encode('enc'), outputLen: 32);
final macKey = MHKDF.derive(ikm: master, info: utf8.encode('mac'), outputLen: 32);

// Two-phase: extract PRK, then expand
final prk = MHKDF.extract(ikm: masterKeyBytes, salt: saltBytes);
final derived = await MHKDF.expand(prk: prk, info: infoBytes, outputLen: 32);
```

Output length must be between 1 and 8160 bytes (RFC 5869 limit for SHA-256: 255 \* 32).

### Streaming Encryption

```dart
import 'package:m_security/src/rust/api/streaming.dart';

// Encrypt a file in chunks with progress
final encrypted = await streamEncrypt(
  plaintext: largeData,
  algorithm: StreamAlgorithm.aes256Gcm,
  compression: CompressionAlgorithm.zstd,
  compressionLevel: 3,
  onProgress: (progress) => print('${(progress * 100).toInt()}%'),
);

// Decrypt
final decrypted = await streamDecrypt(
  ciphertext: encrypted,
  algorithm: StreamAlgorithm.aes256Gcm,
  compression: CompressionAlgorithm.zstd,
);
```

### Encrypted Virtual File System (EVFS)

```dart
import 'package:m_security/m_security.dart';

// Create a 10 MB vault with AES-256-GCM
final handle = await VaultService.create(
  path: '/path/to/my.vault',
  key: key,
  algorithm: 'aes-256-gcm',
  capacityBytes: 10 * 1024 * 1024,
);

// Write a segment (with optional compression)
await VaultService.write(
  handle: handle,
  name: 'secret.txt',
  data: utf8.encode('confidential'),
  compression: CompressionConfig(algorithm: CompressionAlgorithm.zstd),
);

// Read it back (decompression is automatic)
final data = await VaultService.read(handle: handle, name: 'secret.txt');

// List segments, delete, close
final segments = await VaultService.list(handle: handle);
await VaultService.delete(handle: handle, name: 'secret.txt');
await VaultService.close(handle: handle);
```

#### Vault Maintenance

```dart
// Health check (read-only, no I/O)
final health = await VaultService.health(handle: handle);
print('Consistent: ${health.isConsistent}');
print('Fragmentation: ${(health.fragmentationRatio * 100).toStringAsFixed(1)}%');

// Defragment — compact segments, coalesce free space (WAL-protected)
final result = await VaultService.defragment(handle: handle);
print('Moved ${result.segmentsMoved} segments, reclaimed ${result.bytesReclaimed} bytes');

// Resize vault capacity (grow or shrink)
await VaultService.resize(handle: handle, newCapacityBytes: 20 * 1024 * 1024);
```

### BLAKE3 & SHA-3-256 Hashing

For one-shot and streaming hashing, use the lower-level FFI API directly:

```dart
import 'package:m_security/src/rust/api/hashing.dart';

// One-shot hashing (32-byte output)
final blake3Digest = await blake3Hash(data: inputBytes);
final sha3Digest = await sha3Hash(data: inputBytes);

// Streaming: process data in chunks
final hasher = createBlake3();  // or createSha3()
await hasherUpdate(handle: hasher, data: chunk1);
await hasherUpdate(handle: hasher, data: chunk2);
final digest = await hasherFinalize(handle: hasher);

// Reset and reuse
await hasherReset(handle: hasher);
```

## Architecture

<div align="center">
  <img src="assets/architecture.svg" alt="M-Security Architecture" width="600">
</div>

**Key design decisions:**

- **Opaque handles.** `CipherHandle` and `HasherHandle` are `#[frb(opaque)]`. Dart holds a pointer, never raw key bytes.
- **Trait objects.** `Box<dyn Encryption>` and `Box<dyn Hasher>` with `Send + Sync + 'static` enable runtime algorithm selection.
- **SecretBuffer.** All key material is wrapped in `SecretBuffer` which derives `ZeroizeOnDrop`. Memory is zeroed when handles are dropped.
- **No panics across FFI.** `panic = "abort"` in release profile. All FFI functions return `Result<T, CryptoError>`.
- **Format headers.** Encrypted data includes a `MSEC` magic header with version and algorithm identifiers for forward compatibility.

## Rust API Reference

### Encryption (`CipherHandle`)

```
create_aes256_gcm(key: Vec<u8>)              -> Result<CipherHandle>
create_chacha20_poly1305(key: Vec<u8>)       -> Result<CipherHandle>
encrypt(cipher, plaintext, aad)              -> Result<Vec<u8>>
decrypt(cipher, ciphertext, aad)             -> Result<Vec<u8>>
generate_aes256_gcm_key()                    -> Result<Vec<u8>>
generate_chacha20_poly1305_key()             -> Result<Vec<u8>>
encryption_algorithm_id(cipher)              -> String
```

### Hashing (`HasherHandle`)

```
blake3_hash(data)           -> Vec<u8>          (one-shot, 32 bytes)
sha3_hash(data)             -> Vec<u8>          (one-shot, 32 bytes)
create_blake3()             -> HasherHandle      (streaming)
create_sha3()               -> HasherHandle      (streaming)
hasher_update(handle, data) -> Result<()>
hasher_reset(handle)        -> Result<()>
hasher_finalize(handle)     -> Result<Vec<u8>>
hasher_algorithm_id(handle) -> Result<String>
```

### Password Hashing (Argon2id)

```
argon2id_hash(password, preset)                     -> Result<String>  (PHC)
argon2id_hash_with_salt(password, salt, preset)     -> Result<String>  (PHC)
argon2id_verify(phc_hash, password)                 -> Result<()>
```

Presets: `Mobile` (64 MiB, t=3, p=4) | `Desktop` (256 MiB, t=4, p=8)

### Key Derivation (HKDF-SHA256)

```
hkdf_derive(ikm, salt?, info, output_len)   -> Result<Vec<u8>>   (one-shot)
hkdf_extract(ikm, salt?)                    -> Result<Vec<u8>>   (PRK)
hkdf_expand(prk, info, output_len)          -> Result<Vec<u8>>
```

## Platform Support

| Platform | Target                                             | Status    |
| -------- | -------------------------------------------------- | --------- |
| Android  | `aarch64-linux-android`, `armv7-linux-androideabi` | CI-tested |
| iOS      | `aarch64-apple-ios`, `aarch64-apple-ios-sim`       | CI-tested |
| macOS    | `aarch64-apple-darwin`, `x86_64-apple-darwin`      | Supported |
| Linux    | `x86_64-unknown-linux-gnu`                         | CI-tested |
| Windows  | `x86_64-pc-windows-msvc`                           | Supported |

## Testing

**Rust unit tests** (317 tests including EVFS streaming and defrag):

```bash
cd rust && cargo test
```

**Dart integration tests** (63 tests across all features, requires a running device/simulator):

```bash
cd example
flutter test integration_test/
```

## Tech Stack

| Component           | Version |
| ------------------- | ------- |
| Rust                | stable  |
| Flutter Rust Bridge | 2.11.1  |
| Dart SDK            | ^3.10.8 |
| Flutter SDK         | >=3.3.0 |

**Rust crates:** `aes-gcm` 0.10, `chacha20poly1305` 0.10, `blake3` 1.8, `sha3` 0.10, `argon2` 0.5, `hkdf` 0.12, `zstd` 0.13, `brotli` 7.0, `zeroize` 1.8

## Roadmap

| Feature                                  | Description                                                                         | Status  |
| ---------------------------------------- | ----------------------------------------------------------------------------------- | ------- |
| **Streaming encryption**                 | Process large files in chunks with progress callbacks                               | v0.3.0  |
| **Compression pipeline**                 | Zstd/Brotli compression integrated into streaming and EVFS                          | v0.3.0  |
| **Encrypted Virtual File System (EVFS)** | `.vault` container with named segments, WAL recovery, shadow index, secure deletion | v0.3.0  |
| **EVFS v2: Defrag & resize**             | Online defragmentation, vault resizing, health diagnostics                          | v0.3.1  |
| **EVFS v3: Streaming I/O**                | Constant-memory streaming reads/writes, per-chunk AEAD, progress callbacks          | v0.3.2  |
| **EVFS v2: Key rotation**                | Re-encrypt vault with new master key                                                | Planned |
| **Stealth storage**                      | Ephemeral secrets in Rust-managed memory with derived-path obfuscation              | Planned |
| **Hardware key wrap**                    | Master key in Secure Enclave (iOS) / KeyStore (Android) with biometric unlock       | Planned |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and PR workflow.

## License

MIT. See [LICENSE](LICENSE) for details.

Copyright (c) 2025 [MicroClub-USTHB](https://github.com/MicroClub-USTHB)
