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

A native Rust security SDK for Flutter. AEAD encryption, hashing, password hashing and key derivation, plus an encrypted virtual file system this release denies by default. All operations run in Rust through [Flutter Rust Bridge](https://cjycode.com/flutter_rust_bridge/). No Dart-level crypto, no platform channels.

Built and maintained by the **Dev Department** of [MicroClub](https://github.com/MicroClub-USTHB), the computer science club at USTHB (University of Science and Technology Houari Boumediene, Algiers).

## Features

| Category                 | Algorithm / Feature        | Highlights                                                  |
| ------------------------ | -------------------------- | ----------------------------------------------------------- |
| **AEAD Encryption**      | AES-256-GCM                | Industry-standard, hardware-accelerated on most CPUs        |
|                          | ChaCha20-Poly1305          | Optimized for mobile (no AES hardware needed)               |
| **Hashing**              | BLAKE3                     | Ultra-fast, one-shot and streaming                          |
|                          | SHA-3-256 (Keccak)         | NIST-standard, one-shot and streaming                       |
| **File Hashing**         | BLAKE3 / SHA-3-256         | Constant-memory hashing of a file path                      |
| **Password Hashing**     | Argon2id                   | PHC winner, Mobile and Desktop presets, bounded verification |
| **Key Derivation**       | HKDF-SHA256                | RFC 5869, extract-then-expand with domain separation        |
| **Compression**          | Zstd, Brotli               | Configurable levels, applied per vault segment              |
| **Encrypted VFS (EVFS)** | `.vault` container         | Named segments, metadata, rename, parallel reads. Denied unless you opt in, see [Current format restrictions](#current-format-restrictions) |
| **Zero-Copy I/O**        | mmap + DCO codec           | Memory-mapped vault reads, zero-copy Rust-to-Dart transfers |

**Security by design:**

- Cipher state lives in Rust behind an opaque handle. Raw key bytes still cross FFI in both directions, since `generateAes256GcmKey` and the HKDF calls return them to Dart while `createAes256Gcm`, `VaultService.create`, `open` and `rotateKey` take them from it
- Key material held in `SecretBuffer` is zeroed on drop (`ZeroizeOnDrop`). That is not a whole-process property, because expanded cipher state is not proved wiped and no test inspects freed memory
- One-shot AEAD nonces come from the OS CSPRNG (`OsRng`). EVFS segment nonces do not, see [Current format restrictions](#current-format-restrictions)
- AEAD tag verification prevents silent decryption of tampered data
- `panic = "abort"` in release profile, preventing undefined behavior from panics crossing FFI
- `clippy::unwrap_used = "deny"`. Fallible operations return `Result<T, CryptoError>`; the infallible ones, such as one-shot hashing, return their value directly
- Release builds strip all symbols except FRB entry points (LTO + ELF version script)
- CI reads the shipped Linux `.so` with `nm -D --defined-only` and fails if any of the seven removed entries is present or any of four kept entries is missing. That library is a debug build, so the check covers the version script rather than the release profile's stripping
- `mlock()` asks the OS to keep mmap'd ciphertext pages out of swap (unix). A failure is ignored, so it is best effort rather than a guarantee

## Current format restrictions

For now, EVFS is denied by default and the archive and encrypted stream formats are unreachable. Existing code still compiles.

EVFS `create` and `open` fail with `unsafeLegacyFormatDenied` before they touch the path. A caller who accepts the risk passes `UnsafeLegacyEvfsPolicy.allowUnauthenticatedV1V2` explicitly, and that opt-in does not change a single byte on disk or make an existing vault safe. The format derives its keys with no per-vault salt, so two vaults under the same master key repeat their encryption nonces. Segment nonces come from the segment index and generation rather than from the CSPRNG. Structural metadata is not authenticated. Write-ahead log replay can restore an index pointing at ciphertext that a delete already erased, so "WAL recovery" and "secure deletion" are not properties this release offers.

`.mvex` archive export and import, and encrypted or compressed `MSSE` stream files, are gone from the native library. Six methods are kept so current code compiles, namely `VaultService.export` and `importVault`, `StreamingService.encryptFile` and `decryptFile`, and `CompressionService.compressAndEncryptFile` and `decryptAndDecompressFile`. Each fails with exactly one `disabledFormat` error, the four stream methods by emitting it rather than returning it, before reading its input or creating its output. Files you already wrote in either format are unreadable by this release and unchanged on disk. There is no converter, and this release does not ship a replacement format.

File hashing through `StreamingService.hashFile` is unaffected.

## Installation

Add to your `pubspec.yaml`:

```yaml
dependencies:
  m_security: ^0.3.6
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
final desktopHash = await argon2IdHash(
  password: 'hunter2',
  preset: Argon2Preset.desktop,  // 256 MiB, t=4, p=8
);
```

The default preset is selected at compile time: `Argon2Preset.mobile` (64 MiB, t=3, p=4) unless built with `-DIS_DESKTOP=true`.

Verification is bounded before it reserves anything. The password must be at most 1024 UTF-8 bytes. The hash must be Argon2id version 19, with `t` from 1 to 4, `p` from 1 to 8, `m` from `8*p` KiB up to 262144 KiB, and a 16 to 64 byte output. The salt must decode to at least 8 bytes, and the PHC parser caps the encoded form at 64 characters, so 48 decoded bytes is the largest that reaches a verifier at all.

Parameters outside those bounds return `Argon2PolicyViolation`. Input the PHC parser rejects, including an over-long salt, returns `InvalidParameter`. Both come back before any Argon2 memory is allocated. One verification runs at a time, so a call arriving during another gets `Argon2VerificationBusy` rather than waiting.

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

### File hashing

```dart
final hasher = await createBlake3();  // or createSha3()

final digest = await StreamingService.hashFile(
  filePath: '/path/to/large.bin',
  hasher: hasher,
);
```

The file is read in 64 KB chunks, so memory use does not grow with its size. `StreamingService.encryptFile` and `decryptFile` are disabled, see [Current format restrictions](#current-format-restrictions).

### Encrypted Virtual File System (EVFS)

Every snippet below needs the opt-in shown here. Without it `create` and `open` return `unsafeLegacyFormatDenied` and never touch the path.

```dart
import 'package:m_security/m_security.dart';

// Create a 10 MB vault with AES-256-GCM
final handle = await VaultService.create(
  path: '/path/to/my.vault',
  key: key,
  algorithm: 'aes-256-gcm',
  capacityBytes: 10 * 1024 * 1024,
  unsafeLegacyPolicy: UnsafeLegacyEvfsPolicy.allowUnauthenticatedV1V2,
);

// Write a segment (with optional compression and metadata)
await VaultService.write(
  handle: handle,
  name: 'secret.txt',
  data: utf8.encode('confidential'),
  compression: CompressionConfig(algorithm: CompressionAlgorithm.zstd),
  metadata: {'mime': 'text/plain', 'author': 'alice'},
);

// Read it back (decompression is automatic, metadata included)
final result = await VaultService.read(handle: handle, name: 'secret.txt');
print(result.data);       // decrypted bytes
print(result.metadata);   // {'mime': 'text/plain', 'author': 'alice'}

// List segments, delete, close
final segments = await VaultService.list(handle: handle);
await VaultService.delete(handle: handle, name: 'secret.txt');
await VaultService.close(handle: handle);
```

#### Key rotation

```dart
// Rotate master key (re-encrypts all segments under the new key)
final newHandle = await VaultService.rotateKey(handle: handle, newKey: newKey);
// Old handle is invalidated; use newHandle from here
```

Rotation copies to a new file and renames, but the sequence is not crash-atomic. A machine that dies mid-rotation can leave a `.rotating` file that the next `open` cleans up, and that cleanup has no power-loss evidence behind it.

#### Segment Enhancements

```dart
// Rename a segment (index-only, no re-encryption)
await VaultService.renameSegment(handle: handle, oldName: 'draft.txt', newName: 'final.txt');

// Explicit flush — persist in-memory index to disk
await VaultService.flush(handle: handle);

// Parallel read — decrypt multiple segments concurrently
final results = await VaultService.readParallel(
  handle: handle,
  names: ['file1.bin', 'file2.bin', 'file3.bin'],
);
for (final r in results) {
  if (r.error != null) print('${r.name}: failed — ${r.error}');
  else print('${r.name}: ${r.data.length} bytes');
}
```

#### Vault Maintenance

```dart
// Health check (read-only, no I/O)
final health = await VaultService.health(handle: handle);
print('Consistent: ${health.isConsistent}');
print('Fragmentation: ${(health.fragmentationRatio * 100).toStringAsFixed(1)}%');

// Defragment, compacting segments and coalescing free space
final result = await VaultService.defragment(handle: handle);
print('Moved ${result.segmentsMoved} segments, reclaimed ${result.bytesReclaimed} bytes');

// Resize vault capacity (grow or shrink)
await VaultService.resize(handle: handle, newCapacityBytes: 20 * 1024 * 1024);
```

### BLAKE3 & SHA-3-256 Hashing

```dart
// One-shot hashing (32-byte output)
final blake3Digest = await blake3Hash(data: inputBytes);
final sha3Digest = await sha3Hash(data: inputBytes);

// Streaming: process data in chunks
final hasher = await createBlake3();  // or createSha3()
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
- **SecretBuffer.** Key material is wrapped in `SecretBuffer`, which derives `ZeroizeOnDrop`, so its buffer is zeroed when the handle drops. Cipher state expanded from that key is not covered by the same guarantee.
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

Two presets exist, `Mobile` (64 MiB, t=3, p=4) and `Desktop` (256 MiB, t=4, p=8). `argon2id_verify` enforces the limits described under [Argon2id Password Hashing](#argon2id-password-hashing).

### Key Derivation (HKDF-SHA256)

```
hkdf_derive(ikm, salt?, info, output_len)   -> Result<Vec<u8>>   (one-shot)
hkdf_extract(ikm, salt?)                    -> Result<Vec<u8>>   (PRK)
hkdf_expand(prk, info, output_len)          -> Result<Vec<u8>>
```

## Platform Support

The targets below are configured. What CI does with each of them varies, so the table says which, and the platform builds all wait for the release promotion rather than running on every change.

| Platform | Configured target                                  | What CI builds                                                   |
| -------- | -------------------------------------------------- | ---------------------------------------------------------------- |
| Android  | `aarch64-linux-android`, `armv7-linux-androideabi` | A release APK, at the promotion                                  |
| iOS      | `aarch64-apple-ios-sim`, `aarch64-apple-ios`       | A debug simulator build, at the promotion. The device target is never built |
| macOS    | `aarch64-apple-darwin`, `x86_64-apple-darwin`      | A debug build on the runner's own architecture, at the promotion. The other one is never built |
| Linux    | `x86_64-unknown-linux-gnu`                         | A release build at the promotion, and on every change a debug library that a clean consumer runs the tests against |

Ubuntu x86_64 is the only target with both a build and a runtime gate, and that gate runs against a debug library. No release-profile artifact is executed anywhere, on any platform.

## Testing

**Rust unit tests**, 466 in each profile.

```bash
cd rust && cargo test
cd rust && cargo test --release
```

**Host Dart tests**, 20 cases.

```bash
flutter test test/ tool/
```

**Containment integration tests**, 20 cases against the built native library.

```bash
cd example
flutter test integration_test/containment_test.dart -d macos
```

That resolves the package through the checkout. CI runs the same file on Linux from a consumer assembled outside this repository, depending only on the publish payload, which is the packaged path.

The broader suites under `integration_test/` and `example/integration_test/` hold 98 and 120 declarations. Nothing executes them. `containment_test.dart` is one of the 120 and is the only file in either tree that runs anywhere; reconciling the rest is later work.

## Tech Stack

| Component           | Version |
| ------------------- | -------- |
| Rust                | stable   |
| Flutter Rust Bridge | 2.12.0   |
| Dart SDK            | ^3.10.8  |
| Flutter SDK         | >=3.38.9 |

The bridge constraint is exact, not a range. The runtime compares the version stamped into the committed bindings against its own and refuses a mismatch, so a range would ship a package that installs and cannot start.

**Rust crates:** `aes-gcm` 0.10, `chacha20poly1305` 0.10, `blake3` 1.8, `sha3` 0.10, `argon2` 0.5, `hkdf` 0.12, `zstd` 0.13, `brotli` 7.0, `zeroize` 1.8, `memmap2` 0.9

## Roadmap

| Feature                                  | Description                                                                         | Status  |
| ---------------------------------------- | ----------------------------------------------------------------------------------- | ------- |
| **Compression pipeline**                 | Zstd/Brotli compression with configurable levels                                    | v0.3.0  |
| **Encrypted Virtual File System (EVFS)** | `.vault` container with named segments and a shadow index                           | v0.3.0  |
| **EVFS v2: Defrag & resize**             | Online defragmentation, vault resizing, health diagnostics                          | v0.3.1  |
| **EVFS v2: Streaming I/O**               | Constant-memory streaming reads/writes, per-chunk AEAD, progress callbacks          | v0.3.2  |
| **Zero-copy FFI optimization**           | mmap vault reads, DCO codec, release profile hardening, symbol stripping            | v0.3.3  |
| **EVFS v2: Key rotation**                | Master key rotation with Dart wrappers                                              | v0.3.4  |
| **Streaming encryption**                 | Chunked file encryption, shipped in v0.3.0 and withdrawn in v0.3.6. Returns over an authenticated stream format | Withdrawn |
| **`.mvex` portable archives**            | Vault export and import, shipped in v0.3.4 and withdrawn in v0.3.6. Returns over an authenticated archive format | Withdrawn |
| **Crash-atomic vault recovery**          | Write-ahead log ordering that cannot restore an index pointing at erased ciphertext | Planned |
| **Secure deletion**                      | Erasure the container format can actually guarantee                                 | Planned |
| **Stealth storage**                      | Ephemeral secrets in Rust-managed memory with derived-path obfuscation              | Planned |
| **Hardware key wrap**                    | Master key in Secure Enclave (iOS) / KeyStore (Android) with biometric unlock       | Planned |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and PR workflow.

## License

MIT. See [LICENSE](LICENSE) for details.

Copyright (c) 2025 [MicroClub-USTHB](https://github.com/MicroClub-USTHB)
