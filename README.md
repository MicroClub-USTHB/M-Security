# M-Security

[![pub package](https://img.shields.io/pub/v/m_security.svg)](https://pub.dev/packages/m_security)
[![CI](https://github.com/MicroClub-USTHB/M-Security/actions/workflows/ci.yml/badge.svg)](https://github.com/MicroClub-USTHB/M-Security/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A native Rust security SDK for Flutter, providing high-performance cryptographic services, secure memory management, and (coming soon) an encrypted virtual file system. All operations run in Rust through [Flutter Rust Bridge](https://cjycode.com/flutter_rust_bridge/). No Dart-level crypto, no platform channels.

Built and maintained by the **Dev Department** of [MicroClub](https://github.com/MicroClub-USTHB), the computer science club at USTHB (University of Science and Technology Houari Boumediene, Algiers).

## Features

| Category | Algorithm | Highlights |
|----------|-----------|------------|
| **AEAD Encryption** | AES-256-GCM | Industry-standard, hardware-accelerated on most CPUs |
| | ChaCha20-Poly1305 | Optimized for mobile (no AES hardware needed) |
| **Hashing** | BLAKE3 | Ultra-fast, one-shot and streaming |
| | SHA-3-256 (Keccak) | NIST-standard, one-shot and streaming |
| **Password Hashing** | Argon2id | PHC winner, Mobile and Desktop presets |
| **Key Derivation** | HKDF-SHA256 | RFC 5869, extract-then-expand with domain separation |

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
  m_security: ^0.1.0
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

  | Platform | Requirements |
  |----------|-------------|
  | Android | Android NDK (r27c recommended) |
  | iOS / macOS | Xcode with command line tools |
  | Linux | `clang`, `cmake`, `ninja-build`, `pkg-config`, `libgtk-3-dev` |
  | Windows | Visual Studio Build Tools + LLVM |

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

Output length must be between 1 and 8160 bytes (RFC 5869 limit for SHA-256: 255 * 32).

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

| Platform | Target | Status |
|----------|--------|--------|
| Android | `aarch64-linux-android`, `armv7-linux-androideabi` | CI-tested |
| iOS | `aarch64-apple-ios`, `aarch64-apple-ios-sim` | CI-tested |
| macOS | `aarch64-apple-darwin`, `x86_64-apple-darwin` | Supported |
| Linux | `x86_64-unknown-linux-gnu` | CI-tested |
| Windows | `x86_64-pc-windows-msvc` | Supported |

## Testing

**Rust unit tests** (79 tests including NIST/RFC test vectors):
```bash
cd rust && cargo test
```

**Dart integration tests** (44 tests across all features, requires a running device/simulator):
```bash
cd example
flutter test integration_test/aes_gcm_test.dart
flutter test integration_test/chacha20_test.dart
flutter test integration_test/hashing_test.dart
flutter test integration_test/argon2_test.dart
flutter test integration_test/hkdf_test.dart
```

## Tech Stack

| Component | Version |
|-----------|---------|
| Rust | stable |
| Flutter Rust Bridge | 2.11.1 |
| Dart SDK | ^3.10.8 |
| Flutter SDK | >=3.3.0 |

**Rust crates:** `aes-gcm` 0.10, `chacha20poly1305` 0.10, `blake3` 1.8, `sha3` 0.10, `argon2` 0.5, `hkdf` 0.12, `zeroize` 1.8

## Roadmap

v0.1.0 ships the cryptographic foundation. The following features are planned for future releases:

| Feature | Description | Status |
|---------|-------------|--------|
| **Zero-copy stream processing** | Process large files (2 GB+) in 64 KB chunks via Rust pointers, keeping RAM usage constant regardless of file size | Planned |
| **Compression + encryption pipeline** | `Raw Data -> Zstd/Brotli -> AES-GCM/ChaCha20`. Reduces disk usage and increases entropy before encryption | Planned |
| **Encrypted Virtual File System (EVFS)** | Single `.vault` container with random-access decryption of individual segments, isolated from filesystem exploration | Planned |
| **Secure shredding** | Multi-pass overwrite (random noise patterns) before deleting file pointers, preventing forensic recovery | Planned |
| **Stealth storage** | Ephemeral secrets (API tokens) held in Rust-managed memory with derived-path obfuscation to resist memory dump extraction | Planned |
| **Hardware key wrap** | Master key generated in Rust, wrap key stored in Secure Enclave (iOS) / KeyStore (Android), unlocked via biometric authentication | Planned |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and PR workflow.

## License

MIT. See [LICENSE](LICENSE) for details.

Copyright (c) 2025 [MicroClub-USTHB](https://github.com/MicroClub-USTHB)
