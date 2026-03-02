# M-Security

[![pub package](https://img.shields.io/pub/v/m_security.svg)](https://pub.dev/packages/m_security)
[![CI](https://github.com/MicroClub-USTHB/M-Security/actions/workflows/ci.yml/badge.svg)](https://github.com/MicroClub-USTHB/M-Security/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A native Rust cryptographic SDK for Flutter. High-performance hashing, authenticated encryption, and key derivation — all implemented in Rust and exposed to Dart via [Flutter Rust Bridge](https://cjycode.com/flutter_rust_bridge/) (FRB).

## Features

### Hashing

| Algorithm | API | Output |
|-----------|-----|--------|
| **BLAKE3** | One-shot (`blake3_hash`) + streaming (`HasherHandle`) | 32 bytes |
| **SHA-3-256** | One-shot (`sha3_hash`) + streaming (`HasherHandle`) | 32 bytes |
| **Argon2id** | Password hash + verify, Mobile/Desktop presets | PHC string |

### Authenticated Encryption (AEAD)

| Algorithm | Key | Nonce | Tag | Output Format |
|-----------|-----|-------|-----|---------------|
| **AES-256-GCM** | 32 B | 12 B (auto) | 16 B | `nonce \|\| ciphertext \|\| tag` |
| **ChaCha20-Poly1305** | 32 B | 12 B (auto) | 16 B | `nonce \|\| ciphertext \|\| tag` |

Both ciphers use the same `CipherHandle` interface — create, encrypt, decrypt, generate key.

### Key Derivation

| Algorithm | API |
|-----------|-----|
| **HKDF-SHA256** | `hkdf_derive`, `hkdf_extract`, `hkdf_expand` |

Derive multiple subkeys from a single master key using different `info` strings for domain separation.

## Architecture

<div align="center">
  <img src="assets/architecture.svg" alt="M-Security Architecture" width="600">
</div>

**Key design decisions:**

- **Opaque handles** — Crypto state lives in Rust behind `#[frb(opaque)]` handles (`CipherHandle`, `HasherHandle`). Dart holds a pointer, never raw key bytes.
- **Trait objects** — All implementations are behind `Box<dyn Trait>` with `Send + Sync + 'static`, allowing runtime algorithm selection.
- **Secure memory** — All key-holding structs derive `ZeroizeOnDrop`. Key material is zeroed when handles are dropped.
- **No panics across FFI** — `clippy::unwrap_used = "deny"`, `panic = "abort"` in release. All operations return `Result<T, CryptoError>`.

## Dart Usage

### AES-256-GCM

```dart
import 'package:m_security/src/encryption/aes_gcm.dart';

final aes = AesGcmService();
await aes.initWithRandomKey();

final encrypted = await aes.encryptString('hello');
final decrypted = await aes.decryptString(encrypted);
```

### ChaCha20-Poly1305

```dart
import 'package:m_security/src/encryption/chacha20.dart';

final chacha = Chacha20Service();
await chacha.initWithRandomKey();

final encrypted = await chacha.encryptString('hello');
final decrypted = await chacha.decryptString(encrypted);
```

### Argon2id Password Hashing

```dart
import 'package:m_security/src/hashing/argon2.dart';

// Hash (auto-selects Mobile or Desktop preset based on build flag)
final phc = await argon2IdHash(password: 'hunter2');

// Verify
await argon2IdVerify(phcHash: phc, password: 'hunter2');
```

### BLAKE3 / SHA-3 (One-shot)

```dart
import 'package:m_security/src/rust/api/hashing/blake3.dart';
import 'package:m_security/src/rust/api/hashing/sha3.dart';

final digest = await blake3Hash(data: bytes);
final sha3Digest = await sha3Hash(data: bytes);
```

### HKDF Key Derivation

```dart
import 'package:m_security/src/rust/api/kdf/hkdf.dart';

final derived = await hkdfDerive(
  ikm: masterKey,
  salt: null,
  info: Uint8List.fromList('encryption-key'.codeUnits),
  outputLen: 32,
);
```

## Rust API Reference

### Encryption

```
create_aes256_gcm(key)           → CipherHandle
create_chacha20_poly1305(key)    → CipherHandle
encrypt(handle, plaintext, aad)  → Vec<u8>
decrypt(handle, ciphertext, aad) → Vec<u8>
generate_aes256_gcm_key()        → Vec<u8>
generate_chacha20_poly1305_key() → Vec<u8>
```

### Hashing

```
blake3_hash(data)                → Vec<u8>
sha3_hash(data)                  → Vec<u8>
create_blake3()                  → HasherHandle
create_sha3()                    → HasherHandle
hasher_update(handle, data)      → ()
hasher_reset(handle)             → ()
hasher_finalize(handle)          → Vec<u8>
```

### Password Hashing

```
argon2id_hash(password, preset)              → String (PHC)
argon2id_hash_with_salt(password, salt, preset) → String (PHC)
argon2id_verify(phc_hash, password)          → ()
```

Presets: `Mobile` (64 MiB, t=3, p=4) | `Desktop` (256 MiB, t=4, p=8)

### Key Derivation

```
hkdf_derive(ikm, salt?, info, output_len)  → Vec<u8>
hkdf_extract(ikm, salt?)                   → Vec<u8> (PRK)
hkdf_expand(prk, info, output_len)         → Vec<u8>
```

## Security

- All key material zeroized on Drop (`zeroize` crate with `ZeroizeOnDrop` derive)
- No `unwrap()` in FFI-visible code (`clippy::unwrap_used = "deny"`)
- `panic = "abort"` in release profile — no UB from panics crossing FFI
- Nonces generated internally via `OsRng` — callers never handle nonces
- Raw keys never cross the FFI boundary — stays behind opaque Rust handles
- AEAD tag verification prevents silent decryption of tampered data

## Cross-Compilation Targets

| Target | Platform |
|--------|----------|
| `aarch64-linux-android` | Android ARM64 |
| `armv7-linux-androideabi` | Android ARM32 |
| `aarch64-apple-ios` | iOS ARM64 |
| `aarch64-apple-ios-sim` | iOS Simulator |
| `aarch64-apple-darwin` | macOS ARM64 |
| `x86_64-apple-darwin` | macOS Intel |
| `x86_64-unknown-linux-gnu` | Linux |
| `x86_64-pc-windows-msvc` | Windows |

## Tech Stack

- **Rust** (stable) — crypto core
- **Flutter Rust Bridge** 2.11.1 — FFI code generation
- **Flutter SDK** (stable) / **Dart SDK** ^3.10.8

## Prerequisites

```bash
# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# FRB codegen
cargo install flutter_rust_bridge_codegen
```

Platform-specific: Xcode (macOS/iOS), Android NDK (Android), Visual Studio Build Tools + LLVM (Windows), `build-essential` + `libssl-dev` (Linux).

## Quick Start

```bash
flutter pub get
cd rust && cargo build && cd ..
flutter_rust_bridge_codegen generate
flutter run
```

## Testing

**Rust unit tests:**
```bash
cd rust && cargo test
```

**Dart integration tests** (requires a running device/simulator):
```bash
cd example
flutter test integration_test/aes_gcm_test.dart
flutter test integration_test/chacha20_test.dart
flutter test integration_test/hashing_test.dart
flutter test integration_test/argon2_test.dart
```

## License

MIT
