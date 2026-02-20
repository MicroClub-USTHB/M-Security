# M-Security SDK

A native Rust cryptographic SDK for Flutter, providing secure, high-performance primitives for hashing, encryption, and key derivation via Flutter Rust Bridge (FRB).

## Cryptographic Specifications

### 2.1 Modern Hashing

| Algorithm | Purpose | Crate |
|-----------|---------|-------|
| **Argon2id** | Password hashing, GPU/ASIC resistant | `argon2 0.5` |
| **BLAKE3** | Ultra fast integrity verification and checksums | `blake3 1.8` |
| **SHA-3 (Keccak)** | NIST standard for blockchain/state-level compatibility | `sha3 0.10` |

### 2.2 Authenticated Encryption (AEAD)

| Algorithm | Purpose | Crate |
|-----------|---------|-------|
| **AES-256-GCM** | Industry standard with hardware acceleration (AES-NI) | `aes-gcm 0.10` |
| **ChaCha20-Poly1305** | High-performance alternative for mobile (no AES hardware) | `chacha20poly1305 0.10` |

### 2.3 Key Derivation (KDF)

| Algorithm | Purpose | Crate |
|-----------|---------|-------|
| **HKDF** | Convert shared secrets or passwords into high-entropy keys | `hkdf 0.12` |

## Current Status

| Section | Status |
|---------|--------|
| Foundation (traits, error handling, FRB setup) | Done |
| 2.1 Modern Hashing | In progress |
| 2.2 Authenticated Encryption | Planned |
| 2.3 Key Derivation | Planned |

### Implemented (Foundation)

- Flutter plugin scaffold with platform support (Android, iOS, macOS, Linux, Windows)
- Rust crate structure with `cdylib` + `staticlib` outputs
- Flutter Rust Bridge v2.11.1 integration
- Core traits: `Encryption`, `Hasher`, `Kdf` with `Send + Sync + 'static`
- `CryptoError` enum with FFI-safe variants
- `SecretBuffer` with zeroize on Drop
- Opaque handle pattern (`#[frb(opaque)]` on `CipherHandle`)
- Noop encryption reference implementation (FRB validation)
- `clippy::unwrap_used = "deny"` and `panic = "abort"` in release

### Future Milestone

- Streaming encryption/decryption/hashing
- Compression (Zstd)
- Encrypted Virtual File System (.vault)

## Tech Stack

- **Flutter SDK** (stable)
- **Dart SDK** `^3.10.8`
- **Rust** (stable via `rustup`)
- **flutter_rust_bridge** `2.11.1`

## Prerequisites

Install these before building:

**All platforms:**
- Flutter SDK
- Rust toolchain (`rustup`)
- FRB code generator:

```bash
cargo install flutter_rust_bridge_codegen
```

**Platform-specific:**
- **Windows:** Visual Studio C++ Build Tools (MSVC), LLVM
- **macOS:** Xcode, Homebrew (and Android NDK if targeting Android)
- **Linux:** `build-essential`, `libssl-dev`, `pkg-config`, `llvm`

## Quick Start

```bash
flutter pub get
cd rust && cargo build && cd ..
flutter_rust_bridge_codegen generate
```

## Project Structure

```
.
├── lib/                          # Dart code
│   └── src/rust/                 # FRB-generated bindings
├── rust/
│   └── src/
│       ├── api/                  # Public API (FRB scans this)
│       │   ├── encryption/       # AEAD implementations
│       │   └── hashing/          # Hash implementations
│       └── core/                 # Internal (traits, errors, types)
│           ├── error.rs          # CryptoError enum
│           ├── secret.rs         # SecretBuffer with zeroize
│           └── traits.rs         # Encryption, Hasher, Kdf traits
└── pubspec.yaml
```

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

## Security Guidelines

- All key material is zeroized on Drop via `zeroize` crate
- No `unwrap()` in FFI-visible code paths (`clippy::unwrap_used = "deny"`)
- `panic = "abort"` in release profile
- Streaming for large files (constant memory footprint)
- Platform-secure storage for keys (iOS Secure Enclave, Android Keystore) - future

## License

MIT
