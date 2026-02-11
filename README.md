# M-Security SDK

`m_security` is a security sdk build with rust and dart to help flutter developers secure their code.

The goal is to provide secure, high-performance primitives for hashing, encryption, and protected storage.

## Current Status

This repository is in early development.

Implemented now:
- Flutter plugin scaffold
- Rust bridge wiring (`flutter_rust_bridge`)
- Sample Rust APIs in `rust/src/api/simple.rs`

Planned modules:
- Hashing (`Argon2id`, `BLAKE3`, `SHA-3`)
- Encryption (`AES-GCM`, `ChaCha20-Poly1305`)
- KDF (`HKDF`, `PBKDF2`)
- Encrypted virtual file system and secure shredding

## Tech Stack

- Flutter SDK (stable)
- Dart SDK `^3.10.8`
- Rust (stable via `rustup`)
- `flutter_rust_bridge` `2.11.1`

## Prerequisites

Install these before building.

All platforms:
- Flutter SDK
- Rust toolchain (`rustup`)
- FRB code generator:

```bash
cargo install flutter_rust_bridge_codegen
```

Platform-specific:
- Windows: Visual Studio C++ Build Tools (MSVC), LLVM
- macOS: Xcode, Homebrew (and Android NDK if targeting Android)
- Linux: `build-essential`, `libssl-dev`, `pkg-config`, `llvm`

## Quick Start

From the project root:

```bash
flutter pub get
cd rust
cargo build
cd ..
```

## Generate Rust<->Dart Bindings

Regenerate bindings whenever you change Rust API signatures exposed through FRB.

```bash
flutter_rust_bridge_codegen generate
```

## Project Structure

```text
.
|-- lib/
|-- rust/
|   |-- src/
|   |   |-- api/
|   |   |   |-- mod.rs
|   |   |   `-- simple.rs
|   `-- Cargo.toml
`-- pubspec.yaml
```

## Adding New Rust API Modules

Rust modules must be declared in their parent `mod.rs`.

Example:
1. Create `rust/src/api/hashing.rs`
2. Register it in `rust/src/api/mod.rs`:

```rust
pub mod simple;
pub mod hashing;
```

If you create a subfolder (for example `rust/src/api/storage/`), add its own `mod.rs` and declare child modules there.

## Security Guidelines

- Prefer streaming for large file operations; avoid loading full files into RAM.
- Keep key material in platform-secure storage where possible (iOS Secure Enclave, Android Keystore).
- Zero sensitive data in memory using `zeroize`.

## Development Notes

Current sample API (`rust/src/api/simple.rs`) includes:
- `greet(name)`
- `init_app()`
- `hash_password(password)` (mock function i used to test the bridge)


