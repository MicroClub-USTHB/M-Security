# Contributing to M-Security

Thank you for your interest in contributing to M-Security! This project is built and maintained by the **Dev Department** of [MicroClub](https://github.com/MicroClub-USTHB) at USTHB. This guide covers everything you need to get started.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Making Changes](#making-changes)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Security](#security)

## Project Vision

M-Security aims to be a complete security toolkit for Flutter. The current release (v0.3.1) includes the cryptographic foundation, streaming encryption, compression, EVFS v2 (defragmentation, resize, health check), and an encrypted virtual file system. Future releases will continue building on top of it:

1. **Cryptographic primitives** (v0.1.0): AEAD encryption, hashing, password hashing, key derivation
2. **Streaming, compression, and EVFS** (v0.3.0): Chunk-based streaming encryption with progress callbacks, Zstd/Brotli compression pipeline, `.vault` container with named segments, WAL crash recovery, shadow index, and secure deletion
3. **EVFS v2: Defrag, resize, health** (v0.3.1, current): Vault defragmentation with per-move WAL crash safety, vault resize (grow/shrink) with shadow index + WAL relocation, vault health check with consistency invariant, dynamic index sizing
3. **Stealth storage** (planned): Ephemeral secrets in Rust-managed memory with derived-path obfuscation
4. **Hardware integration** (planned): Key wrap with Secure Enclave (iOS) / KeyStore (Android), biometric unlock flow (FaceID/Fingerprint), native Swift/Kotlin bridge layer

Contributions to any of these areas are welcome. If you want to work on an upcoming feature, open an issue first to discuss the approach.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. Be kind, constructive, and professional in all interactions.

## Getting Started

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:
   ```bash
   git clone git@github.com:<your-username>/M-Security.git
   cd M-Security
   ```
3. **Add upstream** remote:
   ```bash
   git remote add upstream git@github.com:MicroClub-USTHB/M-Security.git
   ```

## Development Setup

### Prerequisites

| Tool | Required For |
|------|-------------|
| [Rust](https://rustup.rs/) (stable) | Crypto core compilation |
| [Flutter SDK](https://docs.flutter.dev/get-started/install) (stable) | Dart SDK ^3.10.8 |
| [flutter_rust_bridge_codegen](https://cjycode.com/flutter_rust_bridge/) | FFI binding generation |

Install Rust and FRB codegen:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo install flutter_rust_bridge_codegen
```

**Platform-specific tools:**

| Platform | Requirements |
|----------|-------------|
| macOS / iOS | Xcode with command line tools (`xcode-select --install`) |
| Android | Android NDK (r27c recommended, installed via Android Studio) |
| Linux | `sudo apt install clang cmake ninja-build pkg-config libgtk-3-dev` |
| Windows | Visual Studio Build Tools + LLVM |

### Building the Project

```bash
# 1. Install Flutter dependencies
flutter pub get

# 2. Build the Rust library (verifies Rust code compiles)
cd rust && cargo build && cd ..

# 3. Generate FFI bindings (Dart to Rust)
flutter_rust_bridge_codegen generate

# 4. Generate Freezed data classes
dart run build_runner build --delete-conflicting-outputs

# 5. Run the example app (requires a device/simulator)
cd example && flutter run
```

## Project Structure

```
M-Security/
├── lib/                           # Dart public API
│   ├── m_security.dart            # Barrel export (public surface)
│   └── src/
│       ├── encryption/
│       │   ├── aes_gcm.dart       # AesGcmService wrapper
│       │   └── chacha20.dart      # Chacha20Service wrapper
│       ├── hashing/
│       │   └── argon2.dart        # argon2IdHash/Verify with preset defaults
│       ├── kdf/
│       │   └── hkdf.dart          # MHKDF wrapper class
│       └── rust/                  # Auto-generated FRB bindings (DO NOT EDIT)
│           ├── frb_generated.dart # RustLib.init() entry point
│           ├── api/               # Generated Dart FFI functions
│           └── core/              # Generated Dart types
├── rust/                          # Rust crypto core
│   ├── Cargo.toml                 # Crate config, dependencies, lints
│   └── src/
│       ├── lib.rs                 # Crate root
│       ├── frb_generated.rs       # FRB-generated Rust glue
│       ├── api/                   # Public API (scanned by FRB)
│       │   ├── mod.rs
│       │   ├── error.rs           # CryptoError enum (thiserror)
│       │   ├── encryption/
│       │   │   ├── mod.rs         # CipherHandle, encrypt/decrypt, key gen
│       │   │   ├── aes_gcm.rs     # AES-256-GCM implementation
│       │   │   ├── chacha20.rs    # ChaCha20-Poly1305 implementation
│       │   │   └── noop.rs        # Testing-only cipher (behind `testing` feature)
│       │   ├── hashing/
│       │   │   ├── mod.rs         # HasherHandle, blake3_hash, sha3_hash
│       │   │   ├── argon2.rs      # Argon2id with presets
│       │   │   ├── blake3.rs      # BLAKE3 implementation
│       │   │   └── sha3.rs        # SHA-3-256 implementation
│       │   └── kdf/
│       │       ├── mod.rs
│       │       └── hkdf.rs        # HKDF-SHA256 (derive, extract, expand)
│       └── core/                  # Internal utilities (not exposed to Dart)
│           ├── mod.rs
│           ├── error.rs           # CryptoError definition
│           ├── traits.rs          # Encryption, Hasher, Kdf traits
│           ├── secret.rs          # SecretBuffer with ZeroizeOnDrop
│           ├── rng.rs             # CSPRNG (OsRng) key/nonce generation
│           └── format.rs          # MSEC format header for encrypted data
├── cargokit/                      # Build system: compiles Rust during Flutter build
├── android/                       # Android plugin (ffiPlugin + cargokit)
├── ios/                           # iOS plugin (CocoaPods + cargokit)
├── macos/                         # macOS plugin (CocoaPods + cargokit)
├── linux/                         # Linux plugin (CMake + cargokit)
├── windows/                       # Windows plugin (CMake + cargokit)
├── example/                       # Flutter example app
├── integration_test/              # Dart integration tests
│   ├── aes_gcm_test.dart          # AES-256-GCM (6 tests)
│   ├── chacha20_test.dart         # ChaCha20-Poly1305 (7 tests)
│   ├── hashing_test.dart          # BLAKE3 + SHA-3 (11 tests)
│   ├── argon2_test.dart           # Argon2id (6 tests)
│   └── hkdf_test.dart            # HKDF-SHA256 with RFC 5869 vectors (14 tests)
├── .github/workflows/ci.yml      # CI: lint, test, build (Android, iOS, Linux)
├── flutter_rust_bridge.yaml       # FRB codegen config
├── CONTRIBUTING.md
├── RELEASE_GUIDE.md
├── CHANGELOG.md
├── LICENSE                        # MIT
└── README.md
```

### Key Concepts

- **`rust/src/api/`** contains everything scanned by Flutter Rust Bridge and exposed to Dart. New cryptographic primitives go here.
- **`rust/src/core/`** holds internal Rust utilities not exposed to Dart. It houses the `Encryption`, `Hasher`, and `Kdf` traits that all implementations must satisfy, plus `SecretBuffer` for secure memory.
- **`lib/src/rust/`** is auto-generated by FRB. **Never edit these files manually.** They are regenerated with `flutter_rust_bridge_codegen generate`.
- **`lib/src/encryption/`, `hashing/`, `kdf/`** are hand-written Dart wrapper services that provide a clean, idiomatic API on top of the generated FFI bindings.
- **`lib/m_security.dart`** is the barrel export. Only types and functions exported here are part of the public API.
- **`cargokit/`** is the build system that compiles Rust code automatically during `flutter build`. It integrates with Gradle (Android), CocoaPods (iOS/macOS), and CMake (Linux/Windows).

## Making Changes

### Branch Naming

Create a feature branch from `dev` (not `main`):

```bash
git checkout dev
git pull upstream dev
git checkout -b <type>/<short-description>
```

Branch types:

| Prefix | Use |
|--------|-----|
| `feat/` | New feature or algorithm |
| `fix/` | Bug fix |
| `refactor/` | Code restructuring |
| `docs/` | Documentation changes |
| `ci/` | CI/CD pipeline changes |
| `test/` | Test additions or fixes |

### Adding a New Cryptographic Primitive

1. **Implement in Rust.** Add your module under `rust/src/api/<category>/`.
2. **Implement the appropriate trait** from `rust/src/core/traits.rs`:
   - `Encryption` for ciphers (requires `encrypt`, `decrypt`, `algorithm_id`)
   - `Hasher` for hash functions (requires `update`, `reset`, `finalize`, `algorithm_id`)
   - `Kdf` for key derivation (requires `derive`, `algorithm_id`)
3. **Use `SecretBuffer`** for all key material (ensures automatic zeroization on drop).
4. **Use `OsRng`** via `core::rng` for all randomness. Never use `thread_rng`.
5. **Return `Result<T, CryptoError>`**. Never use `unwrap()` (Clippy will reject it).
6. **Write Rust unit tests** in the same file using `#[cfg(test)]`.
7. **Export the module** from the parent `mod.rs`.
8. **Regenerate FFI bindings**:
   ```bash
   flutter_rust_bridge_codegen generate
   ```
9. **Create a Dart wrapper** in `lib/src/<category>/` following existing patterns.
10. **Export it** from `lib/m_security.dart`.
11. **Write integration tests** in `integration_test/`.

### Adding an Opaque Handle

If your primitive holds state (like a cipher key or hasher state):

```rust
use flutter_rust_bridge::frb;

#[frb(opaque)]
pub struct MyHandle {
    inner: Box<dyn MyTrait + Send + Sync>,
}
```

This ensures the handle is never serialized across FFI. Dart holds a pointer only.

## Coding Standards

### Rust

- **No `unwrap()` in FFI-visible code.** Enforced by `[lints.clippy] unwrap_used = "deny"` in `Cargo.toml`. Use `Result<T, CryptoError>` for all fallible operations. `unwrap()` is allowed in `#[cfg(test)]` modules only.
- **Derive `ZeroizeOnDrop`** on all structs holding key material.
- **Use `thiserror`** for error types. All errors map to `CryptoError` variants.
- **`panic = "abort"` in release.** Panics must not cross FFI. This is enforced in `Cargo.toml`'s `[profile.release]`.
- **Run Clippy** before committing:
  ```bash
  cd rust && cargo clippy --all-targets -- -D warnings
  ```
- **Format code**:
  ```bash
  cd rust && cargo fmt
  ```

### Dart

- Follow the [Flutter style guide](https://docs.flutter.dev/style-guide).
- Run the analyzer:
  ```bash
  dart analyze lib/ integration_test/
  ```
- Format code:
  ```bash
  dart format lib/ integration_test/
  ```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(encryption): add XChaCha20-Poly1305 cipher
fix(argon2): correct memory allocation on mobile preset
docs: update README with new algorithm table
test(hkdf): add RFC 5869 test case 3
ci: add Windows build job
```

Keep commits atomic, with one logical change per commit.

## Testing

### Rust Unit Tests

```bash
cd rust && cargo test
```

There are 79 unit tests covering all algorithms, including NIST and RFC test vectors (RFC 8439 for ChaCha20, RFC 5869 for HKDF).

### Dart Integration Tests

Integration tests require a running device or simulator. From the **project root**:

```bash
cd example
flutter test integration_test/aes_gcm_test.dart
flutter test integration_test/chacha20_test.dart
flutter test integration_test/hashing_test.dart
flutter test integration_test/argon2_test.dart
flutter test integration_test/hkdf_test.dart
```

There are 44 integration tests across 5 files covering all features.

### CI Pipeline

All pull requests must pass the CI pipeline (`.github/workflows/ci.yml`), which runs:

| Job | Runner | What it does |
|-----|--------|-------------|
| **Rust** | `ubuntu-latest` | `cargo clippy -- -D warnings` + `cargo test` |
| **Dart** | `ubuntu-latest` | FRB codegen + `build_runner` + `dart analyze` |
| **Android** | `ubuntu-latest` | Full APK build (ARM64 + ARMv7, NDK r27c) |
| **iOS** | `macos-latest` | Simulator debug build (ARM64 + ARM64-sim) |
| **Linux** | `ubuntu-latest` | Release build with GTK-3 |

The CI is triggered on pushes and PRs to `main` and `dev` branches.

## Submitting a Pull Request

1. **Ensure all tests pass** locally:
   ```bash
   cd rust && cargo clippy --all-targets -- -D warnings && cargo test && cd ..
   dart analyze lib/ integration_test/
   ```
2. **Push** your branch to your fork:
   ```bash
   git push origin <your-branch>
   ```
3. **Open a PR** against the `dev` branch on the upstream repository.
4. **Fill in the PR description** with:
   - A clear description of the change
   - Related issue numbers (if any)
   - Testing steps
5. **Wait for CI** to pass and for a maintainer review.
6. **Address review feedback** with additional commits (do not force-push during review).

### PR Checklist

- [ ] Rust code compiles without warnings (`cargo clippy --all-targets -- -D warnings`)
- [ ] Dart code analyzes clean (`dart analyze lib/ integration_test/`)
- [ ] All existing Rust tests pass (`cargo test`)
- [ ] All existing integration tests pass
- [ ] New tests added for new functionality
- [ ] FRB bindings regenerated if Rust API changed (`flutter_rust_bridge_codegen generate`)
- [ ] Public API exported from `lib/m_security.dart` if adding new user-facing types
- [ ] Documentation updated if public API changed
- [ ] `CHANGELOG.md` updated under an `## Unreleased` section
- [ ] Commit messages follow Conventional Commits

## Security

If you discover a security vulnerability, **do not open a public issue**. Instead, report it privately using [GitHub Security Advisories](https://github.com/MicroClub-USTHB/M-Security/security/advisories/new).

### Cryptographic Code Guidelines

Cryptographic code requires extra scrutiny. All contributions touching crypto must follow these rules:

- **Never introduce `unsafe` blocks** without justification and review.
- **All key material must use `SecretBuffer`** (`rust/src/core/secret.rs`) which derives `ZeroizeOnDrop`.
- **Never expose raw key bytes** across the FFI boundary. Use `#[frb(opaque)]` handles.
- **Use `OsRng`** (via `core::rng`) for all random number generation. Never use `thread_rng` or similar.
- **All errors must be explicit.** Return `Result<T, CryptoError>`, never `unwrap()`.
- **Include test vectors** from official standards (NIST, RFC) when implementing new algorithms.
