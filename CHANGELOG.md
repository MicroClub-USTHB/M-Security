## 0.1.1

- Fixed published package missing `rust/src/frb_generated.rs`, which caused Rust compilation to fail for consumers.

## 0.1.0

Initial release of M-Security, a native Rust cryptographic SDK for Flutter.

### Authenticated Encryption (AEAD)

- **AES-256-GCM.** Industry-standard authenticated encryption with 32-byte keys, 12-byte auto-generated nonces, and 16-byte authentication tags.
- **ChaCha20-Poly1305.** High-performance alternative optimized for mobile processors lacking dedicated AES hardware.
- Unified `CipherHandle` interface for both ciphers (create, encrypt, decrypt, generate key).
- Output format: `nonce || ciphertext || tag`.

### Hashing

- **BLAKE3.** Ultra-fast integrity verification with one-shot and streaming APIs via `HasherHandle`.
- **SHA-3-256 (Keccak).** NIST-standard hashing with one-shot and streaming APIs.
- **Argon2id.** PHC-winning password hashing with Mobile (64 MiB) and Desktop (256 MiB) presets, automatic salt generation, and PHC string output.

### Key Derivation (KDF)

- **HKDF-SHA256.** RFC 5869-compliant key derivation with `derive`, `extract`, and `expand` operations. Output range: 1-8160 bytes.

### Security

- All key material held in Rust behind opaque `#[frb(opaque)]` handles; raw keys never cross the FFI boundary.
- Secure memory management with `ZeroizeOnDrop` on all key-holding structs.
- `clippy::unwrap_used = "deny"`, preventing unwrap in FFI-visible code.
- `panic = "abort"` in release profile, preventing undefined behavior from panics crossing FFI.
- Nonces generated internally via `OsRng`; callers never handle nonces.

### Platform Support

- Android (ARM64, ARM32)
- iOS (ARM64, Simulator)
- macOS (ARM64, Intel)
- Linux (x86_64)
- Windows (x86_64)

### Infrastructure

- CI pipeline with Rust linting/testing, Dart analysis, and platform builds (Android, iOS, Linux).
- Integration tests for all cryptographic operations.
- Flutter Rust Bridge 2.11.1 for FFI code generation.
