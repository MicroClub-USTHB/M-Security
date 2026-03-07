# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.3.0 - 2026-03-07

### Added

- Streaming encryption and decryption with chunk-based AES-256-GCM and ChaCha20-Poly1305, including progress callbacks for large file processing.
- Zstd and Brotli compression with configurable levels, integrated into both the streaming pipeline and the EVFS.
- Encrypted Virtual File System (EVFS): a `.vault` container supporting named segments, WAL crash recovery, shadow index, capacity management, and secure deletion.
- Full-featured Flutter example app demonstrating all library APIs (hashing, encryption, KDF, streaming, compression, vault).

### Fixed

- Integration test reliability improvements for async race conditions and matcher corrections.

## 0.1.1 - 2026-03-06

### Fixed

- Published package was missing `rust/src/frb_generated.rs`, which caused Rust compilation to fail for consumers.

## 0.1.0 - 2026-03-06

Initial release of M-Security, a native Rust cryptographic SDK for Flutter.

### Added

- AES-256-GCM authenticated encryption with 32-byte keys, 12-byte auto-generated nonces, and 16-byte authentication tags.
- ChaCha20-Poly1305 authenticated encryption optimized for mobile processors lacking dedicated AES hardware.
- Unified `CipherHandle` interface for both ciphers (create, encrypt, decrypt, generate key). Output format: `nonce || ciphertext || tag`.
- BLAKE3 hashing with one-shot and streaming APIs via `HasherHandle`.
- SHA-3-256 (Keccak) hashing with one-shot and streaming APIs.
- Argon2id password hashing with Mobile (64 MiB, t=3, p=4) and Desktop (256 MiB, t=4, p=8) presets, automatic salt generation, and PHC string output.
- HKDF-SHA256 key derivation (RFC 5869) with `derive`, `extract`, and `expand` operations. Output range: 1-8160 bytes.
- Secure memory management with `ZeroizeOnDrop` on all key-holding structs.
- Opaque `#[frb(opaque)]` handles ensuring raw keys never cross the FFI boundary.
- Internal nonce generation via `OsRng`; callers never handle nonces.
- CI pipeline with Rust linting/testing, Dart analysis, and platform builds (Android, iOS, Linux).
- Integration tests for all cryptographic operations.
- Platform support: Android (ARM64, ARM32), iOS (ARM64, Simulator), macOS (ARM64, Intel), Linux (x86_64), Windows (x86_64).
