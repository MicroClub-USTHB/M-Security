# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v0.3.3 - 2026-03-27

### Added

- Zero-copy vault reads via `memmap2` memory-mapped I/O — `vault_read` and `vault_read_stream` now slice directly into mapped file pages instead of allocating heap buffers with `read_exact`.
- `VaultMmap` wrapper with `mlock()` on unix to pin ciphertext pages in RAM and prevent swap-to-disk. Graceful fallback to heap reads when mmap fails (32-bit targets, low `mlock` limits).
- mmap invalidation/recreation after every vault mutation (write, delete, defrag, resize).
- ELF linker version script (`ffi-exports.map`) restricting Android/Linux `.so` dynamic symbol table to FRB FFI symbols only — hides `#[no_mangle]` symbols leaked by dependencies.
- `build.rs` for conditional version script application on Android/Linux cdylib builds.

### Changed

- Switched all 50 FRB functions from SSE to CST+DCO codec via `full_dep: true` — `Vec<u8>` returns now use `allo-isolate` `ExternalTypedData` (pointer transfer, no memcpy) instead of SSE serialization.
- Release profile hardened: `lto = "fat"`, `codegen-units = 1`, `strip = "symbols"`, `opt-level = 3`.
- `VaultHandle` field order: `mmap` before `file` so `munlock`/`munmap` runs while the fd is still open.

### Security

- Symbol stripping removes internal Rust function names from release binaries — `nm -D` shows only FRB entry points and libc on ELF targets.
- `mlock()` prevents OS from swapping mmap'd ciphertext pages to disk swap.
- Fewer intermediate `Vec<u8>` copies means shorter plaintext residency in memory.
- ZeroizeOnDrop behavior preserved — no regression from zero-copy refactoring.

## [v0.3.2](https://github.com/MicroClub-USTHB/M-Security/releases/tag/v0.3.2) - 2026-03-26

### Added

- `vault_write_stream()` for constant-memory chunked segment writes — encrypts data in 64 KB chunks without loading the full segment into RAM.
- `vault_read_stream()` for chunked segment reads via `StreamSink` — delivers decrypted data as a stream of byte chunks.
- Per-chunk AEAD encryption with domain-separated nonce derivation (`0x01` prefix, chunk index, generation) — provably disjoint from monolithic nonce space.
- `VaultChunkAad` struct binding generation and chunk position to each chunk's authentication tag (cross-segment splice defense).
- `vault_write_file()` FRB-callable wrapper that reads a file in 64 KB chunks and pipes into `vault_write_stream`.
- Dart `VaultService.writeStream()` — accepts a `Stream<Uint8List>`, buffers to a temp file, and delegates to Rust for bounded-memory encryption.
- Dart `VaultService.readStream()` — returns a `Stream<Uint8List>` of decrypted chunks with optional `onProgress` callback.
- Streaming interop: segments written via streaming can be read one-shot (and vice versa).
- Integration tests for streaming: 10 MB roundtrip, write/read interop, progress reporting, error handling, and 50 MB memory-bounded validation.
- Example app streaming I/O section in the Vault tab — stream-write and stream-read with configurable size and live progress bar.

### Fixed

- Checked arithmetic in `decrypt_streaming_chunks` read path — prevents wrong-region reads from crafted chunk counts.
- I/O errors in `vault_write_file` now surface as `CryptoError::IoError` instead of a misleading "stream underflow" message.
- `total_received` accumulation uses `checked_add` to prevent silent overflow on pathological input.
- Per-chunk `fsync` replaced with a single post-loop durability barrier — reduces streaming write I/O from O(N) fsyncs to O(1).
- WAL checkpoint after streaming write commit — prevents unbounded WAL growth.
- `readStream` cancellation leak — `onCancel` handler now cleans up data and progress subscriptions.
- Overflow error message now reports exact byte count, chunk size, and offset for easier debugging.

## [v0.3.1](https://github.com/MicroClub-USTHB/M-Security/releases/tag/v0.3.1) - 2026-03-16

### Added

- Vault defragmentation: `vault_defragment()` compacts segments toward data region start, coalescing all free space with per-move WAL protection and post-commit secure erase.
- Vault resize: `vault_resize()` grows or shrinks vault capacity, relocating shadow index and WAL region.
- Vault health check: `vault_health()` returns `VaultHealthInfo` with fragmentation %, free region count, largest contiguous block, and consistency invariant.
- Dynamic index sizing: `compute_index_size(capacity)` scales segment index proportionally (64 KB per MB, min 64 KB, max 16 MB cap) — replaces fixed 64 KB `INDEX_PAD_SIZE`.
- Dart `VaultService.defragment()`, `VaultService.resize()`, and `VaultService.health()` wrappers with integration tests.
- Example app vault maintenance UI (defrag, resize, health).

### Fixed

- Nonce reuse prevention after WAL recovery by hardening defrag backup path.
- Resize and defrag crash recovery hardening (fsync ordering, OOM guard, bounds check, health invariant overflow-safe check).
- Segment index size now scales with vault capacity — fixes OOM on large vaults with fixed 64 KB index.
- pub.dev score improvements.

### Security

- No new information leaks, `index_size` remains deterministic from file size.
- Enforced index size bounds (64KB-16MB).
- Added safeguards against excessive memory usage.
- Header tampering results in authentication failure (no data exposure).

## [v0.3.0](https://github.com/MicroClub-USTHB/M-Security/releases/tag/v0.3.0) - 2026-03-07

### Added

- Streaming encryption and decryption with chunk-based AES-256-GCM and ChaCha20-Poly1305, including progress callbacks for large file processing.
- Zstd and Brotli compression with configurable levels, integrated into both the streaming pipeline and the EVFS.
- Encrypted Virtual File System (EVFS): a `.vault` container supporting named segments, WAL crash recovery, shadow index, capacity management, and secure deletion.
- Full-featured Flutter example app demonstrating all library APIs (hashing, encryption, KDF, streaming, compression, vault).

### Fixed

- Integration test reliability improvements for async race conditions and matcher corrections.

## [v0.1.1](https://github.com/MicroClub-USTHB/M-Security/releases/tag/v0.1.1) - 2026-03-06

### Fixed

- Published package was missing `rust/src/frb_generated.rs`, which caused Rust compilation to fail for consumers.

## [v0.1.0](https://github.com/MicroClub-USTHB/M-Security/releases/tag/v0.1.0) - 2026-03-06

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
