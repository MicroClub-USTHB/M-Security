# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — v0.3.5

### Added

- Per-segment metadata: `vault_write()` and `vault_write_stream()` accept optional `HashMap<String, String>` metadata, encrypted within the index block. `vault_read()` returns `SegmentReadResult { data, metadata }`.
- Segment rename: `vault_rename_segment(old_name, new_name)` updates the index without re-encryption. WAL-protected for crash safety. `DuplicateSegment` error variant added.
- Index caching: in-memory dirty flag tracks index mutations. Read-only operations skip redundant index encryption/flush. New `vault_flush()` API for explicit durability control.
- Parallel reads: `vault_read_parallel(handle, names)` decrypts multiple segments concurrently via `rayon` + mmap zero-copy. Returns per-segment `SegmentResult { name, data, error }`.
- Dart `VaultService` wrappers: `renameSegment()`, `flush()`, `readParallel()`. Updated `write()`/`writeStream()` to accept optional `metadata` parameter. Updated `read()` to return `SegmentReadResult`.
- 15 Dart integration tests covering metadata (4), rename (4), flush (2), parallel read (3), and combined workflows (2).
- Rust test suite refactored from monolithic `tests.rs` into 13 focused modules. 407 total Rust tests.
- Example app: metadata input field, rename dialog, flush button, parallel read all button.

### Changed

- `VAULT_VERSION` bumped 1 → 2 for backward-compatible metadata deserialization (v1 vaults return empty metadata).
- `ARCHIVE_VERSION` bumped 1 → 2 for metadata preservation in export/import (v1 archives import with empty metadata).
- `vault_write_file` now passes metadata through to `vault_write_stream` (was hardcoded to `None`).
- `vault_close()` flushes dirty index before releasing lock, with best-effort WAL checkpoint on error.

### Security

- Metadata encrypted within the index block (AEAD with index key), not in the segment cipher — no plaintext leakage.
- OOM guards: `MAX_METADATA_PAIRS` (1024) and `MAX_METADATA_BYTES` (64 KB) enforced on both read and write paths.
- Parallel reads use immutable `&VaultHandle` — no shared mutable state between threads. Compile-time `Sync` assertion.
- Checked offset arithmetic in parallel mmap slicing (`checked_add` instead of bare `+`).
- Plaintext zeroized on all checksum failure paths in parallel reads.

### Fixed

- Async error assertions in Dart rename tests changed from `expect()` to `await expectLater()`.
- Example app `evfs_test.dart` updated for `SegmentReadResult` return type.
## [v0.3.4](https://github.com/MicroClub-USTHB/M-Security/releases/tag/v0.3.4) - 2026-04-05

### Added

- Master key rotation via `vault_rotate_key()` — re-encrypts all vault data under a new key using atomic copy-to-new-vault + rename strategy. Crash recovery: stale `.rotating` file cleaned on `vault_open()`.
- Vault export via `vault_export()` — produces a self-contained `.mvex` encrypted archive with BLAKE3 integrity trailer, ephemeral export key AEAD-wrapped with caller's wrapping key, and per-segment re-encryption.
- Vault import via `vault_import()` — reads `.mvex` archive, creates new vault re-encrypted under a local master key. Validates header, unwraps export key, verifies per-segment BLAKE3 checksums and trailer integrity.
- `ImportFailed`, `ExportFailed`, and `KeyRotationFailed` error variants in `CryptoError`.
- Dart `VaultService.rotateKey()`, `VaultService.export()`, and `VaultService.importVault()` static methods.
- 7 Dart integration tests for key management (rotation roundtrip, old key rejection, export-import roundtrip, wrong wrapping key, 1MB+ segment, multiple rotations, rotate-then-export-import).
- 26 Rust tests for key management (10 rotation + 7 export + 9 import).
- Example app Key Management section with Rotate Key, Export, and Import buttons.
- CI workflow pinned `flutter_rust_bridge_codegen` to v2.11.1 to match runtime dependency.

### Security

- Old sub-keys zeroized immediately after rotation via `ZeroizeOnDrop`.
- Export wrapping uses AAD `b"msec-export-key-wrap"` for domain separation.
- Archive format authenticated: per-segment AAD (segment name) + BLAKE3 trailer covering all preceding bytes.
- `vault_write` plaintext wrapped in `Zeroizing<Vec<u8>>` — guarantees zeroization on all exit paths including `encrypt_segment` failure.
- Import hardened: `u64` to `usize` safe cast via `try_from` (32-bit overflow protection), OOM guard in `u64` arithmetic with `saturating_add`, `.lock` file cleanup in error paths, segment name validation (1-255 bytes), `segment_count` sanity bound (100K), unknown compression byte rejection.
- Atomic rename before lock release in rotation (closes race window).

### Fixed

- `unwrap()` in `archive.rs` replaced with `map_err()` for clippy compliance.
- `from_bytes` errors remapped to `ImportFailed` at import call sites.
- Example app lint: replaced `src/` imports with public `m_security.dart` re-exports.

## [v0.3.3](https://github.com/MicroClub-USTHB/M-Security/releases/tag/v0.3.3) - 2026-03-28

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
