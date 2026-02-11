M-Security : Rust Security SDK for Flutter

1. Project Objective
Development of an open source Flutter package utilizing a native Rust architecture via FFI to provide high performance cryptographic services, secure memory management, and an encrypted virtual file system.

2. Cryptographic Technical Specifications
2.1 Modern Hashing
Argon2id: Implementation of the PHC winner for password hashing; resistant to GPU/ASIC cracking attempts.
BLAKE3: Utilized for ultra fast integrity verification and large file checksums.
SHA-3 (Keccak): Support for the NIST standard to ensure compatibility with modern state level and blockchain protocols.
2.2 Authenticated Encryption (AEAD)
AES-256-GCM: The industry standard for devices with hardware acceleration (AES-NI).
ChaCha20-Poly1305: A high-performance alternative optimized for mobile processors lacking dedicated AES hardware.
2.3 Key Derivation (KDF)
HKDF (HMAC based Extract and Expand): To convert shared secrets or passwords into high entropy encryption keys.

3. Memory and Performance Management
3.1 Zero-Copy Buffer (Stream Processing)
Mechanism: Utilizing Rust pointers to process data without duplicating it within the Dart heap.
Streaming: Partitioning large files (e.g 2GB+) into 64KB chunks.
Goal: Maintain a constant RAM footprint regardless of the total data volume processed
Zero-copy means the Rust code looks at the data exactly where it sits in memory or "streams" it in small chunks (e.g., 64KB at a time).
The Flow: Dart opens a Stream of the file $\rightarrow$ Rust receives a pointer to a small buffer, Rust encrypts it "in-place", The encrypted chunk is written to disk immediately.
The Result: You can encrypt a 10GB file while the app only uses 20MB of RAM.
3.2 Stealth Storage (Protected Memory)
Storage of ephemeral secrets (API tokens) directly within the Rust managed memory space.
Use of derived paths via Scrypt or Argon2 to obfuscate data locations in RAM, making memory dump extraction significantly more difficult.

4. Secure Storage Architecture
4.1 Encrypted Virtual File System (EVFS)
Structure: Creation of a single .vault container file.
Random Access: Rust capability to decrypt only a specific segment (e.g., one specific image) without reading the entire archive.
Isolation: Protection against direct file system exploration by third party apps or rooted users.
4.2 Compression + Encryption Pipeline
Order of Operations: Raw Data -> Compression (Zstd/Brotli) -> Encryption (AES-GCM/ChaCha20).
Advantages: Reduces disk space and increases data entropy before encryption to counter pattern analysis.
4.3 Secure Shredding (File Erasure)
Algorithm: Physical erasure of data by multiple overwrites (random noise patterns) on occupied sectors before deleting the system pointer.
Finality: Renders forensic data recovery impossible.

5. Hardware Integration and Biometrics
5.1 Key Wrap Strategy
Master Key: A high-entropy random master key generated within the Rust environment.
OS Vault: Storage of the "Wrap Key" (used to encrypt the Master Key) inside the Secure Enclave (iOS) or KeyStore (Android).
Authentication Flow:
Trigger local biometric authentication (FaceID/Fingerprint).
Release the Wrap Key to the native layer.
Decrypt the Master Key exclusively within Rust's protected memory.

Component
Technology
Role
API Interface
Dart / Flutter
Clean, asynchronous methods for the end developer.
Bridge
Flutter Rust Bridge (FRB)
Automatic FFI binding generation and type safety.
Core Logic
Rust
Cryptographic math, stream handling, and memory zeroing.
Native Wrappers
Swift / Kotlin
Direct communication with iOS Secure Enclave and Android KeyStore.


