//! Test-only cipher fake plus the guards keeping it out of the generated surface.

use super::CipherHandle;
use crate::core::error::CryptoError;
use crate::core::traits::Encryption;

struct IdentityEncryption;

impl Encryption for IdentityEncryption {
    fn encrypt(&self, plaintext: &[u8], _aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(plaintext.to_vec())
    }

    fn decrypt(&self, ciphertext: &[u8], _aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(ciphertext.to_vec())
    }

    fn algorithm_id(&self) -> &'static str {
        "test-only-identity"
    }
}

const GENERATED_ENCRYPTION_DART: &str =
    include_str!("../../../../lib/src/rust/api/encryption.dart");

// Every bridge entry reaches `frb_generated.dart` whichever per-module file exposes
// it, so these five cover the generated surface without listing every module file.
const GENERATED_SOURCES: [(&str, &str); 5] = [
    (
        "rust/src/frb_generated.rs",
        include_str!("../../frb_generated.rs"),
    ),
    (
        "lib/src/rust/api/encryption.dart",
        GENERATED_ENCRYPTION_DART,
    ),
    (
        "lib/src/rust/frb_generated.dart",
        include_str!("../../../../lib/src/rust/frb_generated.dart"),
    ),
    (
        "lib/src/rust/frb_generated.io.dart",
        include_str!("../../../../lib/src/rust/frb_generated.io.dart"),
    ),
    (
        "lib/src/rust/frb_generated.web.dart",
        include_str!("../../../../lib/src/rust/frb_generated.web.dart"),
    ),
];

// Lowercased spellings the removed constructor took across Rust, Dart and the C ABI:
// create_noop_encryption, createNoopEncryption, NoopEncryption. Matching these rather
// than bare "noop" keeps unrelated names such as the streaming noop_progress helper
// and the bridge's own NoOpErrorListener from tripping the guard.
const REMOVED_CIPHER_NEEDLES: [&str; 2] = ["noop_encryption", "noopencryption"];

const SUPPORTED_CIPHER_CONSTRUCTORS: [&str; 2] = ["createAes256Gcm", "createChacha20Poly1305"];

#[test]
fn cipher_handle_delegates_to_its_boxed_implementation() {
    let handle = CipherHandle::new(Box::new(IdentityEncryption));

    for plaintext in [b"opaque handle payload".as_slice(), b"".as_slice()] {
        for aad in [b"aad".as_slice(), b"".as_slice()] {
            let ciphertext = handle.encrypt_raw(plaintext, aad).expect("encrypt failed");
            let recovered = handle
                .decrypt_raw(&ciphertext, aad)
                .expect("decrypt failed");
            assert_eq!(recovered, plaintext);
        }
    }

    assert_eq!(handle.algorithm_id(), "test-only-identity");
}

#[test]
fn generated_bindings_expose_no_no_op_cipher() {
    for (name, source) in GENERATED_SOURCES {
        assert!(
            source.contains("create_aes256_gcm") || source.contains("CreateAes256Gcm"),
            "{name} no longer looks like a generated bridge file, so this scan proves nothing"
        );

        let lowercased = source.to_lowercase();
        for needle in REMOVED_CIPHER_NEEDLES {
            assert!(
                !lowercased.contains(needle),
                "{name} still exposes the removed no-op cipher (matched {needle})"
            );
        }
    }
}

#[test]
fn public_surface_exposes_only_the_supported_cipher_constructors() {
    let mut found: Vec<&str> = GENERATED_ENCRYPTION_DART
        .lines()
        .filter_map(|line| line.strip_prefix("Future<CipherHandle> "))
        .filter_map(|rest| rest.split('(').next())
        .collect();
    found.sort_unstable();

    assert_eq!(
        found, SUPPORTED_CIPHER_CONSTRUCTORS,
        "the public cipher constructors changed; review any addition for an implementation that panics or aborts"
    );
}
