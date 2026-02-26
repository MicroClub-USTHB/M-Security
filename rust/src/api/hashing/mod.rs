//! Hashing API module.

pub mod argon2;
mod blake3;
mod sha3;

use crate::core::error::CryptoError;
use crate::core::traits::Hasher;
use flutter_rust_bridge::frb;
use std::sync::Mutex;

/// Opaque handle wrapping any hasher implementation.
///
/// Uses Mutex for interior mutability since Hasher::update requires &mut self.
#[frb(opaque)]
pub struct HasherHandle {
    inner: Mutex<Box<dyn Hasher>>,
}

impl HasherHandle {
    fn new(hasher: Box<dyn Hasher>) -> Self {
        Self {
            inner: Mutex::new(hasher),
        }
    }

    pub(crate) fn update_raw(&self, data: &[u8]) -> Result<(), CryptoError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| CryptoError::HashingFailed("Hasher lock poisoned".into()))?;
        guard.update(data)
    }

    pub(crate) fn finalize_raw(&self) -> Result<Vec<u8>, CryptoError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| CryptoError::HashingFailed("Hasher lock poisoned".into()))?;
        guard.finalize()
    }

    pub(crate) fn reset_raw(&self) -> Result<(), CryptoError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| CryptoError::HashingFailed("Hasher lock poisoned".into()))?;
        guard.reset()
    }
}

/// Create a BLAKE3 hasher handle.
pub fn create_blake3() -> HasherHandle {
    HasherHandle::new(Box::new(blake3::Blake3Hasher::new()))
}

/// Create a SHA-3 hasher handle.
pub fn create_sha3() -> HasherHandle {
    HasherHandle::new(Box::new(sha3::Sha3Hasher::new()))
}

/// Feed data into the hasher.
pub fn hasher_update(handle: &HasherHandle, data: Vec<u8>) -> Result<(), CryptoError> {
    let mut guard = handle
        .inner
        .lock()
        .map_err(|_| CryptoError::HashingFailed("Hasher lock poisoned".into()))?;
    guard.update(&data)
}

/// Reset the hasher to its initial state.
pub fn hasher_reset(handle: &HasherHandle) -> Result<(), CryptoError> {
    let mut guard = handle
        .inner
        .lock()
        .map_err(|_| CryptoError::HashingFailed("Hasher lock poisoned".into()))?;
    guard.reset()
}

/// Finalize and return the digest.
pub fn hasher_finalize(handle: &HasherHandle) -> Result<Vec<u8>, CryptoError> {
    let guard = handle
        .inner
        .lock()
        .map_err(|_| CryptoError::HashingFailed("Hasher lock poisoned".into()))?;
    guard.finalize()
}

/// Get the algorithm identifier for the hasher.
pub fn hasher_algorithm_id(handle: &HasherHandle) -> Result<String, CryptoError> {
    let guard = handle
        .inner
        .lock()
        .map_err(|_| CryptoError::HashingFailed("Hasher lock poisoned".into()))?;
    Ok(guard.algorithm_id().to_string())
}

/// One-shot BLAKE3 hash function.
///
/// Convenience function for hashing data in a single call.
pub fn blake3_hash(data: Vec<u8>) -> Vec<u8> {
    ::blake3::hash(&data).as_bytes().to_vec()
}

/// One-shot SHA-3 hash function.
///
/// Convenience function for hashing data in a single call.
pub fn sha3_hash(data: Vec<u8>) -> Vec<u8> {
    use ::sha3::{Digest, Sha3_256 as Sha3Digest};
    Sha3Digest::digest(&data).to_vec()
}
