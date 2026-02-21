//! Secure memory wrapper that zeroes on drop.

use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A buffer that securely zeroes its contents when dropped.
///
/// Use this for all key material to ensure secrets don't linger in memory.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBuffer {
    inner: Vec<u8>,
}

impl SecretBuffer {
    /// Create a new SecretBuffer from existing data.
    pub fn new(data: Vec<u8>) -> Self {
        Self { inner: data }
    }

    /// Create a zero-filled SecretBuffer of the given size.
    pub fn from_size(size: usize) -> Self {
        Self {
            inner: vec![0u8; size],
        }
    }

    /// Access the underlying bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Access the underlying bytes mutably.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }

    /// Returns the length of the buffer.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

// SAFETY: Manual Debug impl to avoid printing secret data
impl fmt::Debug for SecretBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretBuffer")
            .field("len", &self.inner.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_creates_buffer_with_correct_data() {
        let data = vec![1, 2, 3, 4, 5];
        let buf = SecretBuffer::new(data.clone());
        assert_eq!(buf.as_bytes(), &data);
        assert_eq!(buf.len(), 5);
    }

    #[test]
    fn test_from_size_creates_zero_filled_buffer() {
        let buf = SecretBuffer::from_size(32);
        assert_eq!(buf.len(), 32);
        assert!(buf.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_is_empty() {
        let empty = SecretBuffer::new(vec![]);
        let non_empty = SecretBuffer::new(vec![1]);
        assert!(empty.is_empty());
        assert!(!non_empty.is_empty());
    }

    #[test]
    fn test_debug_does_not_print_secret_data() {
        let buf = SecretBuffer::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let debug_str = format!("{:?}", buf);
        // Should show length but NOT the actual bytes
        assert!(debug_str.contains("len"));
        assert!(debug_str.contains("4"));
        assert!(!debug_str.contains("222")); // 0xDE = 222
        assert!(!debug_str.contains("DEAD"));
    }

    #[test]
    fn test_zeroize_on_drop() {
        // Create a buffer and get a raw pointer to its data
        let mut buf = SecretBuffer::new(vec![0xAA; 32]);
        let ptr = buf.as_bytes().as_ptr();
        let len = buf.len();

        // Manually zeroize to simulate drop behavior
        buf.zeroize();

        // Verify the memory is zeroed
        // SAFETY: We're reading memory we own, before it's deallocated
        unsafe {
            let slice = std::slice::from_raw_parts(ptr, len);
            assert!(slice.iter().all(|&b| b == 0), "Memory was not zeroed");
        }
    }
}
