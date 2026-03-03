//! Internal compression implementations (not exposed to FRB).

#[cfg(feature = "compression")]
pub mod brotli_impl;
#[cfg(feature = "compression")]
pub mod streaming;
#[cfg(feature = "compression")]
pub mod zstd_impl;
