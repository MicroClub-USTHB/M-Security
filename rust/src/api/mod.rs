//! # M-security rust API

use crate::api::encryption::Encyprtion;

// The flutter-side of things should not care about the actual types and structs of the
// implementation.
//
// Everything is prettified and passed down as opaque pointers and wrapped in methods. This is a
// commonly done thing in FFI-based libraries (see for example wgpu, which makes extensive use of
// `Box<dyn T>` and `Arc<dyn T>` to achieve what they want)
//
// Needed types will be re-exported here.
mod encryption;
mod hashing;

/// A boxed encryption implementation.
#[allow(type_alias_bounds)] // SEE: rust-lang/rust#112792
pub type BoxedEncryption<T: Encyprtion> = Box<dyn Encyprtion<Params = T::Params> + Send + 'static>;

// FIXME: Implement the flutter-side API for this.
