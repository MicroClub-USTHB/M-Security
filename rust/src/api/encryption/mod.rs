use std::error::Error;

pub mod noop;

/// Shared trait for all encryption algorithms available.
pub trait Encyprtion {
    /// The needed parameters.
    ///
    /// You should store this type inside your encryption algorithm
    type Params: Send + 'static;

    // FIXME: Implement methods.
}
