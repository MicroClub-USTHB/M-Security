//! # No-op encryption.
//!
//! This serves as an example on how to implement an encryption algorithm, and how to link it up
//! with the dart side through FRB.

pub struct NoopEncryption {}

impl super::Encyprtion for NoopEncryption {
    type Params = ();
}
