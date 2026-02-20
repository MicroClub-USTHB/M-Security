//! M-Security
//!
//! This crate provides cryptographic primitives exposed to Flutter via FRB.

#![deny(clippy::unwrap_used)]

pub mod api;

#[allow(dead_code)] // TODO: wire up to api/
mod core;

#[allow(clippy::unwrap_used)] // Generated code
mod frb_generated;
