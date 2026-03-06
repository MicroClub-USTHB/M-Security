//! EVFS internal types — format, segment crypto, WAL, and file locking.
//!
//! These modules live under `core/` (not `api/`) so that FRB codegen
//! does not scan them. Only the public vault API in `api/evfs/` is
//! exposed to Flutter.

pub mod format;
pub mod segment;
pub mod wal;
