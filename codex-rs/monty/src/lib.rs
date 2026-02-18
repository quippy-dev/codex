//! Minimal Monty runtime placeholder.
//!
//! This crate exists to back the dedicated Python tool integration.
//! It is intentionally lightweight until the full implementation lands.

/// Returns the Monty crate version.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
