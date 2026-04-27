//! Host-side IR engine helpers that do not depend on a GPU runtime.
//!
//! These helpers build deterministic host-side input structures used around
//! IR programs. wgpu-owned engines live in the `vyre-wgpu` crate.

/// Prefix-array builders used before scan-style IR dispatch.
pub mod prefix;

#[cfg(test)]
mod tests;
