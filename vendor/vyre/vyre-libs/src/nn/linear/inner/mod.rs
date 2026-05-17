//! Linear layer: `y = x @ W + b`.
//!
//! Audit-fix A30 split this module by concern: `linear` builder + struct in
//! `mod.rs`/`builder.rs`, the tiled variants in `tiled.rs`, the fused
//! `linear_relu` in `relu.rs`, `rms_norm_linear` in `rms_norm.rs`, and tests
//! in `tests.rs`.

mod builder;
mod relu;
mod rms_norm;
mod silu;
mod tiled;

pub use builder::{linear, Linear};
pub use relu::linear_relu;
pub use rms_norm::{rms_norm_linear, try_rms_norm_linear};
pub use silu::linear_silu;
pub use tiled::{linear_tiled, linear_tiled_reference};

#[cfg(test)]
mod tests;
