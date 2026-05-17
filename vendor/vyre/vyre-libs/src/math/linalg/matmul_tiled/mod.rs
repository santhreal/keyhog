//! Cooperative tiled matrix multiplication.
//!
//! Category-A composition. Computes `out = a @ b` where `a` is `m × k`,
//! `b` is `k × n`, `out` is `m × n`. Each workgroup owns a rectangular
//! output tile and cooperatively stages A/B k-tiles through workgroup
//! memory before accumulating one output element per lane.
//!
//! ROADMAP S10: this module was a single 960-LOC file before splitting.
//! The cuts are:
//!
//! - [`plain`] — `MatmulTiled` builder + `matmul_tiled` Cat-A wrapper
//!   for the no-bias variant.
//! - [`bias`] — `MatmulBiasTiled` builder + `matmul_bias_tiled`
//!   Cat-A wrapper for the bias-fused variant.
//! - [`shape`] — `MatrixShape` / `TileShape` value types and the
//!   geometry helpers (`output_tile_shape`,
//!   `padded_tile_lane_count`, `in_output_bounds`).
//! - [`body`] — the cooperative inner kernel body
//!   (`cooperative_matmul_body`) that both builders share.
//!
//! Public surface preserved verbatim through the re-exports below;
//! external callers that import via `vyre_libs::math::linalg::*` see
//! no change.

mod bias;
mod body;
mod plain;
mod shape;

pub use bias::{matmul_bias_tiled, MatmulBiasTiled};
pub use plain::{matmul_tiled, MatmulTiled};
