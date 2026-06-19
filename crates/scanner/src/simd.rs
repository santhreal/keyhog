//! Vectorscan/Hyperscan SIMD regex backend for high-throughput scanning.
//!
//! When the `simd` feature is enabled, this replaces the AC+fallback approach
//! with Hyperscan's simultaneous multi-pattern matching using SIMD instructions.
//! Gives 3-5x throughput improvement. Accuracy is identical - same patterns, faster engine.

#[cfg(feature = "simd")]
pub(crate) mod backend;
