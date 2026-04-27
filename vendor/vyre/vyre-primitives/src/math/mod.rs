//! Tier 2.5 mathematical primitives.
//!
//! Each module exposes one reusable GPU composition with a stable op id.
//! Callers import the narrow module they need so region-chain audits can see
//! which primitive owns the shared work.

/// 1D separable convolution (domain-neutral: blur, signal processing, audio).
pub mod conv1d;
/// Shared dot-product partial accumulator.
pub mod dot_partial;
/// Value-set analysis interval arithmetic.
pub mod interval;
/// Subgroup prefix-sum scan used by compaction, histograms, and reductions.
pub mod prefix_scan;
/// Prefix-scan backed stream compaction over live-lane flags.
pub mod stream_compact;
/// SCC-local matrix fixpoint primitive for recursive graph components.
pub mod tensor_scc;
