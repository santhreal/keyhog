//! Registered reference optimizer passes.

/// Dynamic workgroup-size autotuning.
pub mod autotune;
/// Compile-time constant-buffer load folding.
pub mod const_buffer_fold;
/// Compile-time constant folding.
pub mod const_fold;
/// Remove declared buffers that cannot affect any output.
pub mod dead_buffer_elim;
/// Kernel fusion by eliminating pure single-use scalar intermediates.
pub mod fusion;
/// Hardware quirk normalization (edge-cases).
pub mod normalize_atomics;
/// Algebraic rewrites derived from operation specifications.
pub mod spec_driven;
/// Multiplication strength reduction.
pub mod strength_reduce;

/// G2: megakernel rule-fusion with cross-rule CSE — takes many
/// Programs, emits one fused Program with shared subexpressions
/// deduplicated across rules.
pub mod fuse_cse;

/// G5: decode→scan fusion detector. The transform itself lives in
/// `vyre_libs::decode::streaming::fuse_decode_scan`; this pass
/// reports how many fusion opportunities a given Program presents.
pub mod decode_scan_fuse;
