//! Tier 2.5 parsing primitives.
//!
//! These are the reusable optimizer kernels that Tier 3 language packs compose
//! into full parsing/AST passes.

/// SSA dominance-frontier phi discovery scan.
pub mod ssa_dominance_scan;

/// Shared AST opcode constants.
pub mod ast_ops;

/// Constant-folding wave for packed AST nodes.
pub mod cse_constant_fold;

/// Structural-hash CSE probe/insert wave.
pub mod cse_structural_hash;
