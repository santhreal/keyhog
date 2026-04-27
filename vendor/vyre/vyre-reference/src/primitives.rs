//! Reference evaluators for the twenty canonical open-IR primitives.

/// Integer wrap-around addition primitive reference.
pub mod arith_add;
/// Integer wrap-around multiplication primitive reference.
pub mod arith_mul;
/// Bitwise AND primitive reference.
pub mod bitwise_and;
/// Bitwise OR primitive reference.
pub mod bitwise_or;
/// Bitwise XOR primitive reference.
pub mod bitwise_xor;
/// Count-leading-zeros primitive reference.
pub mod clz;
mod common;
/// Equality comparison primitive reference.
pub mod compare_eq;
/// Less-than comparison primitive reference.
pub mod compare_lt;
/// Workgroup-local gather primitive reference.
pub mod gather;
/// BLAKE3 hashing primitive reference.
pub mod hash_blake3;
/// FNV-1a hashing primitive reference.
pub mod hash_fnv1a;
/// Population-count primitive reference.
pub mod popcount;
/// Associative reduction primitive reference.
pub mod reduce;
/// Inclusive/exclusive prefix scan primitive reference.
pub mod scan;
/// DFA-driven scan primitive reference.
pub mod scan_dfa;
/// Literal-string scan primitive reference.
pub mod scan_literal;
/// Scatter primitive reference.
pub mod scatter;
/// Logical shift-left primitive reference.
pub mod shift_left;
/// Logical shift-right primitive reference.
pub mod shift_right;
/// Workgroup-local shuffle primitive reference.
pub mod shuffle;

pub use common::{EvalError, ReferenceEvaluator};
