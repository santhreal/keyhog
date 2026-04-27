#![allow(
    clippy::only_used_in_recursion,
    clippy::comparison_chain,
    clippy::ptr_arg
)]
//! Pure Rust reference interpreter for vyre IR programs.
//!
//! This module is the executable specification for IR semantics. It is
//! intentionally slow and direct: every current IR expression and node variant
//! has a named evaluator function.

extern crate vyre_foundation as vyre;

/// Dual-reference trait and registry types.
pub mod dual;
// Hash primitive references moved out of `vyre-ops` for the 0.6 cycle
// along with every other WGSL-string-shaped dialect. They return in 0.7
// through the native naga-AST emitter. Until then, consumers that need
// hash reference implementations depend on their own hash crate; no
// placeholder stub is published from here (LAW 1).
/// Operation-specific standalone CPU references.
pub mod primitive;
/// Canonical open-IR primitive reference evaluators.
pub mod primitives;
/// Runtime value representation for interpreter inputs and outputs.
pub mod value;

/// Atomic operation reference implementations.
pub mod atomics;
/// CPU operation traits used by concrete reference implementations.
pub mod cpu_op;
/// Registry-driven dispatch entry point (B-B4).
///
/// Routes an op id through the global `DialectRegistry` and invokes
/// the registered `cpu_ref` function. Complements the existing
/// scan-based evaluators in [`interp`] and `crate::hashmap_interp`
/// by giving external dialect crates a zero-patch path to run on
/// the reference interpreter.
pub mod dialect_dispatch;
mod eval_call;
/// Expression evaluator (BinOp, UnOp, Load, Call, etc).
pub mod eval_expr;
mod eval_expr_cast;
/// Statement evaluator (Let, Store, If, Loop, Barrier, etc).
pub mod eval_node;
/// Flat byte adapter used by [`crate::cpu_op::CpuOp`].
pub mod flat_cpu;
/// IEEE 754 strict floating-point utilities.
pub mod ieee754;
/// Top-level interpreter entry point and error types.
pub mod interp;
/// Sequential workgroup execution - canonical CPU parity oracle.
pub mod sequential;
/// Subgroup simulator for lane-collective Cat-C ops.
pub mod subgroup;
/// Workgroup simulation: invocation IDs, shared memory.
pub mod workgroup;

mod hashmap_interp;
mod oob;
mod ops;
mod typed_ops;

/// Test-only entry point that runs the hashmap interpreter over a Program.
#[cfg(test)]
pub use interp::eval_hashmap_reference;
/// Execute a vyre Program on the pure Rust reference interpreter.
pub use interp::reference_eval;

/// Resolve an operation ID to its two independently-written references.
///
/// # Examples
///
/// ```
/// use vyre_reference::{primitive, resolve_dual};
///
/// let (reference_a, reference_b) =
///     resolve_dual(primitive::bitwise::xor::OP_ID).expect("xor dual refs must be registered");
///
/// let input = [0b1010_1010_u8, 0b0101_0101];
/// assert_eq!(reference_a(&input), reference_b(&input));
/// ```
pub fn resolve_dual(op_id: &str) -> Option<(dual::ReferenceFn, dual::ReferenceFn)> {
    match op_id {
        primitive::bitwise::xor::OP_ID => Some((
            primitive::bitwise::xor::reference_a::reference,
            primitive::bitwise::xor::reference_b::reference,
        )),
        _ => None,
    }
}

/// Return the complete list of operation IDs that have dual references registered.
///
/// This is the canonical enumeration used by the differential fuzzing gate.
/// Every new dual-reference pair MUST add its OP_ID here.
pub fn dual_op_ids() -> &'static [&'static str] {
    &[primitive::bitwise::xor::OP_ID]
}
