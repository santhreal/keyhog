// IR-to-IR optimization passes.

use crate::ir_inner::model::program::Program;

/// Run the standard pre-lowering optimization pipeline.
///
/// The pipeline currently performs common-subexpression elimination followed by
/// dead-code elimination. Pass order is stable so tests and downstream tooling
/// can inspect individual stages when needed.
#[must_use]
#[inline]
pub fn optimize(program: Program) -> Program {
    // P4.2: canonicalize BEFORE region_inline/CSE/DCE so those
    // passes see a deterministic operand order. Canonical form also
    // feeds the content-addressed pipeline cache (P4.3/P4.4).
    // After region_inline flattens small regions, reconcile re-wraps
    // the top level so the program stays runnable and validator-safe.
    dce::dce::dce(cse::cse::cse(
        region_inline::run(canonicalize::run(program)).reconcile_runnable_top_level(),
    ))
}

/// Region-inline pass: flattens `Node::Region` debug-wrappers produced
/// by `vyre-libs` Category-A compositions when the body is under a
/// heuristic threshold. Runs before CSE/DCE so those passes see the
/// composed program as one unit.
pub mod region_inline;

/// P4.2 — canonical-form pass: sorts commutative operands, hoists
/// literals to the right, so semantically-equal programs produce
/// byte-equal wire output.
pub mod canonicalize;

/// Common-subexpression elimination for vyre IR.
///
/// Removes redundant pure subexpressions by replacing them with earlier
/// equivalent variable references.  Effectful expressions are never merged.
pub mod cse;

/// Dead-code elimination for vyre IR.
///
/// Removes unreachable control flow and unread pure `let` bindings.
/// Effectful statements and live variables are always preserved.
pub mod dce;

/// Optimization pass test suites.
#[cfg(test)]
pub mod tests;
