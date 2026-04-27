//! Dead-code elimination helpers for the IR optimizer.
#![allow(unused_doc_comments)]

/// Collect variable references from an expression tree.
pub(crate) use collect_expr_refs::collect_expr_refs;
/// Evaluate whether loop bounds make a loop statically empty.
pub(crate) use const_loop_empty::const_loop_empty;
/// Evaluate an expression as a static boolean when possible.
pub(crate) use const_truth::const_truth;
/// Remove let-bindings whose values are neither live nor effectful.
pub(crate) use eliminate_dead_lets::eliminate_dead_lets;
/// Trim unreachable control-flow nodes after static terminators.
pub(crate) use eliminate_unreachable::eliminate_unreachable;
/// Classify whether an expression must be preserved for side effects.
pub(crate) use expr_has_effect::expr_has_effect;
/// Result bundle returned by liveness pruning.
pub(crate) use live_result::LiveResult;
/// Return the node prefix reachable before an unconditional return.
pub(crate) use reachable_prefix::reachable_prefix;

/// Iterative visitor that accumulates every [`Expr::Var`](crate::ir::Expr::Var)
/// name into a [`HashSet`](std::collections::HashSet).
///
/// Used by liveness analysis as a conservative over-approximation of which
/// variables are referenced.
pub mod collect_expr_refs;
/// Detect statically empty loops.
///
/// Returns `true` only when both loop bounds are matching literal integers
/// and `from >= to`.  Conservatively returns `false` for non-constant bounds.
pub mod const_loop_empty;
/// Partial constant evaluator for boolean expressions.
///
/// Returns `Some(bool)` for literal booleans and integer literals;
/// `None` for anything else.  Used by unreachable-code folding.
pub mod const_truth;
/// Entry point for the dead-code elimination pass.
///
/// Runs `eliminate_dead_lets` → `eliminate_unreachable` →
/// `eliminate_dead_lets` again.  The second dead-let pass catches bindings
/// that become dead after unreachable code is stripped.
///
/// Invariant: removes only unreachable control flow and unread pure `let`
/// bindings; effectful statements are always preserved.
///
/// Complexity: O(n) in program size.
pub mod dce;
/// Backward liveness pass that strips dead `let` bindings.
///
/// Walks nodes in reverse (within the reachable prefix).  Drops a `let` when
/// its name is not live and its value is pure.  Recursively processes `If`,
/// `Loop`, and `Block` bodies.
///
/// Invariant: effectful nodes (`Assign`, `Store`, calls, atomics) and all
/// control flow are always preserved.
pub mod eliminate_dead_lets;
/// Forward pass folding constant branches and truncating after `Return`.
///
/// Constant `If` branches are replaced by the taken arm.  Statically empty
/// loops are elided.  Everything after an unconditional `Return` is discarded.
///
/// Invariant: reachable code semantics are preserved; only unreachable code
/// is removed.
pub mod eliminate_unreachable;
/// Predicate: does an expression contain observable side effects?
///
/// Returns `true` for `Atomic` and `Call`; `false` for literals and builtins.
/// This is the safety gate that prevents DCE from deleting effectful lets.
pub mod expr_has_effect;
/// Result bundle returned by `eliminate_dead_lets()`.
///
/// Carries the pruned node list and the set of variable names live on entry.
pub mod live_result;
/// Slice the node list up to the first unconditional `Return`.
///
/// Nodes after a `Return` are unreachable in straight-line sequences.
/// Complexity: O(n) to find the first `Return`.
pub mod reachable_prefix;
