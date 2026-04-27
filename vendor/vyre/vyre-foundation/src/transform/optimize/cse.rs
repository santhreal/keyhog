//! Common-subexpression elimination helpers for pure IR expressions.
#![allow(unused_doc_comments)]

/// Per-pass table of previously seen expression keys.
pub use cse_ctx::CseCtx;
/// Classify whether an expression is unsafe to merge.
pub(crate) use expr_has_effect::expr_has_effect;
/// Return whether a binary operator can canonicalize operand order.
pub(crate) use is_commutative::is_commutative;
/// Compact key for expression result types.
pub(crate) use type_key::TypeKey;

/// Run one pass of local common-subexpression elimination.
///
/// Invariant: only pure subexpressions are replaced with earlier equivalent
/// bindings; effectful expressions (`Atomic`, `Call`, `Load` with possible
/// side-effects) are never eliminated.
///
/// Complexity: O(n) in program size.
pub mod cse;
/// Per-pass context tracking seen expressions and their first binding name.
///
/// Uses a flat `FxHashMap` plus a Vec-based undo log so that forked contexts
/// for branches cost O(1) and no map cloning occurs.
pub mod cse_ctx;
/// Conservative predicate: does this expression have observable side effects?
///
/// Returns `true` for `Atomic` and `Call`; recurses through pure combinators.
/// This is the safety gate that prevents CSE from merging effectful nodes.
pub mod expr_has_effect;
/// Structural key for comparing candidate expressions during CSE.
///
/// Equality corresponds to structural equality.  Commutative operators are
/// canonicalised by sorting operands.  `Atomic` expressions map to a single
/// sentinel key so they are never considered equal to anything else.
pub mod expr_key;
/// Core CSE algorithm (`CseCtx::node` / `expr`).
///
/// Walks the IR bottom-up, replacing pure common subexpressions with variable
/// references.  Effectful nodes clear the observed-value map.  Branches fork
/// the context; loops start with a fresh context.
///
/// Invariant: never aliases a literal through a mutable variable (e.g.
/// `let state = 0u` does not record `LitU32(0) → "state"`).
pub mod impl_csectx;
/// Build an `ExprKey` from an [`Expr`](crate::ir::Expr).
///
/// Canonicalises commutative `BinOp` operand order.  Maps `Fma` to a synthetic
/// `Call("fma", …)`.  Unknown operators fall back to a sentinel key.
pub mod impl_exprkey;
/// `From<DataType>` implementation for `TypeKey`.
///
/// Encodes scalar and vector types compactly; arrays embed their element size.
/// Unknown types map to sentinel `255`.
pub mod impl_typekey_from;
/// Which binary operators are commutative under CSE canonicalisation?
///
/// Covers `Add`, `Mul`, `BitAnd`, `BitOr`, `BitXor`, `Eq`, `Ne`, `And`, `Or`.
pub mod is_commutative;
/// Compact `Copy` key for expression result types used by the CSE table.
pub mod type_key;

/// CSE test suites — adversarial cases for literal aliasing and non-literal
/// subexpression merging.
#[cfg(test)]
#[path = "tests/cse.rs"]
pub mod tests;
