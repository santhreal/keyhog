//! Rule-engine dialect: typed conditions, formulas, and program builder.

/// Typed condition / formula AST consumed by every rule-set builder.
pub mod ast;
/// Rule-set IR program builder — walks a `[(RuleFormula, rule_id)]` table
/// and emits one `Node::Store` per rule into the shared `verdicts` buffer.
pub mod builder;
/// Shared Cat-A helpers for scalar rule-condition ops (Tier-3 plumbing).
pub mod condition_op;
/// Cat-A op: `file_size == threshold` rule predicate.
pub mod file_size_eq;
/// Cat-A op: `file_size > threshold` rule predicate.
pub mod file_size_gt;
/// Cat-A op: `file_size >= threshold` rule predicate.
pub mod file_size_gte;
/// Cat-A op: `file_size < threshold` rule predicate.
pub mod file_size_lt;
/// Cat-A op: `file_size <= threshold` rule predicate.
pub mod file_size_lte;
/// Cat-A op: `file_size != threshold` rule predicate.
pub mod file_size_ne;
/// Cat-A op: constant-false rule leaf.
pub mod literal_false;
/// Cat-A op: constant-true rule leaf.
pub mod literal_true;
/// Cat-A op: `pattern_count > threshold` rule predicate.
pub mod pattern_count_gt;
/// Cat-A op: `pattern_count >= threshold` rule predicate.
pub mod pattern_count_gte;
/// Cat-A op: pattern-existence rule predicate.
pub mod pattern_exists;

pub use ast::{RuleCondition, RuleFormula};
pub use builder::build_rule_program;
