use super::expr_key::{ExprId, ExprKey};
use rustc_hash::FxHashMap;

/// Mutable state for one common-subexpression-elimination traversal.
#[derive(Default)]
pub struct CseCtx {
    pub(super) values: FxHashMap<ExprId, String>,
    pub(super) undo_log: Vec<(ExprId, Option<String>)>,
    pub(super) scope_stack: Vec<usize>,
    pub(super) arena: Vec<ExprKey>,
    pub(super) deduplication: FxHashMap<ExprKey, ExprId>,
    /// Monotonic counter for uniquely keying subgroup-intrinsic expressions
    /// so CSE never merges two subgroup calls (they are lane-correlated
    /// and effectful). See `expr_key::ExprKey::Subgroup`.
    pub(super) subgroup_counter: u32,
}
