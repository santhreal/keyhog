//! Workgroup-uniformity analysis for `Expr` nodes.
//!
//! An expression is *uniform* iff every invocation in the same
//! workgroup, evaluating it at the same source position, produces
//! the same value. Uniform `Loop` bounds and `If` conditions keep
//! every invocation in lockstep, so a `Node::Barrier` placed in
//! such a body is well-defined under WGSL/Vulkan barrier semantics.
//!
//! The analyzer is intentionally conservative: anything we cannot
//! statically prove uniform is reported as divergent. False
//! negatives are safe (the validator continues to reject barriers
//! that *would* in fact be uniform); false positives are not (a
//! divergent barrier reaches only some lanes and deadlocks the
//! workgroup or produces undefined results on real hardware).

use crate::ir_inner::model::expr::Expr;
use crate::validate::binding::Binding;
use rustc_hash::FxHashMap;

/// Return `true` when `expr` is statically uniform across the
/// workgroup given the live `scope` of `Var` bindings.
///
/// Uniform: literal scalars, `BufLen { .. }`, `WorkgroupId { .. }`,
/// `Var` bindings flagged uniform, and arithmetic/cast/select trees
/// whose every leaf is uniform.
///
/// Divergent: `InvocationId`, `LocalId`, `SubgroupLocalId`,
/// `SubgroupSize`, `Load`, `Atomic`, every `Subgroup*` op, `Call`,
/// and `Opaque`. A `Var` for which no binding is known is also
/// treated as divergent.
pub(crate) fn is_uniform(expr: &Expr, scope: &FxHashMap<String, Binding>) -> bool {
    match expr {
        Expr::LitU32(_) | Expr::LitI32(_) | Expr::LitF32(_) | Expr::LitBool(_) => true,
        Expr::BufLen { .. } => true,
        Expr::WorkgroupId { .. } => true,
        Expr::InvocationId { .. } | Expr::LocalId { .. } => false,
        Expr::SubgroupLocalId | Expr::SubgroupSize => false,
        Expr::Var(name) => scope.get(name.as_str()).map_or(false, |b| b.uniform),
        Expr::BinOp { left, right, .. } => is_uniform(left, scope) && is_uniform(right, scope),
        Expr::UnOp { operand, .. } => is_uniform(operand, scope),
        Expr::Cast { value, .. } => is_uniform(value, scope),
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => is_uniform(cond, scope) && is_uniform(true_val, scope) && is_uniform(false_val, scope),
        Expr::Fma { a, b, c } => {
            is_uniform(a, scope) && is_uniform(b, scope) && is_uniform(c, scope)
        }
        Expr::Load { .. }
        | Expr::Call { .. }
        | Expr::Atomic { .. }
        | Expr::SubgroupBallot { .. }
        | Expr::SubgroupShuffle { .. }
        | Expr::SubgroupAdd { .. }
        | Expr::Opaque(_) => false,
    }
}
