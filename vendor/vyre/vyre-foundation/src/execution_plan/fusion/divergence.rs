//! Divergence + invocation-gate analysis used by the fusion safety check.

use crate::ir::{Expr, Node};

pub(super) fn has_divergent_invocation_gated_store(
    node: &Node,
    inside_invocation_gate: bool,
) -> bool {
    match node {
        Node::Store { .. } => inside_invocation_gate,
        Node::Let { value, .. } | Node::Assign { value, .. } => {
            inside_invocation_gate && expr_writes_atomic(value)
        }
        Node::If {
            cond,
            then,
            otherwise,
        } => {
            let new_gate = inside_invocation_gate || cond_depends_on_invocation_id(cond);
            then.iter()
                .chain(otherwise.iter())
                .any(|n| has_divergent_invocation_gated_store(n, new_gate))
        }
        Node::Loop { body, .. } => body
            .iter()
            .any(|n| has_divergent_invocation_gated_store(n, inside_invocation_gate)),
        Node::Block(body) => body
            .iter()
            .any(|n| has_divergent_invocation_gated_store(n, inside_invocation_gate)),
        Node::Region { body, .. } => body
            .iter()
            .any(|n| has_divergent_invocation_gated_store(n, inside_invocation_gate)),
        Node::IndirectDispatch { .. }
        | Node::AllReduce { .. }
        | Node::AllGather { .. }
        | Node::ReduceScatter { .. }
        | Node::Broadcast { .. }
        | Node::Return
        | Node::Barrier { .. }
        | Node::AsyncLoad { .. }
        | Node::AsyncStore { .. }
        | Node::AsyncWait { .. }
        | Node::Trap { .. }
        | Node::Resume { .. }
        | Node::Opaque(_) => false,
    }
}

/// `true` when `expr` references `Expr::InvocationId` (any axis),
/// `Expr::WorkgroupId`, or `Expr::LocalId` somewhere in its tree.
/// These are the canonical "this thread is special" predicates.
fn cond_depends_on_invocation_id(expr: &Expr) -> bool {
    match expr {
        Expr::InvocationId { .. }
        | Expr::WorkgroupId { .. }
        | Expr::LocalId { .. }
        | Expr::SubgroupLocalId
        | Expr::SubgroupSize => true,
        Expr::BinOp { left, right, .. } => {
            cond_depends_on_invocation_id(left) || cond_depends_on_invocation_id(right)
        }
        Expr::UnOp { operand, .. } => cond_depends_on_invocation_id(operand),
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => {
            cond_depends_on_invocation_id(cond)
                || cond_depends_on_invocation_id(true_val)
                || cond_depends_on_invocation_id(false_val)
        }
        Expr::Cast { value, .. } | Expr::SubgroupAdd { value } => {
            cond_depends_on_invocation_id(value)
        }
        Expr::Fma { a, b, c } => {
            cond_depends_on_invocation_id(a)
                || cond_depends_on_invocation_id(b)
                || cond_depends_on_invocation_id(c)
        }
        Expr::Load { index, .. } => cond_depends_on_invocation_id(index),
        Expr::Atomic {
            index,
            expected,
            value,
            ..
        } => {
            cond_depends_on_invocation_id(index)
                || expected
                    .as_deref()
                    .is_some_and(cond_depends_on_invocation_id)
                || cond_depends_on_invocation_id(value)
        }
        Expr::Call { args, .. } => args.iter().any(cond_depends_on_invocation_id),
        Expr::SubgroupBallot { cond } => cond_depends_on_invocation_id(cond),
        Expr::SubgroupShuffle { value, lane } => {
            cond_depends_on_invocation_id(value) || cond_depends_on_invocation_id(lane)
        }
        Expr::LitU32(_)
        | Expr::LitI32(_)
        | Expr::LitF32(_)
        | Expr::LitBool(_)
        | Expr::Var(_)
        | Expr::BufLen { .. }
        | Expr::Opaque(_) => false,
    }
}

/// `true` when `expr` is an atomic operation (which writes memory).
/// Used by the divergent-gate detector to pick up `Let { value:
/// Atomic { ... } }` / `Assign { value: Atomic { ... } }` patterns  -
/// the canonical `lower_call_to` `atomic_or` shape.
pub(super) fn expr_writes_atomic(expr: &Expr) -> bool {
    match expr {
        Expr::Atomic { .. } => true,
        Expr::BinOp { left, right, .. } => expr_writes_atomic(left) || expr_writes_atomic(right),
        Expr::UnOp { operand, .. } => expr_writes_atomic(operand),
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => {
            expr_writes_atomic(cond)
                || expr_writes_atomic(true_val)
                || expr_writes_atomic(false_val)
        }
        Expr::Cast { value, .. } | Expr::SubgroupAdd { value } => expr_writes_atomic(value),
        Expr::Fma { a, b, c } => {
            expr_writes_atomic(a) || expr_writes_atomic(b) || expr_writes_atomic(c)
        }
        Expr::Load { index, .. } => expr_writes_atomic(index),
        Expr::Call { args, .. } => args.iter().any(expr_writes_atomic),
        Expr::SubgroupBallot { cond } => expr_writes_atomic(cond),
        Expr::SubgroupShuffle { value, lane } => {
            expr_writes_atomic(value) || expr_writes_atomic(lane)
        }
        Expr::LitU32(_)
        | Expr::LitI32(_)
        | Expr::LitF32(_)
        | Expr::LitBool(_)
        | Expr::Var(_)
        | Expr::InvocationId { .. }
        | Expr::WorkgroupId { .. }
        | Expr::LocalId { .. }
        | Expr::SubgroupLocalId
        | Expr::SubgroupSize
        | Expr::BufLen { .. }
        | Expr::Opaque(_) => false,
    }
}
