//! Buffer-target collectors for load/store/atomic walks.

use rustc_hash::FxHashSet;

use crate::ir::{Expr, Ident, Node};

pub(super) fn collect_load_targets_from_node(node: &Node, targets: &mut FxHashSet<Ident>) {
    match node {
        Node::Let { value, .. } | Node::Assign { value, .. } => {
            collect_load_targets_from_expr(value, targets);
        }
        Node::Store { index, value, .. } => {
            collect_load_targets_from_expr(index, targets);
            collect_load_targets_from_expr(value, targets);
        }
        Node::If {
            cond,
            then,
            otherwise,
        } => {
            collect_load_targets_from_expr(cond, targets);
            for n in then.iter().chain(otherwise.iter()) {
                collect_load_targets_from_node(n, targets);
            }
        }
        Node::Loop { from, to, body, .. } => {
            collect_load_targets_from_expr(from, targets);
            collect_load_targets_from_expr(to, targets);
            for n in body {
                collect_load_targets_from_node(n, targets);
            }
        }
        Node::Block(body) => {
            for n in body {
                collect_load_targets_from_node(n, targets);
            }
        }
        Node::Region { body, .. } => {
            for n in body.iter() {
                collect_load_targets_from_node(n, targets);
            }
        }
        Node::IndirectDispatch { .. }
        | Node::Return
        | Node::Barrier { .. }
        | Node::AsyncLoad { .. }
        | Node::AsyncStore { .. }
        | Node::AsyncWait { .. }
        | Node::Trap { .. }
        | Node::Resume { .. }
        | Node::Opaque(_) => {}
    }
}

fn collect_load_targets_from_expr(expr: &Expr, targets: &mut FxHashSet<Ident>) {
    match expr {
        Expr::Load { buffer, index } => {
            targets.insert(Ident::from(buffer));
            collect_load_targets_from_expr(index, targets);
        }
        Expr::Atomic {
            index,
            expected,
            value,
            ..
        } => {
            collect_load_targets_from_expr(index, targets);
            if let Some(expected) = expected {
                collect_load_targets_from_expr(expected, targets);
            }
            collect_load_targets_from_expr(value, targets);
        }
        Expr::BinOp { left, right, .. } => {
            collect_load_targets_from_expr(left, targets);
            collect_load_targets_from_expr(right, targets);
        }
        Expr::UnOp { operand, .. } | Expr::Cast { value: operand, .. } => {
            collect_load_targets_from_expr(operand, targets);
        }
        Expr::Fma { a, b, c } => {
            collect_load_targets_from_expr(a, targets);
            collect_load_targets_from_expr(b, targets);
            collect_load_targets_from_expr(c, targets);
        }
        Expr::Call { args, .. } => {
            for arg in args {
                collect_load_targets_from_expr(arg, targets);
            }
        }
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => {
            collect_load_targets_from_expr(cond, targets);
            collect_load_targets_from_expr(true_val, targets);
            collect_load_targets_from_expr(false_val, targets);
        }
        Expr::SubgroupBallot { cond } => collect_load_targets_from_expr(cond, targets),
        Expr::SubgroupShuffle { value, lane } => {
            collect_load_targets_from_expr(value, targets);
            collect_load_targets_from_expr(lane, targets);
        }
        Expr::SubgroupAdd { value } => collect_load_targets_from_expr(value, targets),
        _ => {}
    }
}

/// Walk a node tree and add the buffer name of every `Node::Store` to
/// `targets`. Mirrors `collect_load_targets_from_node` for the WRITE
/// side so hazards across arms see body-level writes too.
pub(super) fn collect_store_targets_from_node(node: &Node, targets: &mut FxHashSet<Ident>) {
    match node {
        Node::Store { buffer, .. } => {
            targets.insert(Ident::from(buffer));
        }
        Node::Let { .. } | Node::Assign { .. } => {}
        Node::If {
            then, otherwise, ..
        } => {
            for n in then.iter().chain(otherwise.iter()) {
                collect_store_targets_from_node(n, targets);
            }
        }
        Node::Loop { body, .. } => {
            for n in body {
                collect_store_targets_from_node(n, targets);
            }
        }
        Node::Block(body) => {
            for n in body {
                collect_store_targets_from_node(n, targets);
            }
        }
        Node::Region { body, .. } => {
            for n in body.iter() {
                collect_store_targets_from_node(n, targets);
            }
        }
        Node::IndirectDispatch { .. }
        | Node::Return
        | Node::Barrier { .. }
        | Node::AsyncLoad { .. }
        | Node::AsyncStore { .. }
        | Node::AsyncWait { .. }
        | Node::Trap { .. }
        | Node::Resume { .. }
        | Node::Opaque(_) => {}
    }
}

pub(super) fn collect_atomic_targets_from_node(node: &Node, targets: &mut FxHashSet<Ident>) {
    match node {
        Node::Let { value, .. } | Node::Assign { value, .. } => {
            collect_atomic_targets_from_expr(value, targets);
        }
        Node::Store { index, value, .. } => {
            collect_atomic_targets_from_expr(index, targets);
            collect_atomic_targets_from_expr(value, targets);
        }
        Node::If {
            cond,
            then,
            otherwise,
        } => {
            collect_atomic_targets_from_expr(cond, targets);
            for n in then.iter().chain(otherwise.iter()) {
                collect_atomic_targets_from_node(n, targets);
            }
        }
        Node::Loop { from, to, body, .. } => {
            collect_atomic_targets_from_expr(from, targets);
            collect_atomic_targets_from_expr(to, targets);
            for n in body {
                collect_atomic_targets_from_node(n, targets);
            }
        }
        Node::Block(body) => {
            for n in body {
                collect_atomic_targets_from_node(n, targets);
            }
        }
        Node::Region { body, .. } => {
            for n in body.iter() {
                collect_atomic_targets_from_node(n, targets);
            }
        }
        Node::IndirectDispatch { .. }
        | Node::Return
        | Node::Barrier { .. }
        | Node::AsyncLoad { .. }
        | Node::AsyncStore { .. }
        | Node::AsyncWait { .. }
        | Node::Trap { .. }
        | Node::Resume { .. }
        | Node::Opaque(_) => {}
    }
}

/// Detect a divergent store gated on `Expr::InvocationId` — i.e. a
/// store that fires only for a subset of threads in the grid. The
/// canonical example is `bitset_any`'s `if invocation_id == 0 { ...
/// store ... }` where only thread 0 in the entire grid writes the
/// scalar. Such writes propagate within a workgroup via `bar.sync 0`
/// but DO NOT propagate across blocks without a grid-level fence —
fn collect_atomic_targets_from_expr(expr: &Expr, targets: &mut FxHashSet<Ident>) {
    match expr {
        Expr::Atomic {
            buffer,
            index,
            expected,
            value,
            ..
        } => {
            targets.insert(Ident::from(buffer));
            collect_atomic_targets_from_expr(index, targets);
            if let Some(expected) = expected {
                collect_atomic_targets_from_expr(expected, targets);
            }
            collect_atomic_targets_from_expr(value, targets);
        }
        Expr::Load { index, .. } => collect_atomic_targets_from_expr(index, targets),
        Expr::BinOp { left, right, .. } => {
            collect_atomic_targets_from_expr(left, targets);
            collect_atomic_targets_from_expr(right, targets);
        }
        Expr::UnOp { operand, .. } | Expr::Cast { value: operand, .. } => {
            collect_atomic_targets_from_expr(operand, targets);
        }
        Expr::Fma { a, b, c } => {
            collect_atomic_targets_from_expr(a, targets);
            collect_atomic_targets_from_expr(b, targets);
            collect_atomic_targets_from_expr(c, targets);
        }
        Expr::Call { args, .. } => {
            for arg in args {
                collect_atomic_targets_from_expr(arg, targets);
            }
        }
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => {
            collect_atomic_targets_from_expr(cond, targets);
            collect_atomic_targets_from_expr(true_val, targets);
            collect_atomic_targets_from_expr(false_val, targets);
        }
        Expr::SubgroupBallot { cond } => collect_atomic_targets_from_expr(cond, targets),
        Expr::SubgroupShuffle { value, lane } => {
            collect_atomic_targets_from_expr(value, targets);
            collect_atomic_targets_from_expr(lane, targets);
        }
        Expr::SubgroupAdd { value } => collect_atomic_targets_from_expr(value, targets),
        _ => {}
    }
}
