//! Combined arena-pass delta application.
//!
//! Walks the input Program in the same DFS post-order as the
//! ExprArena encoder, applying the canonicalize swap_mask, const-fold
//! foldable+value, and pattern-match rewrite_action in priority order:
//!
//! 1. **const-fold** wins: if `foldable[id] == 1`, replace the Expr
//!    with `LitU32(value[id])`.
//! 2. **pattern-match** next: apply the `rewrite_action` from the
//!    pattern bank (replace with left/right child or LitU32(0)).
//! 3. **canonicalize** last: if it's a BinOp and `swap_mask[id] == 1`,
//!    swap operands.
//!
//! Per the V1 rule sets (see module docs in `pipeline_resident`),
//! this priority is sound — the three passes are independent at the
//! Expr level for the rules currently shipped.

use std::sync::Arc;

use vyre_foundation::ir::{Expr, Node, Program};

use super::pattern_match_via_encoded::rewrite_action as ra;

/// Apply the combined per-Expr deltas to `program`, producing the
/// post-arena-pass Program. DCE is run separately on the result.
pub fn apply_combined_arena_deltas(
    program: &Program,
    swap_mask: &[u32],
    foldable: &[u32],
    value: &[u32],
    rewrite_action: &[u32],
) -> Program {
    let body: Vec<Node> = match program.entry() {
        [Node::Region { body, .. }] => body.as_ref().clone(),
        entry => entry.to_vec(),
    };

    let mut counter = 0u32;
    let rebuilt = rewrite_scope(
        &body,
        swap_mask,
        foldable,
        value,
        rewrite_action,
        &mut counter,
    );

    let new_entry = match program.entry() {
        [Node::Region {
            generator,
            source_region,
            ..
        }] => vec![Node::Region {
            generator: generator.clone(),
            source_region: source_region.clone(),
            body: Arc::new(rebuilt),
        }],
        _ => rebuilt,
    };
    program.with_rewritten_entry(new_entry)
}

fn rewrite_scope(
    body: &[Node],
    swap_mask: &[u32],
    foldable: &[u32],
    value: &[u32],
    rewrite_action: &[u32],
    counter: &mut u32,
) -> Vec<Node> {
    let prefix_len = super::encode::reachable_prefix_len(body);
    let mut out = Vec::with_capacity(prefix_len);
    for node in &body[..prefix_len] {
        out.push(rewrite_node(
            node,
            swap_mask,
            foldable,
            value,
            rewrite_action,
            counter,
        ));
    }
    out
}

fn rewrite_node(
    node: &Node,
    swap_mask: &[u32],
    foldable: &[u32],
    value: &[u32],
    rewrite_action: &[u32],
    counter: &mut u32,
) -> Node {
    match node {
        Node::Let { name, value: e } => Node::let_bind(
            name.clone(),
            rewrite_expr(e, swap_mask, foldable, value, rewrite_action, counter),
        ),
        Node::Assign { name, value: e } => Node::assign(
            name.clone(),
            rewrite_expr(e, swap_mask, foldable, value, rewrite_action, counter),
        ),
        Node::Store {
            buffer,
            index,
            value: e,
        } => Node::store(
            buffer.clone(),
            rewrite_expr(index, swap_mask, foldable, value, rewrite_action, counter),
            rewrite_expr(e, swap_mask, foldable, value, rewrite_action, counter),
        ),
        Node::If {
            cond,
            then,
            otherwise,
        } => Node::if_then_else(
            rewrite_expr(cond, swap_mask, foldable, value, rewrite_action, counter),
            rewrite_scope(then, swap_mask, foldable, value, rewrite_action, counter),
            rewrite_scope(
                otherwise,
                swap_mask,
                foldable,
                value,
                rewrite_action,
                counter,
            ),
        ),
        Node::Loop {
            var,
            from,
            to,
            body,
        } => Node::loop_for(
            var.clone(),
            rewrite_expr(from, swap_mask, foldable, value, rewrite_action, counter),
            rewrite_expr(to, swap_mask, foldable, value, rewrite_action, counter),
            rewrite_scope(body, swap_mask, foldable, value, rewrite_action, counter),
        ),
        Node::AsyncLoad {
            source,
            destination,
            offset,
            size,
            tag,
        } => Node::AsyncLoad {
            source: source.clone(),
            destination: destination.clone(),
            offset: Box::new(rewrite_expr(
                offset,
                swap_mask,
                foldable,
                value,
                rewrite_action,
                counter,
            )),
            size: Box::new(rewrite_expr(
                size,
                swap_mask,
                foldable,
                value,
                rewrite_action,
                counter,
            )),
            tag: tag.clone(),
        },
        Node::AsyncStore {
            source,
            destination,
            offset,
            size,
            tag,
        } => Node::AsyncStore {
            source: source.clone(),
            destination: destination.clone(),
            offset: Box::new(rewrite_expr(
                offset,
                swap_mask,
                foldable,
                value,
                rewrite_action,
                counter,
            )),
            size: Box::new(rewrite_expr(
                size,
                swap_mask,
                foldable,
                value,
                rewrite_action,
                counter,
            )),
            tag: tag.clone(),
        },
        Node::Trap { address, tag } => Node::Trap {
            address: Box::new(rewrite_expr(
                address,
                swap_mask,
                foldable,
                value,
                rewrite_action,
                counter,
            )),
            tag: tag.clone(),
        },
        Node::Block(body) => Node::Block(rewrite_scope(
            body,
            swap_mask,
            foldable,
            value,
            rewrite_action,
            counter,
        )),
        Node::Region {
            generator,
            source_region,
            body,
        } => Node::Region {
            generator: generator.clone(),
            source_region: source_region.clone(),
            body: Arc::new(rewrite_scope(
                body.as_slice(),
                swap_mask,
                foldable,
                value,
                rewrite_action,
                counter,
            )),
        },
        Node::Return
        | Node::Barrier { .. }
        | Node::IndirectDispatch { .. }
        | Node::AsyncWait { .. }
        | Node::Resume { .. }
        | Node::Opaque(_) => node.clone(),
        _ => node.clone(),
    }
}

fn rewrite_expr(
    expr: &Expr,
    swap_mask: &[u32],
    foldable: &[u32],
    value: &[u32],
    rewrite_action: &[u32],
    counter: &mut u32,
) -> Expr {
    match expr {
        Expr::LitU32(_)
        | Expr::LitI32(_)
        | Expr::LitF32(_)
        | Expr::LitBool(_)
        | Expr::Var(_)
        | Expr::BufLen { .. }
        | Expr::InvocationId { .. }
        | Expr::WorkgroupId { .. }
        | Expr::LocalId { .. }
        | Expr::SubgroupLocalId
        | Expr::SubgroupSize => {
            let id = *counter as usize;
            *counter += 1;
            decide_leaf(expr, id, foldable, value)
        }
        Expr::Load { buffer, index } => {
            let new_index =
                rewrite_expr(index, swap_mask, foldable, value, rewrite_action, counter);
            *counter += 1;
            // Loads are not foldable / not pattern-matched / not
            // canonicalized.
            Expr::Load {
                buffer: buffer.clone(),
                index: Box::new(new_index),
            }
        }
        Expr::BinOp { op, left, right } => {
            let new_left = rewrite_expr(left, swap_mask, foldable, value, rewrite_action, counter);
            let new_right =
                rewrite_expr(right, swap_mask, foldable, value, rewrite_action, counter);
            let id = *counter as usize;
            *counter += 1;

            // Priority 1: const-fold. The kernel writes the folded
            // u32 result into `value[id]`. For comparison BinOps the
            // result is semantically Bool — emit LitBool so dead-
            // branch and downstream type-aware passes see the right
            // shape. For arithmetic BinOps emit LitU32.
            if foldable.get(id).copied().unwrap_or(0) == 1 {
                let raw = value.get(id).copied().unwrap_or(0);
                use vyre_foundation::ir::BinOp;
                let bool_result = matches!(
                    op,
                    BinOp::Eq | BinOp::Ne | BinOp::Lt | BinOp::Gt | BinOp::Le | BinOp::Ge
                );
                if bool_result {
                    return Expr::LitBool(raw != 0);
                }
                return Expr::LitU32(raw);
            }
            // Priority 2: pattern-match rewrite.
            match rewrite_action.get(id).copied().unwrap_or(ra::NONE) {
                ra::REPLACE_WITH_LEFT => return new_left,
                ra::REPLACE_WITH_RIGHT => return new_right,
                ra::REPLACE_WITH_LIT_ZERO => return Expr::LitU32(0),
                ra::REPLACE_WITH_LIT_TRUE => return Expr::LitBool(true),
                ra::REPLACE_WITH_LIT_FALSE => return Expr::LitBool(false),
                ra::REPLACE_WITH_LEFT_INNER_LEFT => {
                    if let Expr::BinOp { left: inner_l, .. } = &new_left {
                        return inner_l.as_ref().clone();
                    }
                }
                ra::REPLACE_WITH_LEFT_INNER_RIGHT => {
                    if let Expr::BinOp { right: inner_r, .. } = &new_left {
                        return inner_r.as_ref().clone();
                    }
                }
                _ => {}
            }
            // Priority 3: canonicalize swap.
            if swap_mask.get(id).copied().unwrap_or(0) == 1 {
                Expr::BinOp {
                    op: *op,
                    left: Box::new(new_right),
                    right: Box::new(new_left),
                }
            } else {
                Expr::BinOp {
                    op: *op,
                    left: Box::new(new_left),
                    right: Box::new(new_right),
                }
            }
        }
        Expr::UnOp { op, operand } => {
            let new_operand =
                rewrite_expr(operand, swap_mask, foldable, value, rewrite_action, counter);
            let id = *counter as usize;
            *counter += 1;
            if foldable.get(id).copied().unwrap_or(0) == 1 {
                return Expr::LitU32(value.get(id).copied().unwrap_or(0));
            }
            // UnOp pattern-match: REPLACE_WITH_GRAND_OPERAND fires
            // for `~~x = x`, `--x = x`, `!!x = x`. The grand-child is
            // `new_operand`'s own operand; we descend one level.
            if rewrite_action.get(id).copied().unwrap_or(ra::NONE) == ra::REPLACE_WITH_GRAND_OPERAND
            {
                if let Expr::UnOp { operand: inner, .. } = &new_operand {
                    return inner.as_ref().clone();
                }
            }
            Expr::UnOp {
                op: op.clone(),
                operand: Box::new(new_operand),
            }
        }
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => {
            let nc = rewrite_expr(cond, swap_mask, foldable, value, rewrite_action, counter);
            let nt = rewrite_expr(
                true_val,
                swap_mask,
                foldable,
                value,
                rewrite_action,
                counter,
            );
            let nf = rewrite_expr(
                false_val,
                swap_mask,
                foldable,
                value,
                rewrite_action,
                counter,
            );
            *counter += 1;
            Expr::Select {
                cond: Box::new(nc),
                true_val: Box::new(nt),
                false_val: Box::new(nf),
            }
        }
        Expr::Fma { a, b, c } => {
            let na = rewrite_expr(a, swap_mask, foldable, value, rewrite_action, counter);
            let nb = rewrite_expr(b, swap_mask, foldable, value, rewrite_action, counter);
            let nc = rewrite_expr(c, swap_mask, foldable, value, rewrite_action, counter);
            *counter += 1;
            Expr::Fma {
                a: Box::new(na),
                b: Box::new(nb),
                c: Box::new(nc),
            }
        }
        _ => expr.clone(),
    }
}

fn decide_leaf(expr: &Expr, id: usize, foldable: &[u32], value: &[u32]) -> Expr {
    if foldable.get(id).copied().unwrap_or(0) == 1 {
        match expr {
            Expr::LitU32(_) | Expr::LitI32(_) | Expr::LitF32(_) | Expr::LitBool(_) => expr.clone(),
            _ => Expr::LitU32(value.get(id).copied().unwrap_or(0)),
        }
    } else {
        expr.clone()
    }
}
