#![allow(clippy::expect_used)]
use crate::ir::{BinOp, Expr, Node, Program, UnOp};
use std::borrow::Cow;
use std::sync::Arc;

/// Run an expression-rewrite closure over every node in `program`.
///
/// VYRE_IR_HOTSPOTS HIGH (rewrite.rs:4-13 / optimizer.rs:68): the
/// previous signature took `&Program` and always allocated a new
/// `Vec<Node>` + called `with_rewritten_entry` even when every node
/// was unchanged; the caller then paid a second O(N) structural
/// `PartialEq` through `PassResult::from_programs`.
///
/// The rewrite now returns `(Program, bool)` — the identity path
/// returns the original program untouched (zero allocations) with
/// `changed = false`, and the mutated path returns the rewritten
/// program with `changed = true`. Callers build `PassResult`
/// directly from the flag, skipping the comparison.
pub(crate) fn rewrite_program(
    program: Program,
    mut expr: impl FnMut(&Expr) -> Option<Expr>,
) -> (Program, bool) {
    match rewrite_nodes_cow(program.entry(), &mut expr) {
        Cow::Borrowed(_) => (program, false),
        Cow::Owned(entry) => (program.with_rewritten_entry(entry), true),
    }
}

fn rewrite_nodes_cow<'a>(
    nodes: &'a [Node],
    expr: &mut impl FnMut(&Expr) -> Option<Expr>,
) -> Cow<'a, [Node]> {
    let mut rewritten: Option<Vec<Node>> = None;
    for (index, node) in nodes.iter().enumerate() {
        match rewrite_node_cow(node, expr) {
            Cow::Borrowed(_) if rewritten.is_none() => {}
            Cow::Borrowed(borrowed) => rewritten
                .as_mut()
                .expect("initialized by first Cow::Owned below")
                .push(borrowed.clone()),
            Cow::Owned(owned) => {
                let out = rewritten.get_or_insert_with(|| nodes[..index].to_vec());
                out.push(owned);
            }
        }
    }
    rewritten.map_or(Cow::Borrowed(nodes), Cow::Owned)
}

fn rewrite_node_cow<'a>(
    node: &'a Node,
    expr: &mut impl FnMut(&Expr) -> Option<Expr>,
) -> Cow<'a, Node> {
    match node {
        Node::Let { name, value } => match rewrite_expr(value, expr) {
            Cow::Borrowed(_) => Cow::Borrowed(node),
            Cow::Owned(value) => Cow::Owned(Node::let_bind(name, value)),
        },
        Node::Assign { name, value } => match rewrite_expr(value, expr) {
            Cow::Borrowed(_) => Cow::Borrowed(node),
            Cow::Owned(value) => Cow::Owned(Node::assign(name, value)),
        },
        Node::Store {
            buffer,
            index,
            value,
        } => {
            let idx = rewrite_expr(index, expr);
            let val = rewrite_expr(value, expr);
            if matches!((&idx, &val), (Cow::Borrowed(_), Cow::Borrowed(_))) {
                Cow::Borrowed(node)
            } else {
                Cow::Owned(Node::store(buffer, idx.into_owned(), val.into_owned()))
            }
        }
        Node::If {
            cond,
            then,
            otherwise,
        } => {
            let c = rewrite_expr(cond, expr);
            let t = rewrite_nodes_cow(then, expr);
            let o = rewrite_nodes_cow(otherwise, expr);
            if matches!(
                (&c, &t, &o),
                (Cow::Borrowed(_), Cow::Borrowed(_), Cow::Borrowed(_))
            ) {
                Cow::Borrowed(node)
            } else {
                Cow::Owned(Node::if_then_else(
                    c.into_owned(),
                    t.into_owned(),
                    o.into_owned(),
                ))
            }
        }
        Node::Loop {
            var,
            from,
            to,
            body,
        } => {
            let f = rewrite_expr(from, expr);
            let t = rewrite_expr(to, expr);
            let b = rewrite_nodes_cow(body, expr);
            if matches!(
                (&f, &t, &b),
                (Cow::Borrowed(_), Cow::Borrowed(_), Cow::Borrowed(_))
            ) {
                Cow::Borrowed(node)
            } else {
                Cow::Owned(Node::loop_for(
                    var,
                    f.into_owned(),
                    t.into_owned(),
                    b.into_owned(),
                ))
            }
        }
        Node::Block(body) => match rewrite_nodes_cow(body, expr) {
            Cow::Borrowed(_) => Cow::Borrowed(node),
            Cow::Owned(body) => Cow::Owned(Node::block(body)),
        },
        Node::Trap { address, tag } => match rewrite_expr(address, expr) {
            Cow::Borrowed(_) => Cow::Borrowed(node),
            Cow::Owned(address) => Cow::Owned(Node::Trap {
                address: Box::new(address),
                tag: tag.clone(),
            }),
        },
        Node::Region {
            generator,
            source_region,
            body,
        } => match rewrite_nodes_cow(body, expr) {
            Cow::Borrowed(_) => Cow::Borrowed(node),
            Cow::Owned(body) => Cow::Owned(Node::Region {
                generator: generator.clone(),
                source_region: source_region.clone(),
                body: Arc::new(body),
            }),
        },
        Node::Return
        | Node::Barrier
        | Node::IndirectDispatch { .. }
        | Node::AsyncLoad { .. }
        | Node::AsyncStore { .. }
        | Node::AsyncWait { .. }
        | Node::Resume { .. }
        | Node::Opaque(_) => Cow::Borrowed(node),
    }
}

pub(crate) fn rewrite_expr<'a>(
    expr: &'a Expr,
    transform: &mut impl FnMut(&Expr) -> Option<Expr>,
) -> Cow<'a, Expr> {
    let rewritten = match expr {
        Expr::Load { buffer, index } => match rewrite_expr(index, transform) {
            Cow::Borrowed(_) => Cow::Borrowed(expr),
            Cow::Owned(index) => Cow::Owned(Expr::Load {
                buffer: buffer.clone(),
                index: Box::new(index),
            }),
        },
        Expr::BinOp { op, left, right } => rewrite_binary(
            expr,
            *op,
            rewrite_expr(left, transform),
            rewrite_expr(right, transform),
        ),
        Expr::UnOp { op, operand } => match rewrite_expr(operand, transform) {
            Cow::Borrowed(_) => Cow::Borrowed(expr),
            Cow::Owned(operand) => Cow::Owned(Expr::UnOp {
                op: op.clone(),
                operand: Box::new(operand),
            }),
        },
        Expr::Call { op_id, args } => match rewrite_args(args, transform) {
            Cow::Borrowed(_) => Cow::Borrowed(expr),
            Cow::Owned(args) => Cow::Owned(Expr::Call {
                op_id: op_id.clone(),
                args,
            }),
        },
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => rewrite_select(
            expr,
            rewrite_expr(cond, transform),
            rewrite_expr(true_val, transform),
            rewrite_expr(false_val, transform),
        ),
        Expr::Cast { target, value } => match rewrite_expr(value, transform) {
            Cow::Borrowed(_) => Cow::Borrowed(expr),
            Cow::Owned(value) => Cow::Owned(Expr::Cast {
                target: target.clone(),
                value: Box::new(value),
            }),
        },
        Expr::Fma { a, b, c } => rewrite_fma(
            expr,
            rewrite_expr(a, transform),
            rewrite_expr(b, transform),
            rewrite_expr(c, transform),
        ),
        Expr::Atomic {
            op,
            buffer,
            index,
            expected,
            value,
        } => rewrite_atomic(
            expr,
            op,
            buffer,
            index,
            expected.as_deref(),
            value,
            transform,
        ),
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
        | Expr::SubgroupSize => Cow::Borrowed(expr),
        Expr::SubgroupBallot { cond } => match rewrite_expr(cond, transform) {
            Cow::Borrowed(_) => Cow::Borrowed(expr),
            Cow::Owned(cond) => Cow::Owned(Expr::SubgroupBallot {
                cond: Box::new(cond),
            }),
        },
        Expr::SubgroupShuffle { value, lane } => {
            let v = rewrite_expr(value, transform);
            let l = rewrite_expr(lane, transform);
            match (v, l) {
                (Cow::Borrowed(_), Cow::Borrowed(_)) => Cow::Borrowed(expr),
                (v, l) => Cow::Owned(Expr::SubgroupShuffle {
                    value: Box::new(v.into_owned()),
                    lane: Box::new(l.into_owned()),
                }),
            }
        }
        Expr::SubgroupAdd { value } => match rewrite_expr(value, transform) {
            Cow::Borrowed(_) => Cow::Borrowed(expr),
            Cow::Owned(value) => Cow::Owned(Expr::SubgroupAdd {
                value: Box::new(value),
            }),
        },
        Expr::Opaque(_) => Cow::Borrowed(expr),
    };
    if let Some(transformed) = transform(rewritten.as_ref()) {
        Cow::Owned(transformed)
    } else {
        rewritten
    }
}

#[inline]
fn rewrite_binary<'a>(
    original: &'a Expr,
    op: BinOp,
    left: Cow<'a, Expr>,
    right: Cow<'a, Expr>,
) -> Cow<'a, Expr> {
    if matches!((&left, &right), (Cow::Borrowed(_), Cow::Borrowed(_))) {
        return Cow::Borrowed(original);
    }
    Cow::Owned(Expr::BinOp {
        op,
        left: Box::new(left.into_owned()),
        right: Box::new(right.into_owned()),
    })
}

#[inline]
fn rewrite_fma<'a>(
    original: &'a Expr,
    a: Cow<'a, Expr>,
    b: Cow<'a, Expr>,
    c: Cow<'a, Expr>,
) -> Cow<'a, Expr> {
    if matches!(
        (&a, &b, &c),
        (Cow::Borrowed(_), Cow::Borrowed(_), Cow::Borrowed(_))
    ) {
        return Cow::Borrowed(original);
    }
    Cow::Owned(Expr::Fma {
        a: Box::new(a.into_owned()),
        b: Box::new(b.into_owned()),
        c: Box::new(c.into_owned()),
    })
}

#[inline]
fn rewrite_select<'a>(
    original: &'a Expr,
    cond: Cow<'a, Expr>,
    true_val: Cow<'a, Expr>,
    false_val: Cow<'a, Expr>,
) -> Cow<'a, Expr> {
    if matches!(
        (&cond, &true_val, &false_val),
        (Cow::Borrowed(_), Cow::Borrowed(_), Cow::Borrowed(_))
    ) {
        return Cow::Borrowed(original);
    }
    Cow::Owned(Expr::Select {
        cond: Box::new(cond.into_owned()),
        true_val: Box::new(true_val.into_owned()),
        false_val: Box::new(false_val.into_owned()),
    })
}

#[inline]
fn rewrite_atomic<'a>(
    original: &'a Expr,
    op: &crate::ir::AtomicOp,
    buffer: &crate::ir::Ident,
    index: &'a Expr,
    expected: Option<&'a Expr>,
    value: &'a Expr,
    transform: &mut impl FnMut(&Expr) -> Option<Expr>,
) -> Cow<'a, Expr> {
    let index = rewrite_expr(index, transform);
    let expected = expected.map(|expected| rewrite_expr(expected, transform));
    let value = rewrite_expr(value, transform);
    if matches!(&index, Cow::Borrowed(_))
        && expected
            .as_ref()
            .is_none_or(|expected| matches!(expected, Cow::Borrowed(_)))
        && matches!(&value, Cow::Borrowed(_))
    {
        return Cow::Borrowed(original);
    }
    Cow::Owned(Expr::Atomic {
        op: *op,
        buffer: buffer.clone(),
        index: Box::new(index.into_owned()),
        expected: expected.map(|expected| Box::new(expected.into_owned())),
        value: Box::new(value.into_owned()),
    })
}

#[inline]
fn rewrite_args<'a>(
    args: &'a [Expr],
    transform: &mut impl FnMut(&Expr) -> Option<Expr>,
) -> Cow<'a, [Expr]> {
    let mut rewritten: Option<Vec<Expr>> = None;
    for (index, arg) in args.iter().enumerate() {
        match rewrite_expr(arg, transform) {
            Cow::Borrowed(_) if rewritten.is_none() => {}
            // VYRE_IR_HOTSPOTS CRIT (cse/impl_csectx.rs:357-373): once
            // any prior arg was rewritten, subsequent unchanged args
            // are cloned into the result vec. That is the correct
            // behavior — we still need to materialize the vector —
            // but the clone of an unchanged arg is now the only
            // unavoidable cost (the rewrite_args of rewrite.rs
            // predates the CSE copy and is on the optimizer hot path).
            Cow::Borrowed(borrowed) => rewritten
                .as_mut()
                .expect("initialized by first Cow::Owned below")
                .push(borrowed.clone()),
            Cow::Owned(owned) => {
                let out = rewritten.get_or_insert_with(|| args[..index].to_vec());
                out.push(owned);
            }
        }
    }
    rewritten.map_or(Cow::Borrowed(args), Cow::Owned)
}

pub(crate) fn literal_binop(op: BinOp, left: &Expr, right: &Expr) -> Option<Expr> {
    match (left, right) {
        (Expr::LitU32(left), Expr::LitU32(right)) => eval_u32_binop(op, *left, *right),
        (Expr::LitI32(left), Expr::LitI32(right)) => eval_i32_binop(op, *left, *right),
        (Expr::LitBool(left), Expr::LitBool(right)) => eval_bool_binop(op, *left, *right),
        _ => None,
    }
}

pub(crate) fn literal_unop(op: UnOp, operand: &Expr) -> Option<Expr> {
    match operand {
        Expr::LitU32(value) => eval_u32_unop(op, *value),
        Expr::LitI32(value) => eval_i32_unop(op, *value),
        Expr::LitBool(value) => eval_bool_unop(op, *value),
        _ => None,
    }
}

fn eval_u32_binop(op: BinOp, left: u32, right: u32) -> Option<Expr> {
    let folded = match op {
        BinOp::Add => Expr::u32(left.wrapping_add(right)),
        BinOp::Sub => Expr::u32(left.wrapping_sub(right)),
        BinOp::Mul => Expr::u32(left.wrapping_mul(right)),
        BinOp::Div => {
            if right == 0 {
                return None;
            }
            Expr::u32(left / right)
        }
        BinOp::Mod => {
            if right == 0 {
                return None;
            }
            Expr::u32(left % right)
        }
        BinOp::BitAnd => Expr::u32(left & right),
        BinOp::BitOr => Expr::u32(left | right),
        BinOp::BitXor => Expr::u32(left ^ right),
        BinOp::Shl => Expr::u32(left << (right & 31)),
        BinOp::Shr => Expr::u32(left >> (right & 31)),
        BinOp::Eq => Expr::bool(left == right),
        BinOp::Ne => Expr::bool(left != right),
        BinOp::Lt => Expr::bool(left < right),
        BinOp::Gt => Expr::bool(left > right),
        BinOp::Le => Expr::bool(left <= right),
        BinOp::Ge => Expr::bool(left >= right),
        BinOp::And => Expr::bool(left != 0 && right != 0),
        BinOp::Or => Expr::bool(left != 0 || right != 0),
        BinOp::AbsDiff => Expr::u32(left.abs_diff(right)),
        BinOp::Min => Expr::u32(left.min(right)),
        BinOp::Max => Expr::u32(left.max(right)),
        _ => return None,
    };
    Some(folded)
}

fn eval_i32_binop(op: BinOp, left: i32, right: i32) -> Option<Expr> {
    let folded = match op {
        BinOp::Add => Expr::i32(left.wrapping_add(right)),
        BinOp::Sub => Expr::i32(left.wrapping_sub(right)),
        BinOp::Mul => Expr::i32(left.wrapping_mul(right)),
        BinOp::Div => {
            if right == 0 {
                return None;
            }
            Expr::i32(left.wrapping_div(right))
        }
        BinOp::Mod => {
            if right == 0 {
                return None;
            }
            Expr::i32(left.wrapping_rem(right))
        }
        BinOp::BitAnd => Expr::i32(left & right),
        BinOp::BitOr => Expr::i32(left | right),
        BinOp::BitXor => Expr::i32(left ^ right),
        BinOp::Shl => Expr::i32(left.wrapping_shl((right as u32) & 31)),
        BinOp::Shr => Expr::i32(left.wrapping_shr((right as u32) & 31)),
        BinOp::Eq => Expr::bool(left == right),
        BinOp::Ne => Expr::bool(left != right),
        BinOp::Lt => Expr::bool(left < right),
        BinOp::Gt => Expr::bool(left > right),
        BinOp::Le => Expr::bool(left <= right),
        BinOp::Ge => Expr::bool(left >= right),
        BinOp::And => Expr::bool(left != 0 && right != 0),
        BinOp::Or => Expr::bool(left != 0 || right != 0),
        BinOp::AbsDiff => Expr::u32(left.abs_diff(right)),
        BinOp::Min => Expr::i32(left.min(right)),
        BinOp::Max => Expr::i32(left.max(right)),
        _ => return None,
    };
    Some(folded)
}

fn eval_bool_binop(op: BinOp, left: bool, right: bool) -> Option<Expr> {
    Some(match op {
        BinOp::Eq => Expr::bool(left == right),
        BinOp::Ne => Expr::bool(left != right),
        BinOp::And => Expr::bool(left && right),
        BinOp::Or => Expr::bool(left || right),
        _ => return None,
    })
}

fn eval_u32_unop(op: UnOp, value: u32) -> Option<Expr> {
    Some(match op {
        UnOp::Negate => Expr::u32(0u32.wrapping_sub(value)),
        UnOp::BitNot => Expr::u32(!value),
        UnOp::LogicalNot => Expr::bool(value == 0),
        UnOp::Popcount => Expr::u32(value.count_ones()),
        UnOp::Clz => Expr::u32(value.leading_zeros()),
        UnOp::Ctz => Expr::u32(value.trailing_zeros()),
        UnOp::ReverseBits => Expr::u32(value.reverse_bits()),
        _ => return None,
    })
}

fn eval_i32_unop(op: UnOp, value: i32) -> Option<Expr> {
    Some(match op {
        UnOp::Negate => Expr::i32(0i32.wrapping_sub(value)),
        UnOp::BitNot => Expr::i32(!value),
        UnOp::LogicalNot => Expr::bool(value == 0),
        UnOp::Popcount => Expr::i32(value.count_ones() as i32),
        UnOp::Clz => Expr::i32(value.leading_zeros() as i32),
        UnOp::Ctz => Expr::i32(value.trailing_zeros() as i32),
        UnOp::ReverseBits => Expr::i32(value.reverse_bits()),
        _ => return None,
    })
}

fn eval_bool_unop(op: UnOp, value: bool) -> Option<Expr> {
    Some(match op {
        UnOp::LogicalNot => Expr::bool(!value),
        _ => return None,
    })
}
