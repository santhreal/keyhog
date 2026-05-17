use crate::ir::{Expr, Ident, Node, Program};
use crate::optimizer::{vyre_pass, PassResult};
use smallvec::SmallVec;
use std::borrow::Cow;
use std::ops::Range;
use std::sync::Arc;

const MAX_UNROLL_TRIP_COUNT: u32 = 16;
const MAX_UNROLLED_BODY_COST: u32 = 64;

/// Expand loops with small compile-time-known trip counts.
#[derive(Debug, Default)]
#[vyre_pass(
    name = "loop_unroll",
    requires = ["const_fold"],
    invalidates = ["const_fold", "value_numbering", "fusion"],
    analyze = "always"
)]
pub struct LoopUnroll;

impl LoopUnroll {
    /// Replace bounded `from..to` loops with repeated bodies when the trip
    /// count is compile-time-known and small enough to avoid code-size blowup.
    #[must_use]
    pub fn transform(program: Program) -> PassResult {
        match rewrite_nodes(program.entry()) {
            Cow::Borrowed(_) => PassResult::unchanged(program),
            Cow::Owned(entry) => PassResult {
                program: program.with_rewritten_entry(entry),
                changed: true,
            },
        }
    }}

fn rewrite_nodes(nodes: &[Node]) -> Cow<'_, [Node]> {
    let mut rewritten: Option<Vec<Node>> = None;
    for (index, node) in nodes.iter().enumerate() {
        match rewrite_node(node) {
            Cow::Borrowed(_) if rewritten.is_none() => {}
            Cow::Borrowed(borrowed) => {
                if let Some(out) = rewritten.as_mut() {
                    out.extend_from_slice(borrowed);
                }
            }
            Cow::Owned(owned) => {
                let out = rewritten.get_or_insert_with(|| nodes[..index].to_vec());
                out.extend(owned);
            }
        }
    }
    rewritten.map_or(Cow::Borrowed(nodes), Cow::Owned)
}

fn rewrite_node(node: &Node) -> Cow<'_, [Node]> {
    match node {
        Node::Loop {
            var,
            from,
            to,
            body,
        } => {
            let rewritten_body = rewrite_nodes(body);
            let body_slice = rewritten_body.as_ref();
            if let Some(values) = unroll_values(from, to, body_slice) {
                if body_writes_loop_var(body_slice, var) {
                    let rebuilt = rebuild_loop_if_needed(node, rewritten_body);
                    return rebuilt.map_or_else(
                        || Cow::Borrowed(std::slice::from_ref(node)),
                        |n| Cow::Owned(vec![n]),
                    );
                }
                let isolate_iteration_scope = body_declares_locals(body_slice);
                let trip_count = values.len();
                let mut out = Vec::with_capacity(if isolate_iteration_scope {
                    trip_count
                } else {
                    body_slice.len().saturating_mul(trip_count)
                });
                for value in values {
                    let replacement = Expr::u32(value);
                    if isolate_iteration_scope {
                        out.push(Node::block(substitute_nodes(body_slice, var, &replacement)));
                    } else {
                        for item in body_slice {
                            out.push(substitute_node(item, var, &replacement));
                        }
                    }
                }
                Cow::Owned(out)
            } else {
                let rebuilt = rebuild_loop_if_needed(node, rewritten_body);
                rebuilt.map_or_else(
                    || Cow::Borrowed(std::slice::from_ref(node)),
                    |n| Cow::Owned(vec![n]),
                )
            }
        }
        Node::If {
            cond,
            then,
            otherwise,
        } => {
            let rewritten_then = rewrite_nodes(then);
            let rewritten_otherwise = rewrite_nodes(otherwise);
            if matches!(
                (&rewritten_then, &rewritten_otherwise),
                (Cow::Borrowed(_), Cow::Borrowed(_))
            ) {
                Cow::Borrowed(std::slice::from_ref(node))
            } else {
                Cow::Owned(vec![Node::if_then_else(
                    cond.clone(),
                    rewritten_then.into_owned(),
                    rewritten_otherwise.into_owned(),
                )])
            }
        }
        Node::Block(body) => match rewrite_nodes(body) {
            Cow::Borrowed(_) => Cow::Borrowed(std::slice::from_ref(node)),
            Cow::Owned(body) => Cow::Owned(vec![Node::block(body)]),
        },
        Node::Region {
            generator,
            source_region,
            body,
        } => match rewrite_nodes(body) {
            Cow::Borrowed(_) => Cow::Borrowed(std::slice::from_ref(node)),
            Cow::Owned(body) => Cow::Owned(vec![Node::Region {
                generator: generator.clone(),
                source_region: source_region.clone(),
                body: Arc::new(body),
            }]),
        },
        _ => Cow::Borrowed(std::slice::from_ref(node)),
    }
}

fn rebuild_loop_if_needed(node: &Node, body: Cow<'_, [Node]>) -> Option<Node> {
    let Node::Loop { var, from, to, .. } = node else {
        return None;
    };
    match body {
        Cow::Borrowed(_) => None,
        Cow::Owned(body) => Some(Node::loop_for(var, from.clone(), to.clone(), body)),
    }
}

fn unroll_values(from: &Expr, to: &Expr, body: &[Node]) -> Option<Range<u32>> {
    let from = literal_u32(from)?;
    let to = literal_u32(to)?;
    let trip_count = to.checked_sub(from)?;
    if trip_count == 0 || trip_count > MAX_UNROLL_TRIP_COUNT {
        return None;
    }
    let body_cost = unroll_body_cost(body)?;
    if body_cost.saturating_mul(trip_count) > MAX_UNROLLED_BODY_COST {
        return None;
    }
    Some(from..to)
}

fn literal_u32(expr: &Expr) -> Option<u32> {
    match expr {
        Expr::LitU32(value) => Some(*value),
        Expr::LitI32(value) => u32::try_from(*value).ok(),
        _ => None,
    }
}

fn body_writes_loop_var(nodes: &[Node], var: &Ident) -> bool {
    nodes.iter().any(|node| match node {
        Node::Let { name, .. } | Node::Assign { name, .. } => name == var,
        Node::If {
            then, otherwise, ..
        } => body_writes_loop_var(then, var) || body_writes_loop_var(otherwise, var),
        Node::Loop {
            var: inner, body, ..
        } => inner != var && body_writes_loop_var(body, var),
        Node::Block(body) => body_writes_loop_var(body, var),
        Node::Region { body, .. } => body_writes_loop_var(body, var),
        _ => false,
    })
}

fn body_declares_locals(nodes: &[Node]) -> bool {
    nodes.iter().any(|node| match node {
        Node::Let { .. } => true,
        Node::If {
            then, otherwise, ..
        } => body_declares_locals(then) || body_declares_locals(otherwise),
        Node::Block(body) => body_declares_locals(body),
        Node::Loop { .. } | Node::Region { .. } => false,
        _ => false,
    })
}

fn unroll_body_cost(nodes: &[Node]) -> Option<u32> {
    nodes.iter().try_fold(0u32, |acc, node| {
        Some(acc.saturating_add(node_unroll_cost(node)?))
    })
}

fn node_unroll_cost(node: &Node) -> Option<u32> {
    match node {
        Node::Let { value, .. } | Node::Assign { value, .. } => {
            Some(1u32.saturating_add(expr_unroll_cost(value)))
        }
        Node::Store { index, value, .. } => Some(
            2u32.saturating_add(expr_unroll_cost(index))
                .saturating_add(expr_unroll_cost(value)),
        ),
        Node::If {
            cond,
            then,
            otherwise,
        } => Some(
            4u32.saturating_add(expr_unroll_cost(cond))
                .saturating_add(unroll_body_cost(then)?)
                .saturating_add(unroll_body_cost(otherwise)?),
        ),
        Node::Loop { from, to, body, .. } => Some(
            6u32.saturating_add(expr_unroll_cost(from))
                .saturating_add(expr_unroll_cost(to))
                .saturating_add(unroll_body_cost(body)?),
        ),
        Node::Block(body) => unroll_body_cost(body),
        Node::Region { body, .. } => unroll_body_cost(body),
        Node::Return
        | Node::Barrier { .. }
        | Node::IndirectDispatch { .. }
        | Node::AsyncLoad { .. }
        | Node::AsyncStore { .. }
        | Node::AsyncWait { .. }
        | Node::Trap { .. }
        | Node::Resume { .. }
        | Node::Opaque(_) => None,
    }
}

fn expr_unroll_cost(expr: &Expr) -> u32 {
    let mut cost = 0u32;
    let mut stack: SmallVec<[&Expr; 16]> = SmallVec::new();
    stack.push(expr);
    while let Some(expr) = stack.pop() {
        cost = cost.saturating_add(1);
        push_expr_children(expr, &mut stack);
    }
    cost
}

fn push_expr_children<'a>(expr: &'a Expr, stack: &mut SmallVec<[&'a Expr; 16]>) {
    match expr {
        Expr::Load { index, .. } | Expr::UnOp { operand: index, .. } => stack.push(index),
        Expr::BinOp { left, right, .. } => {
            stack.push(left);
            stack.push(right);
        }
        Expr::Call { args, .. } => stack.extend(args),
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => {
            stack.push(cond);
            stack.push(true_val);
            stack.push(false_val);
        }
        Expr::Cast { value, .. } => stack.push(value),
        Expr::Fma { a, b, c } => {
            stack.push(a);
            stack.push(b);
            stack.push(c);
        }
        Expr::Atomic {
            index,
            expected,
            value,
            ..
        } => {
            stack.push(index);
            if let Some(expected) = expected {
                stack.push(expected);
            }
            stack.push(value);
        }
        Expr::SubgroupBallot { cond } => stack.push(cond),
        Expr::SubgroupShuffle { value, lane } => {
            stack.push(value);
            stack.push(lane);
        }
        Expr::SubgroupAdd { value } => stack.push(value),
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
        | Expr::SubgroupSize
        | Expr::Opaque(_) => {}
    }
}

fn substitute_node(node: &Node, var: &Ident, replacement: &Expr) -> Node {
    match node {
        Node::Let { name, value } => Node::let_bind(name, substitute_expr(value, var, replacement)),
        Node::Assign { name, value } => {
            Node::assign(name, substitute_expr(value, var, replacement))
        }
        Node::Store {
            buffer,
            index,
            value,
        } => Node::store(
            buffer,
            substitute_expr(index, var, replacement),
            substitute_expr(value, var, replacement),
        ),
        Node::If {
            cond,
            then,
            otherwise,
        } => Node::if_then_else(
            substitute_expr(cond, var, replacement),
            substitute_nodes(then, var, replacement),
            substitute_nodes(otherwise, var, replacement),
        ),
        Node::Loop {
            var: inner,
            from,
            to,
            body,
        } => {
            let from = substitute_expr(from, var, replacement);
            let to = substitute_expr(to, var, replacement);
            let body = if inner == var {
                body.clone()
            } else {
                substitute_nodes(body, var, replacement)
            };
            Node::loop_for(inner, from, to, body)
        }
        Node::Block(body) => Node::block(substitute_nodes(body, var, replacement)),
        Node::Region {
            generator,
            source_region,
            body,
        } => Node::Region {
            generator: generator.clone(),
            source_region: source_region.clone(),
            body: Arc::new(substitute_nodes(body, var, replacement)),
        },
        Node::AsyncLoad {
            source,
            destination,
            offset,
            size,
            tag,
        } => Node::AsyncLoad {
            source: source.clone(),
            destination: destination.clone(),
            offset: Box::new(substitute_expr(offset, var, replacement)),
            size: Box::new(substitute_expr(size, var, replacement)),
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
            offset: Box::new(substitute_expr(offset, var, replacement)),
            size: Box::new(substitute_expr(size, var, replacement)),
            tag: tag.clone(),
        },
        Node::Trap { address, tag } => Node::Trap {
            address: Box::new(substitute_expr(address, var, replacement)),
            tag: tag.clone(),
        },
        Node::IndirectDispatch { .. }
        | Node::AsyncWait { .. }
        | Node::Resume { .. }
        | Node::Return
        | Node::Barrier { .. }
        | Node::Opaque(_) => node.clone(),
    }
}

fn substitute_nodes(nodes: &[Node], var: &Ident, replacement: &Expr) -> Vec<Node> {
    nodes
        .iter()
        .map(|node| substitute_node(node, var, replacement))
        .collect()
}

fn substitute_expr(expr: &Expr, var: &Ident, replacement: &Expr) -> Expr {
    match expr {
        Expr::Var(name) if name == var => replacement.clone(),
        Expr::Load { buffer, index } => {
            Expr::load(buffer, substitute_expr(index, var, replacement))
        }
        Expr::BinOp { op, left, right } => Expr::BinOp {
            op: *op,
            left: Box::new(substitute_expr(left, var, replacement)),
            right: Box::new(substitute_expr(right, var, replacement)),
        },
        Expr::UnOp { op, operand } => Expr::UnOp {
            op: op.clone(),
            operand: Box::new(substitute_expr(operand, var, replacement)),
        },
        Expr::Call { op_id, args } => Expr::call(
            op_id,
            args.iter()
                .map(|arg| substitute_expr(arg, var, replacement))
                .collect(),
        ),
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => Expr::select(
            substitute_expr(cond, var, replacement),
            substitute_expr(true_val, var, replacement),
            substitute_expr(false_val, var, replacement),
        ),
        Expr::Cast { target, value } => {
            Expr::cast(target.clone(), substitute_expr(value, var, replacement))
        }
        Expr::Fma { a, b, c } => Expr::fma(
            substitute_expr(a, var, replacement),
            substitute_expr(b, var, replacement),
            substitute_expr(c, var, replacement),
        ),
        Expr::Atomic {
            op,
            buffer,
            index,
            expected,
            value,
            ordering,
        } => Expr::Atomic {
            op: *op,
            buffer: buffer.clone(),
            index: Box::new(substitute_expr(index, var, replacement)),
            expected: expected
                .as_ref()
                .map(|expr| Box::new(substitute_expr(expr, var, replacement))),
            value: Box::new(substitute_expr(value, var, replacement)),
            ordering: *ordering,
        },
        Expr::SubgroupBallot { cond } => {
            Expr::subgroup_ballot(substitute_expr(cond, var, replacement))
        }
        Expr::SubgroupShuffle { value, lane } => Expr::subgroup_shuffle(
            substitute_expr(value, var, replacement),
            substitute_expr(lane, var, replacement),
        ),
        Expr::SubgroupAdd { value } => Expr::subgroup_add(substitute_expr(value, var, replacement)),
        _ => expr.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BufferDecl, DataType};
    use crate::optimizer::passes::const_fold::ConstFold;
    use crate::optimizer::{PassScheduler, ProgramPassKind};

    #[test]
    fn unrolls_small_u32_loop_and_substitutes_index() {
        let program = Program::wrapped(
            vec![BufferDecl::read_write("out", 0, DataType::U32)],
            [1, 1, 1],
            vec![Node::loop_for(
                "i",
                Expr::u32(0),
                Expr::u32(3),
                vec![Node::store(
                    "out",
                    Expr::var("i"),
                    Expr::add(Expr::var("i"), Expr::u32(1)),
                )],
            )],
        );

        let optimized = PassScheduler::with_passes(vec![
            ProgramPassKind::new(ConstFold),
            ProgramPassKind::new(LoopUnroll),
        ])
        .run(program)
        .expect("Fix: loop unroll should converge");

        let body = crate::test_util::region_body(&optimized);
        assert_eq!(body.len(), 3);
        for (index, node) in body.iter().enumerate() {
            assert!(matches!(
                node,
                Node::Store {
                    index: Expr::LitU32(i),
                    value: Expr::LitU32(v),
                    ..
                } if *i == index as u32 && *v == index as u32 + 1
            ));
        }
    }

    #[test]
    fn keeps_large_loop_bounded() {
        fn large_loop_program() -> Program {
            Program::wrapped(
                Vec::new(),
                [1, 1, 1],
                vec![Node::loop_for(
                    "i",
                    Expr::u32(0),
                    Expr::u32(MAX_UNROLL_TRIP_COUNT + 1),
                    vec![Node::let_bind("x", Expr::var("i"))],
                )],
            )
        }

        let program = large_loop_program();
        let expected = large_loop_program();
        let optimized = LoopUnroll::transform(program).program;
        assert_eq!(optimized, expected);
    }

    #[test]
    fn unrolls_tiny_loop_above_old_trip_limit_when_cost_is_small() {
        let program = Program::wrapped(
            vec![BufferDecl::read_write("out", 0, DataType::U32)],
            [1, 1, 1],
            vec![Node::loop_for(
                "i",
                Expr::u32(0),
                Expr::u32(12),
                vec![Node::store("out", Expr::var("i"), Expr::u32(1))],
            )],
        );

        let optimized = LoopUnroll::transform(program).program;
        let body = crate::test_util::region_body(&optimized);
        assert_eq!(body.len(), 12);
        assert!(matches!(
            &body[11],
            Node::Store {
                index: Expr::LitU32(11),
                ..
            }
        ));
    }

    #[test]
    fn keeps_small_trip_loop_when_body_cost_would_bloat_ir() {
        let expensive_value = (0..20).fold(Expr::var("x"), |acc, n| Expr::add(acc, Expr::u32(n)));
        let program = Program::wrapped(
            Vec::new(),
            [1, 1, 1],
            vec![Node::loop_for(
                "i",
                Expr::u32(0),
                Expr::u32(4),
                vec![Node::let_bind("x", expensive_value)],
            )],
        );

        let result = LoopUnroll::transform(program);
        assert!(!result.changed);
        let body = crate::test_util::region_body(&result.program);
        assert!(matches!(&body[0], Node::Loop { .. }));
    }

    #[test]
    fn keeps_loop_with_barrier_as_control_boundary() {
        let program = Program::wrapped(
            Vec::new(),
            [1, 1, 1],
            vec![Node::loop_for(
                "i",
                Expr::u32(0),
                Expr::u32(2),
                vec![Node::barrier()],
            )],
        );

        let result = LoopUnroll::transform(program);
        assert!(!result.changed);
        let body = crate::test_util::region_body(&result.program);
        assert!(matches!(&body[0], Node::Loop { .. }));
    }

    #[test]
    fn does_not_substitute_shadowed_inner_loop_body() {
        let program = Program::wrapped(
            Vec::new(),
            [1, 1, 1],
            vec![Node::loop_for(
                "i",
                Expr::u32(0),
                Expr::u32(2),
                vec![Node::loop_for(
                    "i",
                    Expr::var("i"),
                    Expr::u32(4),
                    vec![Node::let_bind("x", Expr::var("i"))],
                )],
            )],
        );

        let optimized = LoopUnroll::transform(program).program;
        let body = crate::test_util::region_body(&optimized);
        assert_eq!(body.len(), 2);
        assert!(matches!(
            &body[0],
            Node::Loop {
                from: Expr::LitU32(0),
                body,
                ..
            } if matches!(&body[0], Node::Let { value: Expr::Var(name), .. } if name == "i")
        ));
    }
}
