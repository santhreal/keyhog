use crate::ir::{Expr, Node, Program};
use crate::optimizer::{fingerprint_program, vyre_pass, PassAnalysis, PassResult};
use rustc_hash::{FxHashMap, FxHashSet};
use std::sync::Arc;

/// Remove buffers whose contents cannot contribute to observable output.
#[derive(Debug, Default)]
#[vyre_pass(name = "dead_buffer_elim", requires = [], invalidates = ["buffer_layout"])]
pub struct DeadBufferElim;

impl DeadBufferElim {
    /// Decide whether this pass should run.
    #[must_use]
    #[inline]
    pub fn analyze(program: &Program) -> PassAnalysis {
        if live_buffers(program).len() == program.buffers().len() {
            PassAnalysis::SKIP
        } else {
            PassAnalysis::RUN
        }
    }

    /// Remove dead buffer declarations and stores to dead buffers.
    #[must_use]
    pub fn transform(program: Program) -> PassResult {
        let live = live_buffers(&program);
        let buffers = program
            .buffers()
            .iter()
            .filter(|buffer| live.contains(buffer.name.as_ref()))
            .cloned()
            .collect::<Vec<_>>();
        let entry = filter_nodes(program.entry(), &live);

        let optimized = Program::wrapped(buffers, program.workgroup_size(), entry)
            .with_optional_entry_op_id(program.entry_op_id().map(ToOwned::to_owned))
            .with_non_composable_with_self(program.is_non_composable_with_self());
        PassResult::from_programs(&program, optimized)
    }

    /// Fingerprint this pass's visible input.
    #[must_use]
    #[inline]
    pub fn fingerprint(program: &Program) -> u64 {
        fingerprint_program(program)
    }
}

fn live_buffers(program: &Program) -> FxHashSet<Arc<str>> {
    compute_live_buffers(program)
}

/// O(N) single backward pass replacing the old O(B·N) fixpoint.
fn compute_live_buffers(program: &Program) -> FxHashSet<Arc<str>> {
    if program.entry().iter().any(node_contains_opaque) {
        return program
            .buffers()
            .iter()
            .map(|buffer| Arc::clone(&buffer.name))
            .collect();
    }

    let mut live = program
        .buffers()
        .iter()
        .filter(|buffer| buffer.is_output() || buffer.is_pipeline_live_out())
        .map(|buffer| Arc::clone(&buffer.name))
        .collect::<FxHashSet<_>>();

    let mut pending: FxHashMap<Arc<str>, Vec<Vec<Arc<str>>>> = FxHashMap::default();

    for node in program.entry().iter().rev() {
        mark_live_backward(node, &mut live, &mut pending);
    }

    // Indirect dispatch count buffers are live regardless of dataflow.
    for node in program.entry() {
        mark_indirect_buffers(node, &mut live);
    }

    live
}

fn mark_live_backward(
    node: &Node,
    live: &mut FxHashSet<Arc<str>>,
    pending: &mut FxHashMap<Arc<str>, Vec<Vec<Arc<str>>>>,
) {
    match node {
        Node::Store {
            buffer,
            index,
            value,
        } => {
            if live.contains(buffer.as_str()) {
                let mut reads = Vec::new();
                collect_expr_buffers_to_vec(index, &mut reads);
                collect_expr_buffers_to_vec(value, &mut reads);
                for r in reads {
                    make_live(live, pending, r);
                }
            } else {
                let mut reads = Vec::new();
                collect_expr_buffers_to_vec(index, &mut reads);
                collect_expr_buffers_to_vec(value, &mut reads);
                pending
                    .entry(Arc::from(buffer.as_str()))
                    .or_default()
                    .push(reads);
            }
        }
        Node::AsyncStore {
            source,
            destination,
            offset,
            size,
            ..
        } => {
            if live.contains(destination.as_str()) {
                make_live(live, pending, Arc::from(source.as_str()));
                let mut reads = Vec::new();
                collect_expr_buffers_to_vec(offset, &mut reads);
                collect_expr_buffers_to_vec(size, &mut reads);
                for r in reads {
                    make_live(live, pending, r);
                }
            } else {
                let mut reads = Vec::new();
                collect_expr_buffers_to_vec(offset, &mut reads);
                collect_expr_buffers_to_vec(size, &mut reads);
                reads.push(Arc::from(source.as_str()));
                pending
                    .entry(Arc::from(destination.as_str()))
                    .or_default()
                    .push(reads);
            }
        }
        Node::AsyncLoad {
            source,
            destination,
            offset,
            size,
            ..
        } => {
            if live.contains(destination.as_str()) {
                make_live(live, pending, Arc::from(source.as_str()));
                let mut reads = Vec::new();
                collect_expr_buffers_to_vec(offset, &mut reads);
                collect_expr_buffers_to_vec(size, &mut reads);
                for r in reads {
                    make_live(live, pending, r);
                }
            } else {
                let mut reads = Vec::new();
                collect_expr_buffers_to_vec(offset, &mut reads);
                collect_expr_buffers_to_vec(size, &mut reads);
                reads.push(Arc::from(source.as_str()));
                pending
                    .entry(Arc::from(destination.as_str()))
                    .or_default()
                    .push(reads);
            }
        }
        Node::Region { body, .. } => {
            for node in body.iter().rev() {
                mark_live_backward(node, live, pending);
            }
        }
        Node::If {
            cond,
            then,
            otherwise,
        } => {
            for node in otherwise.iter().rev() {
                mark_live_backward(node, live, pending);
            }
            for node in then.iter().rev() {
                mark_live_backward(node, live, pending);
            }
            let mut reads = Vec::new();
            collect_expr_buffers_to_vec(cond, &mut reads);
            for r in reads {
                make_live(live, pending, r);
            }
        }
        Node::Loop { from, to, body, .. } => {
            for node in body.iter().rev() {
                mark_live_backward(node, live, pending);
            }
            let mut reads = Vec::new();
            collect_expr_buffers_to_vec(to, &mut reads);
            for r in reads {
                make_live(live, pending, r);
            }
            let mut reads = Vec::new();
            collect_expr_buffers_to_vec(from, &mut reads);
            for r in reads {
                make_live(live, pending, r);
            }
        }
        Node::Block(nodes) => {
            for node in nodes.iter().rev() {
                mark_live_backward(node, live, pending);
            }
        }
        _ => {}
    }
}

fn make_live(
    live: &mut FxHashSet<Arc<str>>,
    pending: &mut FxHashMap<Arc<str>, Vec<Vec<Arc<str>>>>,
    buffer: Arc<str>,
) {
    if live.insert(buffer.clone()) {
        if let Some(pending_reads) = pending.remove(&buffer) {
            for reads in pending_reads {
                for r in reads {
                    make_live(live, pending, r);
                }
            }
        }
    }
}

fn collect_expr_buffers_to_vec(expr: &Expr, out: &mut Vec<Arc<str>>) {
    match expr {
        Expr::Load { buffer, index } => {
            out.push(Arc::from(buffer.as_str()));
            collect_expr_buffers_to_vec(index, out);
        }
        Expr::BufLen { buffer } => {
            out.push(Arc::from(buffer.as_str()));
        }
        Expr::Atomic {
            buffer,
            index,
            expected,
            value,
            ..
        } => {
            out.push(Arc::from(buffer.as_str()));
            collect_expr_buffers_to_vec(index, out);
            if let Some(expected) = expected {
                collect_expr_buffers_to_vec(expected, out);
            }
            collect_expr_buffers_to_vec(value, out);
        }
        Expr::BinOp { left, right, .. } => {
            collect_expr_buffers_to_vec(left, out);
            collect_expr_buffers_to_vec(right, out);
        }
        Expr::UnOp { operand, .. } | Expr::Cast { value: operand, .. } => {
            collect_expr_buffers_to_vec(operand, out);
        }
        Expr::Fma { a, b, c } => {
            collect_expr_buffers_to_vec(a, out);
            collect_expr_buffers_to_vec(b, out);
            collect_expr_buffers_to_vec(c, out);
        }
        Expr::Call { args, .. } => {
            for arg in args {
                collect_expr_buffers_to_vec(arg, out);
            }
        }
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => {
            collect_expr_buffers_to_vec(cond, out);
            collect_expr_buffers_to_vec(true_val, out);
            collect_expr_buffers_to_vec(false_val, out);
        }
        _ => {}
    }
}

fn live_buffers_legacy(program: &Program) -> FxHashSet<Arc<str>> {
    if program.entry().iter().any(node_contains_opaque) {
        return program
            .buffers()
            .iter()
            .map(|buffer| Arc::clone(&buffer.name))
            .collect();
    }

    let mut live = program
        .buffers()
        .iter()
        .filter(|buffer| buffer.is_output() || buffer.is_pipeline_live_out())
        .map(|buffer| Arc::clone(&buffer.name))
        .collect::<FxHashSet<_>>();

    let mut changed = true;
    while changed {
        changed = false;
        for node in program.entry() {
            changed |= mark_live_dependencies(node, &mut live);
        }
    }

    for node in program.entry() {
        mark_indirect_buffers(node, &mut live);
    }
    live
}

fn mark_live_dependencies(node: &Node, live: &mut FxHashSet<Arc<str>>) -> bool {
    match node {
        Node::Store {
            buffer,
            index,
            value,
        } if live.contains(buffer.as_str()) => {
            let before = live.len();
            collect_expr_buffers(index, live);
            collect_expr_buffers(value, live);
            live.len() != before
        }
        Node::AsyncStore {
            source,
            destination,
            offset,
            size,
            ..
        } if live.contains(destination.as_str()) => {
            let before = live.len();
            live.insert(Arc::from(source.as_str()));
            collect_expr_buffers(offset, live);
            collect_expr_buffers(size, live);
            live.len() != before
        }
        Node::AsyncLoad {
            source,
            destination,
            offset,
            size,
            ..
        } if live.contains(destination.as_str()) => {
            let before = live.len();
            live.insert(Arc::from(source.as_str()));
            collect_expr_buffers(offset, live);
            collect_expr_buffers(size, live);
            live.len() != before
        }
        Node::Region { body, .. } => mark_live_dependencies_in_nodes(body, live),
        Node::If {
            cond,
            then,
            otherwise,
        } => {
            let before = live.len();
            collect_expr_buffers(cond, live);
            let changed = mark_live_dependencies_in_nodes(then, live)
                || mark_live_dependencies_in_nodes(otherwise, live);
            changed || live.len() != before
        }
        Node::Loop { from, to, body, .. } => {
            let before = live.len();
            collect_expr_buffers(from, live);
            collect_expr_buffers(to, live);
            mark_live_dependencies_in_nodes(body, live) || live.len() != before
        }
        Node::Block(nodes) => mark_live_dependencies_in_nodes(nodes, live),
        _ => false,
    }
}

fn mark_live_dependencies_in_nodes(nodes: &[Node], live: &mut FxHashSet<Arc<str>>) -> bool {
    nodes.iter().fold(false, |changed, node| {
        mark_live_dependencies(node, live) || changed
    })
}

fn mark_indirect_buffers(node: &Node, live: &mut FxHashSet<Arc<str>>) {
    match node {
        Node::IndirectDispatch { count_buffer, .. } => {
            live.insert(Arc::from(count_buffer.as_str()));
        }
        Node::If {
            then, otherwise, ..
        } => {
            for node in then.iter().chain(otherwise) {
                mark_indirect_buffers(node, live);
            }
        }
        Node::Loop { body, .. } | Node::Block(body) => {
            for node in body {
                mark_indirect_buffers(node, live);
            }
        }
        Node::Region { body, .. } => {
            for node in body.iter() {
                mark_indirect_buffers(node, live);
            }
        }
        _ => {}
    }
}

fn collect_expr_buffers(expr: &Expr, live: &mut FxHashSet<Arc<str>>) {
    match expr {
        Expr::Load { buffer, index } => {
            live.insert(Arc::from(buffer.as_str()));
            collect_expr_buffers(index, live);
        }
        Expr::BufLen { buffer } => {
            live.insert(Arc::from(buffer.as_str()));
        }
        Expr::Atomic {
            buffer,
            index,
            expected,
            value,
            ..
        } => {
            live.insert(Arc::from(buffer.as_str()));
            collect_expr_buffers(index, live);
            if let Some(expected) = expected {
                collect_expr_buffers(expected, live);
            }
            collect_expr_buffers(value, live);
        }
        Expr::BinOp { left, right, .. } => {
            collect_expr_buffers(left, live);
            collect_expr_buffers(right, live);
        }
        Expr::UnOp { operand, .. } | Expr::Cast { value: operand, .. } => {
            collect_expr_buffers(operand, live);
        }
        Expr::Fma { a, b, c } => {
            collect_expr_buffers(a, live);
            collect_expr_buffers(b, live);
            collect_expr_buffers(c, live);
        }
        Expr::Call { args, .. } => {
            for arg in args {
                collect_expr_buffers(arg, live);
            }
        }
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => {
            collect_expr_buffers(cond, live);
            collect_expr_buffers(true_val, live);
            collect_expr_buffers(false_val, live);
        }
        _ => {}
    }
}

fn node_contains_opaque(node: &Node) -> bool {
    match node {
        Node::Opaque(_) => true,
        Node::Let { value, .. } | Node::Assign { value, .. } => expr_contains_opaque(value),
        Node::Store { index, value, .. } => {
            expr_contains_opaque(index) || expr_contains_opaque(value)
        }
        Node::If {
            cond,
            then,
            otherwise,
        } => {
            expr_contains_opaque(cond)
                || then.iter().any(node_contains_opaque)
                || otherwise.iter().any(node_contains_opaque)
        }
        Node::Loop { from, to, body, .. } => {
            expr_contains_opaque(from)
                || expr_contains_opaque(to)
                || body.iter().any(node_contains_opaque)
        }
        Node::Block(nodes) => nodes.iter().any(node_contains_opaque),
        Node::AsyncLoad { offset, size, .. } | Node::AsyncStore { offset, size, .. } => {
            expr_contains_opaque(offset) || expr_contains_opaque(size)
        }
        _ => false,
    }
}

fn expr_contains_opaque(expr: &Expr) -> bool {
    match expr {
        Expr::Opaque(_) => true,
        Expr::Load { index, .. } => expr_contains_opaque(index),
        Expr::BinOp { left, right, .. } => {
            expr_contains_opaque(left) || expr_contains_opaque(right)
        }
        Expr::UnOp { operand, .. } | Expr::Cast { value: operand, .. } => {
            expr_contains_opaque(operand)
        }
        Expr::Call { args, .. } => args.iter().any(expr_contains_opaque),
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => {
            expr_contains_opaque(cond)
                || expr_contains_opaque(true_val)
                || expr_contains_opaque(false_val)
        }
        Expr::Fma { a, b, c } => {
            expr_contains_opaque(a) || expr_contains_opaque(b) || expr_contains_opaque(c)
        }
        Expr::Atomic {
            index,
            expected,
            value,
            ..
        } => {
            expr_contains_opaque(index)
                || expected.as_deref().is_some_and(expr_contains_opaque)
                || expr_contains_opaque(value)
        }
        _ => false,
    }
}

fn filter_nodes(nodes: &[Node], live: &FxHashSet<Arc<str>>) -> Vec<Node> {
    nodes
        .iter()
        .filter_map(|node| filter_node(node, live))
        .collect()
}

fn filter_node(node: &Node, live: &FxHashSet<Arc<str>>) -> Option<Node> {
    match node {
        Node::Store { buffer, .. } if !live.contains(buffer.as_ref()) => None,
        Node::AsyncStore { destination, .. } if !live.contains(destination.as_str()) => None,
        Node::AsyncLoad { destination, .. } if !live.contains(destination.as_str()) => None,
        Node::Region {
            generator,
            source_region,
            body,
        } => Some(Node::Region {
            generator: generator.clone(),
            source_region: source_region.clone(),
            body: Arc::new(filter_nodes(body, live)),
        }),
        Node::If {
            cond,
            then,
            otherwise,
        } => Some(Node::if_then_else(
            cond.clone(),
            filter_nodes(then, live),
            filter_nodes(otherwise, live),
        )),
        Node::Loop {
            var,
            from,
            to,
            body,
        } => Some(Node::loop_for(
            var,
            from.clone(),
            to.clone(),
            filter_nodes(body, live),
        )),
        Node::Block(nodes) => Some(Node::block(filter_nodes(nodes, live))),
        other => Some(other.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BufferDecl, DataType};
    use crate::optimizer::{PassKind, PassScheduler};

    #[test]
    fn unread_buffer_removed() {
        let optimized = run(sample_program(false));
        assert!(optimized.buffer("scratch").is_none());
    }

    #[test]
    fn output_buffer_preserved() {
        let optimized = run(sample_program(false));
        assert!(optimized.buffer("out").is_some());
    }

    fn run(program: Program) -> Program {
        PassScheduler::with_passes(vec![PassKind::DeadBufferElim(DeadBufferElim)])
            .run(program)
            .expect("Fix: dead buffer elimination should converge")
    }

    fn sample_program(read_scratch: bool) -> Program {
        Program::wrapped(
            vec![
                BufferDecl::output("out", 0, DataType::U32).with_count(1),
                BufferDecl::read_write("scratch", 1, DataType::U32).with_count(1),
            ],
            [1, 1, 1],
            if read_scratch {
                vec![
                    Node::store("scratch", Expr::u32(0), Expr::u32(999)),
                    Node::store("out", Expr::u32(0), Expr::load("scratch", Expr::u32(0))),
                ]
            } else {
                vec![
                    Node::store("scratch", Expr::u32(0), Expr::u32(999)),
                    Node::store("out", Expr::u32(0), Expr::u32(7)),
                ]
            },
        )
    }
}
