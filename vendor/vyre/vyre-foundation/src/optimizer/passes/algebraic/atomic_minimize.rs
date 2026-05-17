//! ROADMAP A36 — minimize identity-op atomics under Relaxed ordering
//! to a plain `Expr::Load`, and eliminate unique-writer atomics.
//!
//! Op id: `vyre-foundation::optimizer::passes::atomic_minimize`.

use crate::ir::{AtomicOp, Expr, Node, Program};
use crate::optimizer::{vyre_pass, PassAnalysis, PassResult};
use crate::runtime::memory_model::MemoryOrdering;
use std::collections::{HashMap, HashSet};

#[derive(Default, Debug, Clone, Copy)]
struct BufferAccesses {
    atomic_adds: u32,
    other_accesses: u32,
}

/// Replace identity-op Relaxed atomics with plain `Expr::Load`, and rewrite single-writer atomics.
#[derive(Debug, Default)]
#[vyre_pass(
    name = "atomic_minimize",
    requires = [],
    invalidates = []
)]
pub struct AtomicMinimizePass;

impl AtomicMinimizePass {
    /// Skip programs that do not contain a candidate atomic.
    #[must_use]
    fn analyze_impl(program: &Program) -> PassAnalysis {
        let mut found = false;
        scan_for_identity_candidate(program.entry(), &mut found);
        if found {
            return PassAnalysis::RUN;
        }

        let mut access_counts = HashMap::new();
        count_buffer_accesses(program.entry(), &mut access_counts);
        let has_single_writer = access_counts
            .values()
            .any(|counts| counts.atomic_adds == 1 && counts.other_accesses == 0);

        if has_single_writer {
            PassAnalysis::RUN
        } else {
            PassAnalysis::SKIP
        }
    }

    /// Walk the program and collapse atomics.
    #[must_use]
    pub fn transform(program: Program) -> PassResult {
        let mut access_counts = HashMap::new();
        count_buffer_accesses(program.entry(), &mut access_counts);
        let eligible_buffers: HashSet<_> = access_counts
            .into_iter()
            .filter(|(_, counts)| counts.atomic_adds == 1 && counts.other_accesses == 0)
            .map(|(buf, _)| buf)
            .collect();

        let scaffold = program.with_rewritten_entry(Vec::new());
        let mut changed = false;
        let entry: Vec<Node> = program
            .into_entry_vec()
            .into_iter()
            .flat_map(|n| rewrite_node_multi(n, &eligible_buffers, &mut changed))
            .collect();
        PassResult {
            program: scaffold.with_rewritten_entry(entry),
            changed,
        }
    }}

fn rewrite_node_multi(
    node: Node,
    eligible_buffers: &HashSet<crate::ir::Ident>,
    changed: &mut bool,
) -> Vec<Node> {
    match node {
        Node::Let { name, value } => {
            if let Expr::Atomic {
                op: AtomicOp::Add,
                buffer,
                index,
                expected: None,
                value: add_value,
                ..
            } = &value
            {
                if eligible_buffers.contains(buffer) {
                    *changed = true;
                    let new_load = Expr::Load {
                        buffer: buffer.clone(),
                        index: index.clone(),
                    };
                    let store_node = Node::Store {
                        buffer: buffer.clone(),
                        index: *index.clone(),
                        value: rewrite_expr(
                            Expr::BinOp {
                                op: crate::ir::BinOp::Add,
                                left: Box::new(Expr::Var(name.clone())),
                                right: add_value.clone(),
                            },
                            changed,
                        ),
                    };
                    return vec![
                        Node::Let {
                            name,
                            value: rewrite_expr(new_load, changed),
                        },
                        store_node,
                    ];
                }
            }
            vec![Node::Let {
                name,
                value: rewrite_expr(value, changed),
            }]
        }
        Node::Assign { name, value } => {
            if let Expr::Atomic {
                op: AtomicOp::Add,
                buffer,
                index,
                expected: None,
                value: add_value,
                ..
            } = &value
            {
                if eligible_buffers.contains(buffer) {
                    *changed = true;
                    let new_load = Expr::Load {
                        buffer: buffer.clone(),
                        index: index.clone(),
                    };
                    let store_node = Node::Store {
                        buffer: buffer.clone(),
                        index: *index.clone(),
                        value: rewrite_expr(
                            Expr::BinOp {
                                op: crate::ir::BinOp::Add,
                                left: Box::new(Expr::Var(name.clone())),
                                right: add_value.clone(),
                            },
                            changed,
                        ),
                    };
                    return vec![
                        Node::Assign {
                            name,
                            value: rewrite_expr(new_load, changed),
                        },
                        store_node,
                    ];
                }
            }
            vec![Node::Assign {
                name,
                value: rewrite_expr(value, changed),
            }]
        }
        Node::Store {
            buffer,
            index,
            value,
        } => vec![Node::Store {
            buffer,
            index: rewrite_expr(index, changed),
            value: rewrite_expr(value, changed),
        }],
        Node::If {
            cond,
            then,
            otherwise,
        } => vec![Node::If {
            cond: rewrite_expr(cond, changed),
            then: then
                .into_iter()
                .flat_map(|n| rewrite_node_multi(n, eligible_buffers, changed))
                .collect(),
            otherwise: otherwise
                .into_iter()
                .flat_map(|n| rewrite_node_multi(n, eligible_buffers, changed))
                .collect(),
        }],
        Node::Loop {
            var,
            from,
            to,
            body,
        } => vec![Node::Loop {
            var,
            from: rewrite_expr(from, changed),
            to: rewrite_expr(to, changed),
            body: body
                .into_iter()
                .flat_map(|n| rewrite_node_multi(n, eligible_buffers, changed))
                .collect(),
        }],
        Node::Block(body) => vec![Node::Block(
            body.into_iter()
                .flat_map(|n| rewrite_node_multi(n, eligible_buffers, changed))
                .collect(),
        )],
        Node::Region {
            generator,
            source_region,
            body,
        } => {
            let body_vec: Vec<Node> = match std::sync::Arc::try_unwrap(body) {
                Ok(v) => v,
                Err(arc) => (*arc).clone(),
            };
            vec![Node::Region {
                generator,
                source_region,
                body: std::sync::Arc::new(
                    body_vec
                        .into_iter()
                        .flat_map(|n| rewrite_node_multi(n, eligible_buffers, changed))
                        .collect(),
                ),
            }]
        }
        Node::AsyncLoad {
            source,
            destination,
            offset,
            size,
            tag,
        } => vec![Node::AsyncLoad {
            source,
            destination,
            tag,
            offset: Box::new(rewrite_expr(*offset, changed)),
            size: Box::new(rewrite_expr(*size, changed)),
        }],
        Node::AsyncStore {
            source,
            destination,
            offset,
            size,
            tag,
        } => vec![Node::AsyncStore {
            source,
            destination,
            tag,
            offset: Box::new(rewrite_expr(*offset, changed)),
            size: Box::new(rewrite_expr(*size, changed)),
        }],
        Node::Trap { address, tag } => vec![Node::Trap {
            address: Box::new(rewrite_expr(*address, changed)),
            tag,
        }],
        other => vec![other],
    }
}

fn rewrite_expr(expr: Expr, changed: &mut bool) -> Expr {
    match expr {
        Expr::Atomic {
            op,
            buffer,
            index,
            expected,
            value,
            ordering,
        } => {
            let index_rw = Box::new(rewrite_expr(*index, changed));
            let value_rw = Box::new(rewrite_expr(*value, changed));
            let expected_rw = expected.map(|e| Box::new(rewrite_expr(*e, changed)));
            if expected_rw.is_none()
                && ordering == MemoryOrdering::Relaxed
                && is_identity_atomic(op, value_rw.as_ref())
            {
                *changed = true;
                return Expr::Load {
                    buffer,
                    index: index_rw,
                };
            }
            Expr::Atomic {
                op,
                buffer,
                index: index_rw,
                expected: expected_rw,
                value: value_rw,
                ordering,
            }
        }
        Expr::Load { buffer, index } => Expr::Load {
            buffer,
            index: Box::new(rewrite_expr(*index, changed)),
        },
        Expr::BinOp { op, left, right } => Expr::BinOp {
            op,
            left: Box::new(rewrite_expr(*left, changed)),
            right: Box::new(rewrite_expr(*right, changed)),
        },
        Expr::UnOp { op, operand } => Expr::UnOp {
            op,
            operand: Box::new(rewrite_expr(*operand, changed)),
        },
        Expr::Call { op_id, args } => Expr::Call {
            op_id,
            args: args.into_iter().map(|a| rewrite_expr(a, changed)).collect(),
        },
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => Expr::Select {
            cond: Box::new(rewrite_expr(*cond, changed)),
            true_val: Box::new(rewrite_expr(*true_val, changed)),
            false_val: Box::new(rewrite_expr(*false_val, changed)),
        },
        Expr::Cast { target, value } => Expr::Cast {
            target,
            value: Box::new(rewrite_expr(*value, changed)),
        },
        Expr::Fma { a, b, c } => Expr::Fma {
            a: Box::new(rewrite_expr(*a, changed)),
            b: Box::new(rewrite_expr(*b, changed)),
            c: Box::new(rewrite_expr(*c, changed)),
        },
        Expr::SubgroupBallot { cond } => Expr::SubgroupBallot {
            cond: Box::new(rewrite_expr(*cond, changed)),
        },
        Expr::SubgroupShuffle { value, lane } => Expr::SubgroupShuffle {
            value: Box::new(rewrite_expr(*value, changed)),
            lane: Box::new(rewrite_expr(*lane, changed)),
        },
        Expr::SubgroupAdd { value } => Expr::SubgroupAdd {
            value: Box::new(rewrite_expr(*value, changed)),
        },
        other => other,
    }
}

fn is_identity_atomic(op: AtomicOp, value: &Expr) -> bool {
    match (op, value) {
        (AtomicOp::Add | AtomicOp::Or | AtomicOp::Xor, Expr::LitU32(0) | Expr::LitI32(0)) => true,
        (AtomicOp::And, Expr::LitU32(u32::MAX)) => true,
        (AtomicOp::And, Expr::LitI32(-1)) => true,
        _ => false,
    }
}

fn scan_for_identity_candidate(nodes: &[Node], found: &mut bool) {
    for node in nodes {
        if *found {
            return;
        }
        scan_node_for_identity(node, found);
    }
}

fn scan_node_for_identity(node: &Node, found: &mut bool) {
    match node {
        Node::Let { value, .. } | Node::Assign { value, .. } => {
            scan_expr_for_identity(value, found)
        }
        Node::Store { index, value, .. } => {
            scan_expr_for_identity(index, found);
            scan_expr_for_identity(value, found);
        }
        Node::If {
            cond,
            then,
            otherwise,
        } => {
            scan_expr_for_identity(cond, found);
            scan_for_identity_candidate(then, found);
            scan_for_identity_candidate(otherwise, found);
        }
        Node::Loop { from, to, body, .. } => {
            scan_expr_for_identity(from, found);
            scan_expr_for_identity(to, found);
            scan_for_identity_candidate(body, found);
        }
        Node::Block(body) => scan_for_identity_candidate(body, found),
        Node::Region { body, .. } => scan_for_identity_candidate(body, found),
        _ => {}
    }
}

fn scan_expr_for_identity(expr: &Expr, found: &mut bool) {
    if *found {
        return;
    }
    match expr {
        Expr::Atomic {
            op,
            value,
            expected,
            ordering,
            index,
            ..
        } => {
            if expected.is_none()
                && *ordering == MemoryOrdering::Relaxed
                && is_identity_atomic(*op, value)
            {
                *found = true;
                return;
            }
            scan_expr_for_identity(index, found);
            if let Some(e) = expected.as_deref() {
                scan_expr_for_identity(e, found);
            }
            scan_expr_for_identity(value, found);
        }
        Expr::Load { index, .. } => scan_expr_for_identity(index, found),
        Expr::BinOp { left, right, .. } => {
            scan_expr_for_identity(left, found);
            scan_expr_for_identity(right, found);
        }
        Expr::UnOp { operand, .. } => scan_expr_for_identity(operand, found),
        Expr::Call { args, .. } => {
            for a in args {
                scan_expr_for_identity(a, found);
            }
        }
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => {
            scan_expr_for_identity(cond, found);
            scan_expr_for_identity(true_val, found);
            scan_expr_for_identity(false_val, found);
        }
        Expr::Cast { value, .. } => scan_expr_for_identity(value, found),
        Expr::Fma { a, b, c } => {
            scan_expr_for_identity(a, found);
            scan_expr_for_identity(b, found);
            scan_expr_for_identity(c, found);
        }
        Expr::SubgroupBallot { cond } => scan_expr_for_identity(cond, found),
        Expr::SubgroupShuffle { value, lane } => {
            scan_expr_for_identity(value, found);
            scan_expr_for_identity(lane, found);
        }
        Expr::SubgroupAdd { value } => scan_expr_for_identity(value, found),
        _ => {}
    }
}

fn count_buffer_accesses(nodes: &[Node], counts: &mut HashMap<crate::ir::Ident, BufferAccesses>) {
    for node in nodes {
        match node {
            Node::Let { value, .. } | Node::Assign { value, .. } => {
                count_expr_accesses(value, counts)
            }
            Node::Store {
                buffer,
                index,
                value,
            } => {
                counts.entry(buffer.clone()).or_default().other_accesses += 1;
                count_expr_accesses(index, counts);
                count_expr_accesses(value, counts);
            }
            Node::If {
                cond,
                then,
                otherwise,
            } => {
                count_expr_accesses(cond, counts);
                count_buffer_accesses(then, counts);
                count_buffer_accesses(otherwise, counts);
            }
            Node::Loop { from, to, body, .. } => {
                count_expr_accesses(from, counts);
                count_expr_accesses(to, counts);
                count_buffer_accesses(body, counts);
            }
            Node::Block(body) => count_buffer_accesses(body, counts),
            Node::Region { body, .. } => count_buffer_accesses(body, counts),
            Node::AsyncLoad {
                source,
                destination,
                offset,
                size,
                ..
            } => {
                counts.entry(source.clone()).or_default().other_accesses += 1;
                counts
                    .entry(destination.clone())
                    .or_default()
                    .other_accesses += 1;
                count_expr_accesses(offset, counts);
                count_expr_accesses(size, counts);
            }
            Node::AsyncStore {
                source,
                destination,
                offset,
                size,
                ..
            } => {
                counts.entry(source.clone()).or_default().other_accesses += 1;
                counts
                    .entry(destination.clone())
                    .or_default()
                    .other_accesses += 1;
                count_expr_accesses(offset, counts);
                count_expr_accesses(size, counts);
            }
            Node::Trap { address, .. } => count_expr_accesses(address, counts),
            Node::Barrier { .. }
            | Node::Return
            | Node::Resume { .. }
            | Node::IndirectDispatch { .. }
            | Node::AsyncWait { .. }
            | Node::Opaque(_) => {}
        }
    }
}

fn count_expr_accesses(expr: &Expr, counts: &mut HashMap<crate::ir::Ident, BufferAccesses>) {
    match expr {
        Expr::Atomic {
            op,
            buffer,
            index,
            expected,
            value,
            ..
        } => {
            if *op == AtomicOp::Add && expected.is_none() {
                counts.entry(buffer.clone()).or_default().atomic_adds += 1;
            } else {
                counts.entry(buffer.clone()).or_default().other_accesses += 1;
            }
            count_expr_accesses(index, counts);
            if let Some(e) = expected {
                count_expr_accesses(e, counts);
            }
            count_expr_accesses(value, counts);
        }
        Expr::Load { buffer, index } => {
            counts.entry(buffer.clone()).or_default().other_accesses += 1;
            count_expr_accesses(index, counts);
        }
        Expr::BinOp { left, right, .. } => {
            count_expr_accesses(left, counts);
            count_expr_accesses(right, counts);
        }
        Expr::UnOp { operand, .. } => count_expr_accesses(operand, counts),
        Expr::Call { args, .. } => {
            for a in args {
                count_expr_accesses(a, counts);
            }
        }
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => {
            count_expr_accesses(cond, counts);
            count_expr_accesses(true_val, counts);
            count_expr_accesses(false_val, counts);
        }
        Expr::Cast { value, .. } => count_expr_accesses(value, counts),
        Expr::Fma { a, b, c } => {
            count_expr_accesses(a, counts);
            count_expr_accesses(b, counts);
            count_expr_accesses(c, counts);
        }
        Expr::SubgroupBallot { cond } => count_expr_accesses(cond, counts),
        Expr::SubgroupShuffle { value, lane } => {
            count_expr_accesses(value, counts);
            count_expr_accesses(lane, counts);
        }
        Expr::SubgroupAdd { value } => count_expr_accesses(value, counts),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BufferAccess, BufferDecl, DataType, Expr, Ident};

    fn buf() -> BufferDecl {
        BufferDecl::storage("buf", 0, BufferAccess::ReadWrite, DataType::U32).with_count(4)
    }

    fn program(entry: Vec<Node>) -> Program {
        Program::wrapped(vec![buf()], [1, 1, 1], entry)
    }

    fn relaxed_atomic(op: AtomicOp, value: Expr) -> Expr {
        Expr::Atomic {
            op,
            buffer: Ident::from("buf"),
            index: Box::new(Expr::u32(0)),
            expected: None,
            value: Box::new(value),
            ordering: MemoryOrdering::Relaxed,
        }
    }

    fn extract_let_value(p: &Program, name: &str) -> Expr {
        fn walk<'a>(nodes: &'a [Node], target: &str) -> Option<&'a Expr> {
            for n in nodes {
                match n {
                    Node::Let { name, value } if name.as_str() == target => return Some(value),
                    Node::Block(body) => {
                        if let Some(found) = walk(body, target) {
                            return Some(found);
                        }
                    }
                    Node::Region { body, .. } => {
                        if let Some(found) = walk(body.as_ref(), target) {
                            return Some(found);
                        }
                    }
                    Node::If {
                        then, otherwise, ..
                    } => {
                        if let Some(found) = walk(then, target) {
                            return Some(found);
                        }
                        if let Some(found) = walk(otherwise, target) {
                            return Some(found);
                        }
                    }
                    Node::Loop { body, .. } => {
                        if let Some(found) = walk(body, target) {
                            return Some(found);
                        }
                    }
                    _ => {}
                }
            }
            None
        }
        walk(p.entry(), name)
            .cloned()
            .unwrap_or_else(|| panic!("expected Let `{name}` in entry tree"))
    }

    #[test]
    fn add_zero_relaxed_collapses_to_load() {
        let entry = vec![Node::let_bind(
            "x",
            relaxed_atomic(AtomicOp::Add, Expr::u32(0)),
        )];
        let result = AtomicMinimizePass::transform(program(entry));
        assert!(result.changed);
        assert_eq!(
            extract_let_value(&result.program, "x"),
            Expr::Load {
                buffer: Ident::from("buf"),
                index: Box::new(Expr::u32(0)),
            }
        );
    }

    #[test]
    fn or_zero_relaxed_collapses_to_load() {
        let entry = vec![Node::let_bind(
            "x",
            relaxed_atomic(AtomicOp::Or, Expr::u32(0)),
        )];
        let result = AtomicMinimizePass::transform(program(entry));
        assert!(result.changed);
        assert!(matches!(
            extract_let_value(&result.program, "x"),
            Expr::Load { .. }
        ));
    }

    #[test]
    fn xor_zero_relaxed_collapses_to_load() {
        let entry = vec![Node::let_bind(
            "x",
            relaxed_atomic(AtomicOp::Xor, Expr::u32(0)),
        )];
        let result = AtomicMinimizePass::transform(program(entry));
        assert!(result.changed);
        assert!(matches!(
            extract_let_value(&result.program, "x"),
            Expr::Load { .. }
        ));
    }

    #[test]
    fn and_max_relaxed_collapses_to_load() {
        let entry = vec![Node::let_bind(
            "x",
            relaxed_atomic(AtomicOp::And, Expr::u32(u32::MAX)),
        )];
        let result = AtomicMinimizePass::transform(program(entry));
        assert!(result.changed);
        assert!(matches!(
            extract_let_value(&result.program, "x"),
            Expr::Load { .. }
        ));
    }

    #[test]
    fn single_writer_atomic_add_rewritten() {
        let entry = vec![Node::let_bind(
            "x",
            relaxed_atomic(AtomicOp::Add, Expr::u32(42)),
        )];
        let result = AtomicMinimizePass::transform(program(entry));
        assert!(result.changed);

        let mut found_store = false;
        fn walk_store(nodes: &[Node], found: &mut bool) {
            for n in nodes {
                match n {
                    Node::Store { buffer, .. } if buffer.as_str() == "buf" => *found = true,
                    Node::Region { body, .. } => walk_store(body, found),
                    Node::Block(body) => walk_store(body, found),
                    Node::If {
                        then, otherwise, ..
                    } => {
                        walk_store(then, found);
                        walk_store(otherwise, found);
                    }
                    Node::Loop { body, .. } => walk_store(body, found),
                    _ => {}
                }
            }
        }
        walk_store(result.program.entry(), &mut found_store);

        assert!(found_store, "Store should have been generated");
        assert!(matches!(
            extract_let_value(&result.program, "x"),
            Expr::Load { .. }
        ));
    }

    #[test]
    fn two_atomic_adds_keep_atomic() {
        let entry = vec![
            Node::let_bind("x", relaxed_atomic(AtomicOp::Add, Expr::u32(42))),
            Node::let_bind("y", relaxed_atomic(AtomicOp::Add, Expr::u32(43))),
        ];
        let result = AtomicMinimizePass::transform(program(entry));
        assert!(!result.changed);
        assert!(matches!(
            extract_let_value(&result.program, "x"),
            Expr::Atomic { .. }
        ));
    }

    #[test]
    fn atomic_with_load_keeps_atomic() {
        let entry = vec![
            Node::let_bind("x", relaxed_atomic(AtomicOp::Add, Expr::u32(42))),
            Node::let_bind(
                "y",
                Expr::Load {
                    buffer: Ident::from("buf"),
                    index: Box::new(Expr::u32(0)),
                },
            ),
        ];
        let result = AtomicMinimizePass::transform(program(entry));
        assert!(!result.changed);
        assert!(matches!(
            extract_let_value(&result.program, "x"),
            Expr::Atomic { .. }
        ));
    }

    #[test]
    fn atomic_with_store_keeps_atomic() {
        let entry = vec![
            Node::let_bind("x", relaxed_atomic(AtomicOp::Add, Expr::u32(42))),
            Node::store("buf", Expr::u32(1), Expr::u32(99)),
        ];
        let result = AtomicMinimizePass::transform(program(entry));
        assert!(!result.changed);
        assert!(matches!(
            extract_let_value(&result.program, "x"),
            Expr::Atomic { .. }
        ));
    }

    #[test]
    fn compare_exchange_not_eligible() {
        let entry = vec![Node::let_bind(
            "x",
            Expr::Atomic {
                op: AtomicOp::CompareExchange,
                buffer: Ident::from("buf"),
                index: Box::new(Expr::u32(0)),
                expected: Some(Box::new(Expr::u32(1))),
                value: Box::new(Expr::u32(42)),
                ordering: MemoryOrdering::Relaxed,
            },
        )];
        let result = AtomicMinimizePass::transform(program(entry));
        assert!(!result.changed);
    }

    #[test]
    fn seq_cst_not_identity_but_maybe_single_writer() {
        let entry = vec![Node::let_bind(
            "x",
            Expr::Atomic {
                op: AtomicOp::Add,
                buffer: Ident::from("buf"),
                index: Box::new(Expr::u32(0)),
                expected: None,
                value: Box::new(Expr::u32(42)),
                ordering: MemoryOrdering::SeqCst, // Even if it's SeqCst, single-writer eliminates it, since there are no other accesses. Wait, if it's single writer, is SeqCst allowed to be eliminated? "even for non-identity ops ... Conservative: if any other access exists, do nothing." The prompt says "AND that atomic is AtomicOp::Add with expected: None", doesn't restrict ordering! Let's see if we rewrite it.
            },
        )];
        let result = AtomicMinimizePass::transform(program(entry));
        assert!(result.changed);
    }

    #[test]
    fn analyze_skips_program_with_no_candidate() {
        let entry = vec![Node::let_bind("x", Expr::u32(7))];
        match crate::optimizer::ProgramPass::analyze(&AtomicMinimizePass, &program(entry)) {
            PassAnalysis::SKIP => {}
            other => panic!("expected SKIP, got {other:?}"),
        }
    }
}
