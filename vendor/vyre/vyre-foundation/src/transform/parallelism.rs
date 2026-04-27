//! Shared-nothing parallelism detection for IR dispatch planning.
//!
//! The analysis is conservative: a statement may enter a parallel dispatch
//! group only when its writable buffer set is disjoint from every other
//! statement in the group. Any write-after-write conflict forms a serial
//! boundary.

use crate::ir::{Expr, Node};
use rustc_hash::FxHashSet;

/// Dispatch grouping selected by shared-nothing analysis.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DispatchGroup {
    /// One statement must run alone because it conflicts with adjacent work.
    Serial {
        /// Original top-level node index that must dispatch alone.
        node_index: usize,
    },
    /// Several statements can be emitted as concurrent dispatches.
    Parallel {
        /// Original top-level node indices that can dispatch concurrently.
        node_indices: Vec<usize>,
    },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct AccessSet {
    reads: FxHashSet<String>,
    writes: FxHashSet<String>,
    serial_boundary: bool,
}

/// Analyze top-level IR nodes for writable-state independence.
#[must_use]
pub fn detect_parallelism(nodes: &[Node]) -> Vec<DispatchGroup> {
    let mut groups = Vec::new();
    let mut current = Vec::new();
    let mut current_access = AccessSet::default();

    for (index, node) in nodes.iter().enumerate() {
        let access = access_set(node);
        if access.serial_boundary || conflicts(&current_access, &access) {
            push_group(&mut groups, &mut current);
            groups.push(DispatchGroup::Serial { node_index: index });
            current_access = AccessSet::default();
            continue;
        }
        current_access.reads.extend(access.reads);
        current_access.writes.extend(access.writes);
        current.push(index);
    }
    push_group(&mut groups, &mut current);
    groups
}

fn push_group(groups: &mut Vec<DispatchGroup>, current: &mut Vec<usize>) {
    match current.len() {
        0 => {}
        1 => groups.push(DispatchGroup::Serial {
            node_index: current[0],
        }),
        _ => groups.push(DispatchGroup::Parallel {
            node_indices: std::mem::take(current),
        }),
    }
    current.clear();
}

fn conflicts(left: &AccessSet, right: &AccessSet) -> bool {
    right
        .writes
        .iter()
        .any(|buffer| left.writes.contains(buffer) || left.reads.contains(buffer))
        || right
            .reads
            .iter()
            .any(|buffer| left.writes.contains(buffer))
}

fn access_set(node: &Node) -> AccessSet {
    let mut access = AccessSet::default();
    collect_node_access(node, &mut access);
    access
}

fn collect_node_access(node: &Node, access: &mut AccessSet) {
    match node {
        Node::Let { value, .. } | Node::Assign { value, .. } => collect_expr_reads(value, access),
        Node::Store {
            buffer,
            index,
            value,
        } => {
            collect_expr_reads(index, access);
            collect_expr_reads(value, access);
            access.writes.insert(buffer.to_string());
        }
        Node::If {
            cond,
            then,
            otherwise,
        } => {
            collect_expr_reads(cond, access);
            for node in then.iter().chain(otherwise) {
                collect_node_access(node, access);
            }
        }
        Node::Loop { from, to, body, .. } => {
            collect_expr_reads(from, access);
            collect_expr_reads(to, access);
            for node in body {
                collect_node_access(node, access);
            }
        }
        Node::Block(body) => {
            for node in body {
                collect_node_access(node, access);
            }
        }
        Node::IndirectDispatch { count_buffer, .. } => {
            access.reads.insert(count_buffer.to_string());
            access.serial_boundary = true;
        }
        Node::Trap { address, .. } => {
            collect_expr_reads(address, access);
            access.serial_boundary = true;
        }
        Node::Resume { .. } => {
            access.serial_boundary = true;
        }
        Node::Return
        | Node::Barrier
        | Node::AsyncLoad { .. }
        | Node::AsyncStore { .. }
        | Node::AsyncWait { .. }
        | Node::Region { .. }
        | Node::Opaque(_) => {
            access.serial_boundary = true;
        }
    }
}

fn collect_expr_reads(expr: &Expr, access: &mut AccessSet) {
    match expr {
        Expr::Load { buffer, index } => {
            access.reads.insert(buffer.to_string());
            collect_expr_reads(index, access);
        }
        Expr::BufLen { buffer } => {
            access.reads.insert(buffer.to_string());
        }
        Expr::BinOp { left, right, .. } => {
            collect_expr_reads(left, access);
            collect_expr_reads(right, access);
        }
        Expr::UnOp { operand, .. } => collect_expr_reads(operand, access),
        Expr::Call { args, .. } => {
            for arg in args {
                collect_expr_reads(arg, access);
            }
        }
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => {
            collect_expr_reads(cond, access);
            collect_expr_reads(true_val, access);
            collect_expr_reads(false_val, access);
        }
        Expr::Cast { value, .. } => collect_expr_reads(value, access),
        Expr::Fma { a, b, c } => {
            collect_expr_reads(a, access);
            collect_expr_reads(b, access);
            collect_expr_reads(c, access);
        }
        Expr::Atomic {
            buffer,
            index,
            expected,
            value,
            ..
        } => {
            access.reads.insert(buffer.to_string());
            access.writes.insert(buffer.to_string());
            collect_expr_reads(index, access);
            if let Some(expected) = expected {
                collect_expr_reads(expected, access);
            }
            collect_expr_reads(value, access);
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
        | Expr::SubgroupSize => {}
        Expr::SubgroupBallot { .. } | Expr::SubgroupShuffle { .. } | Expr::SubgroupAdd { .. } => {}
        Expr::Opaque(_) => {
            access.serial_boundary = true;
        }
    }
}

/// Parallelism analysis test suite.
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::ir::Expr;

    /// Write-after-write on the same buffer must serialise.
    #[test]
    pub fn write_after_write_serialised() {
        let nodes = vec![
            Node::store("out", Expr::u32(0), Expr::u32(1)),
            Node::store("out", Expr::u32(1), Expr::u32(2)),
        ];

        assert_eq!(
            detect_parallelism(&nodes),
            vec![
                DispatchGroup::Serial { node_index: 0 },
                DispatchGroup::Serial { node_index: 1 },
            ]
        );
    }

    /// Independent writes to different buffers may run in parallel.
    #[test]
    pub fn independent_writes_parallelised() {
        let nodes = vec![
            Node::store("a", Expr::u32(0), Expr::u32(1)),
            Node::store("b", Expr::u32(0), Expr::u32(2)),
        ];

        assert_eq!(
            detect_parallelism(&nodes),
            vec![DispatchGroup::Parallel {
                node_indices: vec![0, 1]
            }]
        );
    }

    /// Read-after-write on the same buffer must serialise.
    #[test]
    pub fn read_after_write_serialised() {
        let nodes = vec![
            Node::store("out", Expr::u32(0), Expr::u32(1)),
            Node::let_bind("x", Expr::load("out", Expr::u32(0))),
        ];

        assert_eq!(
            detect_parallelism(&nodes),
            vec![
                DispatchGroup::Serial { node_index: 0 },
                DispatchGroup::Serial { node_index: 1 },
            ]
        );
    }
}
