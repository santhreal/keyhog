//! Fusion-aware buffer hazard checks.
//!
//! Single-node validation knows whether one atomic expression is well-typed,
//! but it cannot see hazards introduced when independently valid nodes are
//! fused into the same kernel. This pass walks node sequences and rejects
//! mixed atomic / non-atomic access to the same buffer unless an explicit
//! `Node::Barrier` separates them.

use crate::ir::Expr;
use crate::ir::Node;
use crate::validate::{err, ValidationError};
use rustc_hash::FxHashSet;

#[derive(Debug, Default)]
pub(crate) struct NodeAccesses {
    pub(crate) read_buffers: FxHashSet<String>,
    pub(crate) atomic_buffers: FxHashSet<String>,
}

/// Validate fusion hazards caused by mixing non-atomic reads and atomic writes.
pub(crate) fn validate_fusion_alias_hazards(nodes: &[Node], errors: &mut Vec<ValidationError>) {
    validate_sequence(nodes, errors);
}

fn validate_sequence(nodes: &[Node], errors: &mut Vec<ValidationError>) {
    let mut reads_since_barrier = FxHashSet::<String>::default();
    let mut atomics_since_barrier = FxHashSet::<String>::default();

    for node in nodes {
        match node {
            Node::Barrier => {
                reads_since_barrier.clear();
                atomics_since_barrier.clear();
            }
            Node::If {
                cond,
                then,
                otherwise,
            } => {
                let mut accesses = NodeAccesses::default();
                collect_expr_accesses(cond, &mut accesses);
                report_alias_hazards(
                    &accesses,
                    &reads_since_barrier,
                    &atomics_since_barrier,
                    errors,
                );
                validate_sequence(then, errors);
                validate_sequence(otherwise, errors);
                reads_since_barrier.extend(accesses.read_buffers);
                atomics_since_barrier.extend(accesses.atomic_buffers);
            }
            Node::Loop { from, to, body, .. } => {
                let mut accesses = NodeAccesses::default();
                collect_expr_accesses(from, &mut accesses);
                collect_expr_accesses(to, &mut accesses);
                report_alias_hazards(
                    &accesses,
                    &reads_since_barrier,
                    &atomics_since_barrier,
                    errors,
                );
                validate_sequence(body, errors);
                reads_since_barrier.extend(accesses.read_buffers);
                atomics_since_barrier.extend(accesses.atomic_buffers);
            }
            Node::Block(body) => {
                validate_sequence(body, errors);
            }
            Node::Region { body, .. } => {
                validate_sequence(body, errors);
            }
            _ => {
                let mut accesses = NodeAccesses::default();
                collect_node_accesses(node, &mut accesses);
                report_alias_hazards(
                    &accesses,
                    &reads_since_barrier,
                    &atomics_since_barrier,
                    errors,
                );
                reads_since_barrier.extend(accesses.read_buffers);
                atomics_since_barrier.extend(accesses.atomic_buffers);
            }
        }
    }
}

fn report_alias_hazards(
    accesses: &NodeAccesses,
    reads_since_barrier: &FxHashSet<String>,
    atomics_since_barrier: &FxHashSet<String>,
    errors: &mut Vec<ValidationError>,
) {
    let mut hazards = accesses
        .atomic_buffers
        .intersection(reads_since_barrier)
        .cloned()
        .collect::<Vec<_>>();
    hazards.extend(
        accesses
            .read_buffers
            .intersection(atomics_since_barrier)
            .cloned(),
    );
    hazards.sort();
    hazards.dedup();

    for buffer in hazards {
        errors.push(err(format!(
            "fusion hazard on buffer `{buffer}`: one node reads it non-atomically while another issues an atomic access without an explicit barrier. Fix: insert `Node::barrier()` between the read path and the atomic path, or rename the buffers before fusion."
        )));
    }
}

pub(crate) fn collect_node_accesses(node: &Node, accesses: &mut NodeAccesses) {
    match node {
        Node::Let { value, .. } | Node::Assign { value, .. } => {
            collect_expr_accesses(value, accesses);
        }
        Node::Store {
            buffer,
            index,
            value,
        } => {
            accesses.read_buffers.insert(buffer.to_string());
            collect_expr_accesses(index, accesses);
            collect_expr_accesses(value, accesses);
        }
        Node::IndirectDispatch { count_buffer, .. } => {
            accesses.read_buffers.insert(count_buffer.to_string());
        }
        Node::AsyncLoad {
            source,
            destination,
            offset,
            size,
            ..
        }
        | Node::AsyncStore {
            source,
            destination,
            offset,
            size,
            ..
        } => {
            accesses.read_buffers.insert(source.to_string());
            accesses.read_buffers.insert(destination.to_string());
            collect_expr_accesses(offset, accesses);
            collect_expr_accesses(size, accesses);
        }
        Node::Trap { .. }
        | Node::Resume { .. }
        | Node::Return
        | Node::Barrier
        | Node::Opaque(_) => {}
        Node::If { .. } | Node::Loop { .. } | Node::Block(_) | Node::Region { .. } => {
            unreachable!("control-flow nodes are handled by validate_sequence")
        }
        Node::AsyncWait { .. } => {}
    }
}

pub(crate) fn collect_expr_accesses(expr: &Expr, accesses: &mut NodeAccesses) {
    match expr {
        Expr::Load { buffer, index } => {
            accesses.read_buffers.insert(buffer.to_string());
            collect_expr_accesses(index, accesses);
        }
        Expr::BufLen { buffer } => {
            accesses.read_buffers.insert(buffer.to_string());
        }
        Expr::Atomic {
            buffer,
            index,
            expected,
            value,
            ..
        } => {
            accesses.atomic_buffers.insert(buffer.to_string());
            collect_expr_accesses(index, accesses);
            if let Some(expected) = expected {
                collect_expr_accesses(expected, accesses);
            }
            collect_expr_accesses(value, accesses);
        }
        Expr::BinOp { left, right, .. } => {
            collect_expr_accesses(left, accesses);
            collect_expr_accesses(right, accesses);
        }
        Expr::UnOp { operand, .. } | Expr::Cast { value: operand, .. } => {
            collect_expr_accesses(operand, accesses);
        }
        Expr::Call { args, .. } => {
            for arg in args {
                collect_expr_accesses(arg, accesses);
            }
        }
        Expr::Fma { a, b, c } => {
            collect_expr_accesses(a, accesses);
            collect_expr_accesses(b, accesses);
            collect_expr_accesses(c, accesses);
        }
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => {
            collect_expr_accesses(cond, accesses);
            collect_expr_accesses(true_val, accesses);
            collect_expr_accesses(false_val, accesses);
        }
        Expr::SubgroupBallot { cond } => collect_expr_accesses(cond, accesses),
        Expr::SubgroupShuffle { value, lane } => {
            collect_expr_accesses(value, accesses);
            collect_expr_accesses(lane, accesses);
        }
        Expr::SubgroupAdd { value } => collect_expr_accesses(value, accesses),
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
        | Expr::Opaque(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BufferAccess, BufferDecl, DataType, Program};

    fn validate(program: &Program) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        validate_fusion_alias_hazards(program.entry(), &mut errors);
        errors
    }

    #[test]
    fn atomic_after_plain_read_requires_barrier() {
        let program = Program::wrapped(
            vec![BufferDecl::storage(
                "state",
                0,
                BufferAccess::ReadWrite,
                DataType::U32,
            )],
            [1, 1, 1],
            vec![
                Node::let_bind("plain", Expr::load("state", Expr::u32(0))),
                Node::let_bind(
                    "atomic_old",
                    Expr::atomic_add("state", Expr::u32(0), Expr::u32(1)),
                ),
            ],
        );

        let errors = validate(&program);
        assert!(errors
            .iter()
            .any(|error| error.message.contains("fusion hazard on buffer `state`")));
    }

    #[test]
    fn barrier_clears_atomic_plain_alias_hazard() {
        let program = Program::wrapped(
            vec![BufferDecl::storage(
                "state",
                0,
                BufferAccess::ReadWrite,
                DataType::U32,
            )],
            [1, 1, 1],
            vec![
                Node::let_bind("plain", Expr::load("state", Expr::u32(0))),
                Node::barrier(),
                Node::let_bind(
                    "atomic_old",
                    Expr::atomic_add("state", Expr::u32(0), Expr::u32(1)),
                ),
            ],
        );

        assert!(validate(&program).is_empty());
    }
}
