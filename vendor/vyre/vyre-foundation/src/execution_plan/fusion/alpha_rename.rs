//! Per-arm alpha-renaming for cross-program fusion.

use std::sync::Arc;

use crate::ir::{Expr, Ident, Node};

pub(super) fn push_alpha_renamed_arm_entry_node(out: &mut Vec<Node>, node: &Node, arm_idx: usize) {
    match node {
        Node::Region { body, .. } => out.extend(alpha_rename_arm_nodes(body, arm_idx)),
        _ => out.push(alpha_rename_arm_node(node, arm_idx)),
    }
}

fn alpha_rename_arm_node(node: &Node, arm_idx: usize) -> Node {
    match node {
        Node::Let { name, value } => Node::Let {
            name: arm_local_ident(arm_idx, name),
            value: alpha_rename_arm_expr(value, arm_idx),
        },
        Node::Assign { name, value } => Node::Assign {
            name: arm_local_ident(arm_idx, name),
            value: alpha_rename_arm_expr(value, arm_idx),
        },
        Node::Store {
            buffer,
            index,
            value,
        } => Node::Store {
            buffer: buffer.clone(),
            index: alpha_rename_arm_expr(index, arm_idx),
            value: alpha_rename_arm_expr(value, arm_idx),
        },
        Node::If {
            cond,
            then,
            otherwise,
        } => Node::If {
            cond: alpha_rename_arm_expr(cond, arm_idx),
            then: alpha_rename_arm_nodes(then, arm_idx),
            otherwise: alpha_rename_arm_nodes(otherwise, arm_idx),
        },
        Node::Loop {
            var,
            from,
            to,
            body,
        } => Node::Loop {
            var: arm_local_ident(arm_idx, var),
            from: alpha_rename_arm_expr(from, arm_idx),
            to: alpha_rename_arm_expr(to, arm_idx),
            body: alpha_rename_arm_nodes(body, arm_idx),
        },
        Node::Block(body) => Node::Block(alpha_rename_arm_nodes(body, arm_idx)),
        Node::Region {
            generator,
            source_region,
            body,
        } => Node::Region {
            generator: generator.clone(),
            source_region: source_region.clone(),
            body: Arc::new(alpha_rename_arm_nodes(body, arm_idx)),
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
            offset: Box::new(alpha_rename_arm_expr(offset, arm_idx)),
            size: Box::new(alpha_rename_arm_expr(size, arm_idx)),
            tag: arm_local_ident(arm_idx, tag),
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
            offset: Box::new(alpha_rename_arm_expr(offset, arm_idx)),
            size: Box::new(alpha_rename_arm_expr(size, arm_idx)),
            tag: arm_local_ident(arm_idx, tag),
        },
        Node::AsyncWait { tag } => Node::AsyncWait {
            tag: arm_local_ident(arm_idx, tag),
        },
        Node::Trap { address, tag } => Node::Trap {
            address: Box::new(alpha_rename_arm_expr(address, arm_idx)),
            tag: arm_local_ident(arm_idx, tag),
        },
        Node::Resume { tag } => Node::Resume {
            tag: arm_local_ident(arm_idx, tag),
        },
        Node::IndirectDispatch {
            count_buffer,
            count_offset,
        } => Node::IndirectDispatch {
            count_buffer: count_buffer.clone(),
            count_offset: *count_offset,
        },
        Node::AllReduce { buffer, op, group } => Node::AllReduce {
            buffer: buffer.clone(),
            op: *op,
            group: *group,
        },
        Node::AllGather {
            input,
            output,
            group,
        } => Node::AllGather {
            input: input.clone(),
            output: output.clone(),
            group: *group,
        },
        Node::ReduceScatter {
            input,
            output,
            op,
            group,
        } => Node::ReduceScatter {
            input: input.clone(),
            output: output.clone(),
            op: *op,
            group: *group,
        },
        Node::Broadcast {
            buffer,
            root,
            group,
        } => Node::Broadcast {
            buffer: buffer.clone(),
            root: *root,
            group: *group,
        },
        Node::Return => Node::Return,
        Node::Barrier { ordering } => Node::barrier_with_ordering(*ordering),
        Node::Opaque(extension) => Node::Opaque(Arc::clone(extension)),
    }
}

fn alpha_rename_arm_nodes(nodes: &[Node], arm_idx: usize) -> Vec<Node> {
    nodes
        .iter()
        .map(|node| alpha_rename_arm_node(node, arm_idx))
        .collect()
}

fn alpha_rename_arm_expr(expr: &Expr, arm_idx: usize) -> Expr {
    match expr {
        Expr::Var(name) => Expr::Var(arm_local_ident(arm_idx, name)),
        Expr::Load { buffer, index } => Expr::Load {
            buffer: buffer.clone(),
            index: Box::new(alpha_rename_arm_expr(index, arm_idx)),
        },
        Expr::BufLen { buffer } => Expr::BufLen {
            buffer: buffer.clone(),
        },
        Expr::BinOp { op, left, right } => Expr::BinOp {
            op: *op,
            left: Box::new(alpha_rename_arm_expr(left, arm_idx)),
            right: Box::new(alpha_rename_arm_expr(right, arm_idx)),
        },
        Expr::UnOp { op, operand } => Expr::UnOp {
            op: op.clone(),
            operand: Box::new(alpha_rename_arm_expr(operand, arm_idx)),
        },
        Expr::Call { op_id, args } => Expr::Call {
            op_id: op_id.clone(),
            args: args
                .iter()
                .map(|arg| alpha_rename_arm_expr(arg, arm_idx))
                .collect(),
        },
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => Expr::Select {
            cond: Box::new(alpha_rename_arm_expr(cond, arm_idx)),
            true_val: Box::new(alpha_rename_arm_expr(true_val, arm_idx)),
            false_val: Box::new(alpha_rename_arm_expr(false_val, arm_idx)),
        },
        Expr::Cast { target, value } => Expr::Cast {
            target: target.clone(),
            value: Box::new(alpha_rename_arm_expr(value, arm_idx)),
        },
        Expr::Fma { a, b, c } => Expr::Fma {
            a: Box::new(alpha_rename_arm_expr(a, arm_idx)),
            b: Box::new(alpha_rename_arm_expr(b, arm_idx)),
            c: Box::new(alpha_rename_arm_expr(c, arm_idx)),
        },
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
            index: Box::new(alpha_rename_arm_expr(index, arm_idx)),
            expected: expected
                .as_ref()
                .map(|expr| Box::new(alpha_rename_arm_expr(expr, arm_idx))),
            value: Box::new(alpha_rename_arm_expr(value, arm_idx)),
            ordering: *ordering,
        },
        Expr::SubgroupBallot { cond } => Expr::SubgroupBallot {
            cond: Box::new(alpha_rename_arm_expr(cond, arm_idx)),
        },
        Expr::SubgroupShuffle { value, lane } => Expr::SubgroupShuffle {
            value: Box::new(alpha_rename_arm_expr(value, arm_idx)),
            lane: Box::new(alpha_rename_arm_expr(lane, arm_idx)),
        },
        Expr::SubgroupAdd { value } => Expr::SubgroupAdd {
            value: Box::new(alpha_rename_arm_expr(value, arm_idx)),
        },
        Expr::LitU32(_)
        | Expr::LitI32(_)
        | Expr::LitF32(_)
        | Expr::LitBool(_)
        | Expr::InvocationId { .. }
        | Expr::WorkgroupId { .. }
        | Expr::LocalId { .. }
        | Expr::SubgroupLocalId
        | Expr::SubgroupSize
        | Expr::Opaque(_) => expr.clone(),
    }
}

fn arm_local_ident(arm_idx: usize, name: &Ident) -> Ident {
    Ident::from(format!("__vyre_fuse_a{arm_idx}_{}", name.as_str()))
}
