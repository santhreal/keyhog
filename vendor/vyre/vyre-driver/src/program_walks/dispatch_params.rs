//! Dispatch ABI parameter derivation from binding plans.

use vyre_foundation::ir::{Expr, Node, Program};

use crate::binding::{Binding, BindingRole};

/// Derive the dispatch element count from a binding plan.
#[must_use]
pub fn dispatch_element_count(bindings: &[Binding]) -> u32 {
    dispatch_element_count_inner(bindings, false)
}

/// Derive the dispatch element count from a binding plan and Program body.
#[must_use]
pub fn dispatch_element_count_for_program(program: &Program, bindings: &[Binding]) -> u32 {
    dispatch_element_count_inner(bindings, program_contains_atomic(program))
}

fn dispatch_element_count_inner(bindings: &[Binding], force_full_span: bool) -> u32 {
    if bindings
        .iter()
        .any(|binding| binding.role == BindingRole::Shared)
        || force_full_span
    {
        return bindings
            .iter()
            .filter(|binding| binding.role != BindingRole::Shared)
            .map(|binding| binding.element_count)
            .max()
            .unwrap_or(1)
            .max(1);
    }

    let output_count = bindings
        .iter()
        .filter(|binding| matches!(binding.role, BindingRole::Output | BindingRole::InputOutput))
        .map(|binding| binding.element_count)
        .max()
        .unwrap_or(0);
    if output_count > 0 {
        return output_count;
    }

    bindings
        .iter()
        .filter(|binding| binding.role != BindingRole::Shared)
        .map(|binding| binding.element_count)
        .max()
        .unwrap_or(1)
        .max(1)
}

fn program_contains_atomic(program: &Program) -> bool {
    nodes_contain_atomic(program.entry())
}

fn nodes_contain_atomic(nodes: &[Node]) -> bool {
    nodes.iter().any(node_contains_atomic)
}

fn node_contains_atomic(node: &Node) -> bool {
    match node {
        Node::Let { value, .. } | Node::Assign { value, .. } => expr_contains_atomic(value),
        Node::Store { index, value, .. } => {
            expr_contains_atomic(index) || expr_contains_atomic(value)
        }
        Node::If {
            cond,
            then,
            otherwise,
        } => {
            expr_contains_atomic(cond)
                || nodes_contain_atomic(then)
                || nodes_contain_atomic(otherwise)
        }
        Node::Loop {
            from, to, body, ..
        } => expr_contains_atomic(from) || expr_contains_atomic(to) || nodes_contain_atomic(body),
        Node::Block(body) => nodes_contain_atomic(body),
        Node::Region { body, .. } => nodes_contain_atomic(body),
        Node::AsyncLoad { offset, size, .. } | Node::AsyncStore { offset, size, .. } => {
            expr_contains_atomic(offset) || expr_contains_atomic(size)
        }
        Node::Trap { address, .. } => expr_contains_atomic(address),
        Node::IndirectDispatch { .. }
        | Node::AsyncWait { .. }
        | Node::Resume { .. }
        | Node::Return
        | Node::Barrier { .. }
        | Node::Opaque(_) => false,
        _ => false,
    }
}

fn expr_contains_atomic(expr: &Expr) -> bool {
    match expr {
        Expr::Atomic { .. } => true,
        Expr::Load { index, .. } => expr_contains_atomic(index),
        Expr::BinOp { left, right, .. } => expr_contains_atomic(left) || expr_contains_atomic(right),
        Expr::UnOp { operand, .. } => expr_contains_atomic(operand),
        Expr::Call { args, .. } => args.iter().any(expr_contains_atomic),
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => {
            expr_contains_atomic(cond)
                || expr_contains_atomic(true_val)
                || expr_contains_atomic(false_val)
        }
        Expr::Cast { value, .. } => expr_contains_atomic(value),
        Expr::Fma { a, b, c } => {
            expr_contains_atomic(a) || expr_contains_atomic(b) || expr_contains_atomic(c)
        }
        Expr::SubgroupBallot { cond } => expr_contains_atomic(cond),
        Expr::SubgroupShuffle { value, lane } => {
            expr_contains_atomic(value) || expr_contains_atomic(lane)
        }
        Expr::SubgroupAdd { value } => expr_contains_atomic(value),
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
        | Expr::Opaque(_) => false,
        _ => false,
    }
}

/// Build per-buffer element-count parameter words for a dispatch.
#[must_use]
pub fn dispatch_param_words(bindings: &[Binding], element_count: u32) -> Vec<u32> {
    let mut words = Vec::with_capacity(bindings.len().saturating_add(1).max(1));
    dispatch_param_words_into(bindings, element_count, &mut words);
    words
}

/// Build per-buffer element-count parameter words into caller-owned storage.
pub fn dispatch_param_words_into(bindings: &[Binding], element_count: u32, words: &mut Vec<u32>) {
    words.clear();
    words.resize(bindings.len().saturating_add(1).max(1), 0);
    words[0] = element_count;
    for binding in bindings {
        if binding.buffer_index + 1 >= words.len() {
            words.resize(binding.buffer_index + 2, 0);
        }
        words[binding.buffer_index + 1] = if binding.element_count == 0 {
            element_count
        } else {
            binding.element_count
        };
    }
}
