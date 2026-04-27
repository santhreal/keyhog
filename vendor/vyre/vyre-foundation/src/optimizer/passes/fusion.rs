use crate::composition::duplicate_self_exclusive_regions;
use crate::ir::{Expr, Node, Program};
use crate::optimizer::{fingerprint_program, vyre_pass, PassAnalysis, PassResult};
use rustc_hash::{FxHashMap, FxHashSet};

/// Fuse pure single-use scalar pipelines into their consuming expression.
///
/// The pass must preserve the original program's happens-before ordering.
/// Any replacement that depends on a buffer load is flushed before a write to
/// that same buffer so optimized IR cannot observe a newer value than the
/// unfused sequence would have seen.
#[derive(Debug, Default)]
#[vyre_pass(name = "fusion", requires = [], invalidates = [])]
pub struct Fusion;

impl Fusion {
    /// Decide whether this pass should run.
    #[must_use]
    #[inline]
    pub fn analyze(program: &Program) -> PassAnalysis {
        if duplicate_self_exclusive_regions(program.entry()).is_empty() {
            PassAnalysis::RUN
        } else {
            PassAnalysis::SKIP
        }
    }

    /// Inline single-use pure bindings so load/op/store pipelines lower as one kernel body.
    #[must_use]
    pub fn transform(program: Program) -> PassResult {
        // AUDIT_2026-04-24 F-FUSE-01: preserve non_composable_with_self
        // across fusion — fused body is identical semantics, so the
        // self-exclusion invariant must carry through.
        let optimized = Program::wrapped(
            program.buffers().to_vec(),
            program.workgroup_size(),
            fuse_nodes(program.entry()),
        )
        .with_optional_entry_op_id(program.entry_op_id().map(str::to_string))
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

#[cfg(test)]
mod analyze_tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn analyze_skips_self_exclusive_duplicate_regions() {
        let generator = crate::composition::mark_self_exclusive_region(
            "vyre-libs::parsing::core_delimiter_match",
        );
        let program = Program::wrapped(
            Vec::new(),
            [1, 1, 1],
            vec![
                Node::Region {
                    generator: generator.clone().into(),
                    source_region: None,
                    body: Arc::new(vec![Node::Return]),
                },
                Node::Region {
                    generator: generator.into(),
                    source_region: None,
                    body: Arc::new(vec![Node::Return]),
                },
            ],
        );
        assert_eq!(Fusion::analyze(&program), PassAnalysis::SKIP);
    }
}

#[derive(Clone, Debug, Default)]
struct ExprDeps {
    vars: FxHashSet<String>,
    buffers: FxHashSet<String>,
}

#[derive(Clone, Debug)]
struct PendingExpr {
    expr: Expr,
    deps: ExprDeps,
}

fn fuse_nodes(nodes: &[Node]) -> Vec<Node> {
    let use_counts = count_var_uses(nodes);
    let mut replacements = FxHashMap::<String, PendingExpr>::default();
    let mut replacement_order = Vec::<String>::new();
    let mut fused = Vec::with_capacity(nodes.len());

    for node in nodes {
        if is_control_flow_boundary(node) {
            flush_all_replacements(&mut replacements, &mut replacement_order, &mut fused);
            fused.push(fuse_control_flow_node(node));
            continue;
        }

        match node {
            Node::Let { name, value }
                if use_counts.get(name.as_str()).copied().unwrap_or(0) == 1
                    && is_fusable_expr(value) =>
            {
                let used = used_vars_in_expr(value);
                let value = substitute_expr(value, &replacements);
                drop_used_replacements(&used, &mut replacements, &mut replacement_order);
                replacements.insert(
                    name.to_string(),
                    PendingExpr {
                        deps: expr_deps(&value),
                        expr: value,
                    },
                );
                replacement_order.push(name.to_string());
            }
            Node::Let { name, value } => {
                let used = used_vars_in_expr(value);
                let value = substitute_expr(value, &replacements);
                drop_used_replacements(&used, &mut replacements, &mut replacement_order);
                flush_replacements_for_var(
                    name.as_str(),
                    &mut replacements,
                    &mut replacement_order,
                    &mut fused,
                );
                fused.push(Node::let_bind(name, value));
            }
            Node::Assign { name, value } => {
                flush_replacements_for_var(
                    name.as_str(),
                    &mut replacements,
                    &mut replacement_order,
                    &mut fused,
                );
                let used = used_vars_in_expr(value);
                let value = substitute_expr(value, &replacements);
                drop_used_replacements(&used, &mut replacements, &mut replacement_order);
                fused.push(Node::assign(name, value));
            }
            Node::Store {
                buffer,
                index,
                value,
            } => {
                flush_replacements_for_buffer(
                    buffer.as_str(),
                    &mut replacements,
                    &mut replacement_order,
                    &mut fused,
                );
                let mut used = used_vars_in_expr(index);
                used.extend(used_vars_in_expr(value));
                fused.push(Node::store(
                    buffer,
                    substitute_expr(index, &replacements),
                    substitute_expr(value, &replacements),
                ));
                drop_used_replacements(&used, &mut replacements, &mut replacement_order);
            }
            Node::Return => {
                replacements.clear();
                replacement_order.clear();
                fused.push(Node::Return);
            }
            Node::Barrier => {
                flush_all_replacements(&mut replacements, &mut replacement_order, &mut fused);
                fused.push(Node::Barrier);
            }
            Node::IndirectDispatch {
                count_buffer,
                count_offset,
            } => {
                flush_all_replacements(&mut replacements, &mut replacement_order, &mut fused);
                fused.push(Node::IndirectDispatch {
                    count_buffer: count_buffer.clone(),
                    count_offset: *count_offset,
                });
            }
            Node::AsyncLoad {
                source,
                destination,
                offset,
                size,
                tag,
            } => {
                flush_all_replacements(&mut replacements, &mut replacement_order, &mut fused);
                fused.push(Node::async_load_ext(
                    source.clone(),
                    destination.clone(),
                    (**offset).clone(),
                    (**size).clone(),
                    tag.clone(),
                ));
            }
            Node::AsyncStore {
                source,
                destination,
                offset,
                size,
                tag,
            } => {
                flush_all_replacements(&mut replacements, &mut replacement_order, &mut fused);
                fused.push(Node::async_store(
                    source.clone(),
                    destination.clone(),
                    (**offset).clone(),
                    (**size).clone(),
                    tag.clone(),
                ));
            }
            Node::AsyncWait { tag } => {
                flush_all_replacements(&mut replacements, &mut replacement_order, &mut fused);
                fused.push(Node::async_wait(tag));
            }
            Node::Trap { .. } | Node::Resume { .. } | Node::Opaque(_) => {
                flush_all_replacements(&mut replacements, &mut replacement_order, &mut fused);
                fused.push(node.clone());
            }
            Node::If { .. } | Node::Loop { .. } | Node::Block(_) | Node::Region { .. } => {
                unreachable!("control-flow nodes are handled above")
            }
        }
    }

    flush_all_replacements(&mut replacements, &mut replacement_order, &mut fused);
    fused
}

fn fuse_control_flow_node(node: &Node) -> Node {
    match node {
        Node::If {
            cond,
            then,
            otherwise,
        } => Node::if_then_else(cond.clone(), fuse_nodes(then), fuse_nodes(otherwise)),
        Node::Loop {
            var,
            from,
            to,
            body,
        } => Node::loop_for(var, from.clone(), to.clone(), fuse_nodes(body)),
        Node::Block(nodes) => Node::block(fuse_nodes(nodes)),
        Node::Region {
            generator,
            source_region,
            body,
        } => Node::Region {
            generator: generator.clone(),
            source_region: source_region.clone(),
            body: std::sync::Arc::new(fuse_nodes(body)),
        },
        _ => unreachable!("only control-flow nodes reach fuse_control_flow_node"),
    }
}

fn is_control_flow_boundary(node: &Node) -> bool {
    matches!(
        node,
        Node::If { .. } | Node::Loop { .. } | Node::Block(_) | Node::Region { .. }
    )
}

fn drop_used_replacements(
    used: &FxHashSet<String>,
    replacements: &mut FxHashMap<String, PendingExpr>,
    replacement_order: &mut Vec<String>,
) {
    for name in used {
        replacements.remove(name.as_str());
        replacement_order.retain(|pending| pending != name);
    }
}

fn flush_replacements_for_var(
    name: &str,
    replacements: &mut FxHashMap<String, PendingExpr>,
    replacement_order: &mut Vec<String>,
    fused: &mut Vec<Node>,
) {
    let names = replacements
        .iter()
        .filter_map(|(pending_name, pending)| {
            (pending_name == name || pending.deps.vars.contains(name))
                .then_some(pending_name.clone())
        })
        .collect::<FxHashSet<_>>();
    flush_selected_replacements(names, replacements, replacement_order, fused);
}

fn flush_replacements_for_buffer(
    buffer: &str,
    replacements: &mut FxHashMap<String, PendingExpr>,
    replacement_order: &mut Vec<String>,
    fused: &mut Vec<Node>,
) {
    let names = replacements
        .iter()
        .filter_map(|(pending_name, pending)| {
            pending
                .deps
                .buffers
                .contains(buffer)
                .then_some(pending_name.clone())
        })
        .collect::<FxHashSet<_>>();
    flush_selected_replacements(names, replacements, replacement_order, fused);
}

fn flush_all_replacements(
    replacements: &mut FxHashMap<String, PendingExpr>,
    replacement_order: &mut Vec<String>,
    fused: &mut Vec<Node>,
) {
    let names = replacement_order.iter().cloned().collect::<FxHashSet<_>>();
    flush_selected_replacements(names, replacements, replacement_order, fused);
}

fn flush_selected_replacements(
    names: FxHashSet<String>,
    replacements: &mut FxHashMap<String, PendingExpr>,
    replacement_order: &mut Vec<String>,
    fused: &mut Vec<Node>,
) {
    let pending = std::mem::take(replacement_order);
    for name in pending {
        if let Some(pending_expr) = replacements.remove(name.as_str()) {
            if names.contains(name.as_str()) {
                fused.push(Node::let_bind(name, pending_expr.expr));
            } else {
                replacements.insert(name.clone(), pending_expr);
                replacement_order.push(name);
            }
        }
    }
}

fn expr_deps(expr: &Expr) -> ExprDeps {
    let mut deps = ExprDeps::default();
    collect_expr_deps(expr, &mut deps);
    deps
}

fn collect_expr_deps(expr: &Expr, deps: &mut ExprDeps) {
    match expr {
        Expr::Var(name) => {
            deps.vars.insert(name.to_string());
        }
        Expr::Load { buffer, index } => {
            deps.buffers.insert(buffer.to_string());
            collect_expr_deps(index, deps);
        }
        Expr::BufLen { buffer } => {
            deps.buffers.insert(buffer.to_string());
        }
        Expr::Atomic {
            buffer,
            index,
            expected,
            value,
            ..
        } => {
            deps.buffers.insert(buffer.to_string());
            collect_expr_deps(index, deps);
            if let Some(expected) = expected {
                collect_expr_deps(expected, deps);
            }
            collect_expr_deps(value, deps);
        }
        Expr::BinOp { left, right, .. } => {
            collect_expr_deps(left, deps);
            collect_expr_deps(right, deps);
        }
        Expr::UnOp { operand, .. } | Expr::Cast { value: operand, .. } => {
            collect_expr_deps(operand, deps);
        }
        Expr::Fma { a, b, c } => {
            collect_expr_deps(a, deps);
            collect_expr_deps(b, deps);
            collect_expr_deps(c, deps);
        }
        Expr::Call { args, .. } => {
            for arg in args {
                collect_expr_deps(arg, deps);
            }
        }
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => {
            collect_expr_deps(cond, deps);
            collect_expr_deps(true_val, deps);
            collect_expr_deps(false_val, deps);
        }
        Expr::LitU32(_)
        | Expr::LitI32(_)
        | Expr::LitF32(_)
        | Expr::LitBool(_)
        | Expr::InvocationId { .. }
        | Expr::WorkgroupId { .. }
        | Expr::LocalId { .. }
        | Expr::SubgroupLocalId
        | Expr::SubgroupSize
        | Expr::SubgroupBallot { .. }
        | Expr::SubgroupShuffle { .. }
        | Expr::SubgroupAdd { .. }
        | Expr::Opaque(_) => {}
    }
}

fn used_vars_in_expr(expr: &Expr) -> FxHashSet<String> {
    let mut used = FxHashSet::default();
    collect_used_vars(expr, &mut used);
    used
}

fn collect_used_vars(expr: &Expr, used: &mut FxHashSet<String>) {
    match expr {
        Expr::Var(name) => {
            used.insert(name.to_string());
        }
        Expr::Load { index, .. } => collect_used_vars(index, used),
        Expr::Atomic {
            index,
            expected,
            value,
            ..
        } => {
            collect_used_vars(index, used);
            if let Some(expected) = expected {
                collect_used_vars(expected, used);
            }
            collect_used_vars(value, used);
        }
        Expr::BinOp { left, right, .. } => {
            collect_used_vars(left, used);
            collect_used_vars(right, used);
        }
        Expr::UnOp { operand, .. } | Expr::Cast { value: operand, .. } => {
            collect_used_vars(operand, used);
        }
        Expr::Fma { a, b, c } => {
            collect_used_vars(a, used);
            collect_used_vars(b, used);
            collect_used_vars(c, used);
        }
        Expr::Call { args, .. } => {
            for arg in args {
                collect_used_vars(arg, used);
            }
        }
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => {
            collect_used_vars(cond, used);
            collect_used_vars(true_val, used);
            collect_used_vars(false_val, used);
        }
        Expr::LitU32(_)
        | Expr::LitI32(_)
        | Expr::LitF32(_)
        | Expr::LitBool(_)
        | Expr::BufLen { .. }
        | Expr::InvocationId { .. }
        | Expr::WorkgroupId { .. }
        | Expr::LocalId { .. }
        | Expr::SubgroupLocalId
        | Expr::SubgroupSize
        | Expr::SubgroupBallot { .. }
        | Expr::SubgroupShuffle { .. }
        | Expr::SubgroupAdd { .. }
        | Expr::Opaque(_) => {}
    }
}

// VYRE_IR_HOTSPOTS HIGH (fusion.rs:272-277): substitute_expr now
// reads the `PendingExpr` map directly so callers no longer rebuild
// a fresh `FxHashMap<String, Expr>` on every node via
// `replacement_exprs`. The old helper allocated N×M entries + a
// clone per entry on every visited statement.
fn substitute_expr(expr: &Expr, replacements: &FxHashMap<String, PendingExpr>) -> Expr {
    match expr {
        Expr::Var(name) => replacements
            .get(name.as_str())
            .map(|pending| pending.expr.clone())
            .unwrap_or_else(|| expr.clone()),
        Expr::Load { buffer, index } => Expr::Load {
            buffer: buffer.clone(),
            index: Box::new(substitute_expr(index, replacements)),
        },
        Expr::BinOp { op, left, right } => Expr::BinOp {
            op: *op,
            left: Box::new(substitute_expr(left, replacements)),
            right: Box::new(substitute_expr(right, replacements)),
        },
        Expr::UnOp { op, operand } => Expr::UnOp {
            op: op.clone(),
            operand: Box::new(substitute_expr(operand, replacements)),
        },
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => Expr::Select {
            cond: Box::new(substitute_expr(cond, replacements)),
            true_val: Box::new(substitute_expr(true_val, replacements)),
            false_val: Box::new(substitute_expr(false_val, replacements)),
        },
        Expr::Cast { target, value } => Expr::Cast {
            target: target.clone(),
            value: Box::new(substitute_expr(value, replacements)),
        },
        Expr::Fma { a, b, c } => Expr::Fma {
            a: Box::new(substitute_expr(a, replacements)),
            b: Box::new(substitute_expr(b, replacements)),
            c: Box::new(substitute_expr(c, replacements)),
        },
        Expr::Atomic {
            op,
            buffer,
            index,
            expected,
            value,
        } => Expr::Atomic {
            op: *op,
            buffer: buffer.clone(),
            index: Box::new(substitute_expr(index, replacements)),
            expected: expected
                .as_deref()
                .map(|expected| Box::new(substitute_expr(expected, replacements))),
            value: Box::new(substitute_expr(value, replacements)),
        },
        Expr::Call { op_id, args } => Expr::Call {
            op_id: op_id.clone(),
            args: args
                .iter()
                .map(|arg| substitute_expr(arg, replacements))
                .collect(),
        },
        Expr::LitU32(_)
        | Expr::LitI32(_)
        | Expr::LitF32(_)
        | Expr::LitBool(_)
        | Expr::BufLen { .. }
        | Expr::InvocationId { .. }
        | Expr::WorkgroupId { .. }
        | Expr::LocalId { .. }
        | Expr::SubgroupLocalId
        | Expr::SubgroupSize
        | Expr::SubgroupBallot { .. }
        | Expr::SubgroupShuffle { .. }
        | Expr::SubgroupAdd { .. } => expr.clone(),
        Expr::Opaque(_) => expr.clone(),
    }
}

fn is_fusable_expr(expr: &Expr) -> bool {
    match expr {
        Expr::Load { index, .. } => is_pure_expr(index),
        Expr::BinOp { left, right, .. } => is_pure_expr(left) && is_pure_expr(right),
        Expr::UnOp { operand, .. } => is_pure_expr(operand),
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => is_pure_expr(cond) && is_pure_expr(true_val) && is_pure_expr(false_val),
        Expr::Cast { value, .. } => is_pure_expr(value),
        Expr::Fma { a, b, c } => is_pure_expr(a) && is_pure_expr(b) && is_pure_expr(c),
        Expr::Call { .. }
        | Expr::Atomic { .. }
        | Expr::Opaque(_)
        | Expr::LitU32(_)
        | Expr::LitI32(_)
        | Expr::LitF32(_)
        | Expr::LitBool(_)
        | Expr::Var(_)
        | Expr::BufLen { .. }
        | Expr::InvocationId { .. }
        | Expr::WorkgroupId { .. }
        | Expr::SubgroupBallot { .. }
        | Expr::SubgroupShuffle { .. }
        | Expr::SubgroupAdd { .. }
        | Expr::LocalId { .. }
        | Expr::SubgroupLocalId
        | Expr::SubgroupSize => false,
    }
}

fn is_pure_expr(expr: &Expr) -> bool {
    match expr {
        Expr::Atomic { .. }
        | Expr::Call { .. }
        | Expr::SubgroupBallot { .. }
        | Expr::SubgroupShuffle { .. }
        | Expr::SubgroupAdd { .. } => false,
        Expr::Opaque(_) => false,
        Expr::Load { index, .. } => is_pure_expr(index),
        Expr::BinOp { left, right, .. } => is_pure_expr(left) && is_pure_expr(right),
        Expr::UnOp { operand, .. } | Expr::Cast { value: operand, .. } => is_pure_expr(operand),
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => is_pure_expr(cond) && is_pure_expr(true_val) && is_pure_expr(false_val),
        Expr::Fma { a, b, c } => is_pure_expr(a) && is_pure_expr(b) && is_pure_expr(c),
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
        | Expr::SubgroupSize => true,
    }
}

fn count_var_uses(nodes: &[Node]) -> FxHashMap<String, usize> {
    let mut counts = FxHashMap::default();
    for node in nodes {
        count_node_uses(node, &mut counts);
    }
    counts
}

fn count_node_uses(node: &Node, counts: &mut FxHashMap<String, usize>) {
    match node {
        Node::Let { value, .. } | Node::Assign { value, .. } => count_expr_uses(value, counts),
        Node::Store { index, value, .. } => {
            count_expr_uses(index, counts);
            count_expr_uses(value, counts);
        }
        Node::If {
            cond,
            then,
            otherwise,
        } => {
            count_expr_uses(cond, counts);
            for node in then.iter().chain(otherwise.iter()) {
                count_node_uses(node, counts);
            }
        }
        Node::Loop { from, to, body, .. } => {
            count_expr_uses(from, counts);
            count_expr_uses(to, counts);
            for node in body {
                count_node_uses(node, counts);
            }
        }
        Node::Block(nodes) => {
            for node in nodes {
                count_node_uses(node, counts);
            }
        }
        Node::Return
        | Node::Barrier
        | Node::IndirectDispatch { .. }
        | Node::AsyncLoad { .. }
        | Node::AsyncStore { .. }
        | Node::AsyncWait { .. }
        | Node::Trap { .. }
        | Node::Resume { .. }
        | Node::Region { .. }
        | Node::Opaque(_) => {}
    }
}

fn count_expr_uses(expr: &Expr, counts: &mut FxHashMap<String, usize>) {
    match expr {
        Expr::Var(name) => {
            *counts.entry(name.to_string()).or_insert(0) += 1;
        }
        Expr::Load { index, .. } => count_expr_uses(index, counts),
        Expr::BinOp { left, right, .. } => {
            count_expr_uses(left, counts);
            count_expr_uses(right, counts);
        }
        Expr::UnOp { operand, .. } | Expr::Cast { value: operand, .. } => {
            count_expr_uses(operand, counts);
        }
        Expr::Call { args, .. } => {
            for arg in args {
                count_expr_uses(arg, counts);
            }
        }
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => {
            count_expr_uses(cond, counts);
            count_expr_uses(true_val, counts);
            count_expr_uses(false_val, counts);
        }
        Expr::Fma { a, b, c } => {
            count_expr_uses(a, counts);
            count_expr_uses(b, counts);
            count_expr_uses(c, counts);
        }
        Expr::Atomic {
            index,
            expected,
            value,
            ..
        } => {
            count_expr_uses(index, counts);
            if let Some(expected) = expected {
                count_expr_uses(expected, counts);
            }
            count_expr_uses(value, counts);
        }
        Expr::LitU32(_)
        | Expr::LitI32(_)
        | Expr::LitF32(_)
        | Expr::LitBool(_)
        | Expr::BufLen { .. }
        | Expr::InvocationId { .. }
        | Expr::WorkgroupId { .. }
        | Expr::LocalId { .. }
        | Expr::SubgroupLocalId
        | Expr::SubgroupSize
        | Expr::SubgroupBallot { .. }
        | Expr::SubgroupShuffle { .. }
        | Expr::SubgroupAdd { .. } => {}
        Expr::Opaque(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BufferDecl, DataType};
    use crate::optimizer::{PassKind, PassScheduler};

    #[test]
    fn preserves_happens_before_for_load_followed_by_write() {
        let program = Program::wrapped(
            vec![
                BufferDecl::read_write("state", 0, DataType::U32).with_count(1),
                BufferDecl::output("out", 1, DataType::U32).with_count(1),
            ],
            [1, 1, 1],
            vec![
                Node::let_bind("snapshot", Expr::load("state", Expr::u32(0))),
                Node::store("state", Expr::u32(0), Expr::u32(7)),
                Node::store("out", Expr::u32(0), Expr::var("snapshot")),
            ],
        );

        let optimized = PassScheduler::with_passes(vec![PassKind::Fusion(Fusion)])
            .run(program)
            .expect("Fix: fusion must preserve happens-before ordering.");

        let body = match optimized.entry() {
            [Node::Region { body, .. }] => body.as_ref(),
            entry => panic!("Fix: fusion output must preserve the root region, got {entry:?}"),
        };

        assert!(matches!(
            body.as_slice(),
            [
                Node::Let {
                    name,
                    value: Expr::Load { buffer, .. }
                },
                Node::Store { buffer: state, .. },
                Node::Store {
                    buffer: out,
                    value: Expr::Var(snapshot),
                    ..
                }
            ] if name == "snapshot"
                && buffer == "state"
                && state == "state"
                && out == "out"
                && snapshot == "snapshot"
        ));
    }

    #[test]
    fn fusion_keeps_snapshot_before_later_state_write() {
        let program = Program::wrapped(
            vec![
                BufferDecl::read_write("state", 0, DataType::U32).with_count(1),
                BufferDecl::output("out", 1, DataType::U32).with_count(1),
            ],
            [1, 1, 1],
            vec![
                Node::store("state", Expr::u32(0), Expr::u32(5)),
                Node::let_bind("snapshot", Expr::load("state", Expr::u32(0))),
                Node::store("state", Expr::u32(0), Expr::u32(9)),
                Node::store("out", Expr::u32(0), Expr::var("snapshot")),
            ],
        );

        let optimized = PassScheduler::with_passes(vec![PassKind::Fusion(Fusion)])
            .run(program)
            .expect("Fix: fusion must preserve happens-before ordering.");

        let body = match optimized.entry() {
            [Node::Region { body, .. }] => body.as_ref(),
            entry => panic!("Fix: fusion output must preserve the root region, got {entry:?}"),
        };

        assert!(
            matches!(
                body.as_slice(),
                [
                    Node::Store {
                        buffer: initial_state,
                        value: Expr::LitU32(5),
                        ..
                    },
                    Node::Let {
                        name,
                        value: Expr::Load { buffer: snapshot_source, .. }
                    },
                    Node::Store {
                        buffer: later_state,
                        value: Expr::LitU32(9),
                        ..
                    },
                    Node::Store {
                        buffer: out,
                        value: Expr::Var(snapshot),
                        ..
                    }
                ] if initial_state == "state"
                    && name == "snapshot"
                    && snapshot_source == "state"
                    && later_state == "state"
                    && out == "out"
                    && snapshot == "snapshot"
            ),
            "Fix: fusion must not move the snapshot load after the later state write."
        );
    }
}
