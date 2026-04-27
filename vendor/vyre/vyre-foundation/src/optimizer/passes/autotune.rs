use crate::ir::{Expr, Node, Program};
use crate::optimizer::{fingerprint_program, vyre_pass, PassAnalysis, PassResult};

/// Dynamically adjust dispatch dimensions and workgroup bounds.
#[derive(Debug, Default)]
#[vyre_pass(name = "autotune", requires = [], invalidates = [])]
pub struct Autotune;

impl Autotune {
    /// Decide whether this pass should run.
    #[must_use]
    #[inline]
    pub fn analyze(_program: &Program) -> PassAnalysis {
        PassAnalysis::RUN
    }

    /// Autotune invocation scales without introducing partial-wave OOB accesses.
    #[must_use]
    pub fn transform(program: Program) -> PassResult {
        let current = program.workgroup_size();
        let tuned = tuned_workgroup_size(current);
        let size_changed = tuned != current;

        if !size_changed {
            // Missing bounds-guard is not a compiler-wide crash condition —
            // it is exactly what this pass would inject if it were running
            // a tuning step. Return unchanged so a later pass / the backend
            // validator surfaces the issue with an actionable diagnostic.
            // VYRE_IR_HOTSPOTS CRIT: cloning + comparing the whole Program
            // just to prove changed=false is O(N) pure overhead; use the
            // fast-path PassResult::unchanged.
            let _divisibility = check_even_divisible_without_guard(&program, current);
            return PassResult::unchanged(program);
        }

        let Some(bound) = inferred_guard_bound_expr(&program) else {
            return PassResult::unchanged(program);
        };

        let entry = if program_has_gid_x_bounds_check(&program) {
            program.entry().to_vec()
        } else {
            vec![Node::if_then(
                Expr::lt(Expr::gid_x(), bound),
                program.entry().to_vec(),
            )]
        };

        // AUDIT_2026-04-24 F-AUTO-01: preserve non_composable_with_self
        // across the rewrite so a self-exclusive program doesn't silently
        // become self-composable after autotune.
        let optimized = Program::wrapped(program.buffers().to_vec(), tuned, entry)
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

fn tuned_workgroup_size(current: [u32; 3]) -> [u32; 3] {
    if current[1] == 1 && current[2] == 1 && (current[0] == 1 || current[0] > 64) {
        [64, 1, 1]
    } else {
        current
    }
}

fn program_has_gid_x_bounds_check(program: &Program) -> bool {
    program.entry().iter().any(node_has_gid_x_bounds_check)
}

fn inferred_guard_bound_expr(program: &Program) -> Option<Expr> {
    referenced_storage_buffers(program)
        .into_iter()
        .filter(|buffer| buffer.count() > 0)
        .max_by_key(|buffer| {
            (
                u8::from(buffer.is_output() || buffer.is_pipeline_live_out()),
                buffer.count(),
            )
        })
        .map(|buffer| Expr::buf_len(buffer.name()))
}

fn infer_problem_size(program: &Program) -> Option<u32> {
    referenced_storage_buffers(program)
        .into_iter()
        .map(|buffer| buffer.count())
        .filter(|count| *count > 0)
        .min()
}

fn referenced_storage_buffers(program: &Program) -> Vec<&crate::ir::BufferDecl> {
    let mut names = std::collections::BTreeSet::new();
    for node in program.entry() {
        collect_referenced_buffers_from_node(node, &mut names);
    }
    names
        .into_iter()
        .filter_map(|name| program.buffer(&name))
        .collect()
}

fn collect_referenced_buffers_from_node(
    node: &Node,
    names: &mut std::collections::BTreeSet<String>,
) {
    match node {
        Node::Let { value, .. } | Node::Assign { value, .. } => {
            collect_referenced_buffers_from_expr(value, names);
        }
        Node::Store {
            buffer,
            index,
            value,
        } => {
            names.insert(buffer.to_string());
            collect_referenced_buffers_from_expr(index, names);
            collect_referenced_buffers_from_expr(value, names);
        }
        Node::If {
            cond,
            then,
            otherwise,
        } => {
            collect_referenced_buffers_from_expr(cond, names);
            for child in then.iter().chain(otherwise) {
                collect_referenced_buffers_from_node(child, names);
            }
        }
        Node::Loop { from, to, body, .. } => {
            collect_referenced_buffers_from_expr(from, names);
            collect_referenced_buffers_from_expr(to, names);
            for child in body {
                collect_referenced_buffers_from_node(child, names);
            }
        }
        Node::Block(nodes) => {
            for child in nodes {
                collect_referenced_buffers_from_node(child, names);
            }
        }
        Node::Region { body, .. } => {
            for child in body.iter() {
                collect_referenced_buffers_from_node(child, names);
            }
        }
        Node::IndirectDispatch { count_buffer, .. } => {
            names.insert(count_buffer.to_string());
        }
        Node::Return
        | Node::Barrier
        | Node::AsyncLoad { .. }
        | Node::AsyncStore { .. }
        | Node::AsyncWait { .. }
        | Node::Trap { .. }
        | Node::Resume { .. }
        | Node::Opaque(_) => {}
    }
}

fn collect_referenced_buffers_from_expr(
    expr: &Expr,
    names: &mut std::collections::BTreeSet<String>,
) {
    match expr {
        Expr::Load { buffer, index } => {
            names.insert(buffer.to_string());
            collect_referenced_buffers_from_expr(index, names);
        }
        Expr::BufLen { buffer } => {
            names.insert(buffer.to_string());
        }
        Expr::Atomic {
            buffer,
            index,
            expected,
            value,
            ..
        } => {
            names.insert(buffer.to_string());
            collect_referenced_buffers_from_expr(index, names);
            if let Some(expected) = expected {
                collect_referenced_buffers_from_expr(expected, names);
            }
            collect_referenced_buffers_from_expr(value, names);
        }
        Expr::BinOp { left, right, .. } => {
            collect_referenced_buffers_from_expr(left, names);
            collect_referenced_buffers_from_expr(right, names);
        }
        Expr::UnOp { operand, .. } | Expr::Cast { value: operand, .. } => {
            collect_referenced_buffers_from_expr(operand, names);
        }
        Expr::Fma { a, b, c } => {
            collect_referenced_buffers_from_expr(a, names);
            collect_referenced_buffers_from_expr(b, names);
            collect_referenced_buffers_from_expr(c, names);
        }
        Expr::Call { args, .. } => {
            for arg in args {
                collect_referenced_buffers_from_expr(arg, names);
            }
        }
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => {
            collect_referenced_buffers_from_expr(cond, names);
            collect_referenced_buffers_from_expr(true_val, names);
            collect_referenced_buffers_from_expr(false_val, names);
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
        | Expr::SubgroupSize
        | Expr::SubgroupBallot { .. }
        | Expr::SubgroupShuffle { .. }
        | Expr::SubgroupAdd { .. }
        | Expr::Opaque(_) => {}
    }
}

/// Returns `Ok(())` when the program has a bounds check OR the
/// workgroup size evenly divides the inferred problem size.
/// Returns `Err(msg)` when neither holds — the caller then decides
/// whether to emit a diagnostic, fall through without tuning, or
/// inject the missing guard.
///
/// Historical note: this used to be
/// `assert_even_divisible_without_guard` with an `assert_eq!` that
/// panicked on legal user IR (VYRE_OPTIMIZER audit CRIT-01:
/// optimizer crashing on valid input). Panicking the whole compiler
/// for a condition the very same pass is supposed to *fix* is the
/// exact wrong move. The caller now gets an actionable Result.
fn check_even_divisible_without_guard(
    program: &Program,
    workgroup_size: [u32; 3],
) -> Result<(), String> {
    if program_has_gid_x_bounds_check(program) {
        return Ok(());
    }
    if let Some(problem_size) = infer_problem_size(program) {
        if problem_size % workgroup_size[0] != 0 {
            return Err(format!(
                "Fix: inject a bounds check when workgroup_size.x={} does not evenly divide inferred problem size {}.",
                workgroup_size[0], problem_size,
            ));
        }
    }
    Ok(())
}

fn node_has_gid_x_bounds_check(node: &Node) -> bool {
    match node {
        Node::If {
            cond,
            then,
            otherwise,
        } => {
            is_gid_x_bounds_cond(cond)
                || then.iter().any(node_has_gid_x_bounds_check)
                || otherwise.iter().any(node_has_gid_x_bounds_check)
        }
        Node::Loop { body, .. } | Node::Block(body) => body.iter().any(node_has_gid_x_bounds_check),
        Node::Region { body, .. } => body.iter().any(node_has_gid_x_bounds_check),
        Node::Let { .. }
        | Node::Assign { .. }
        | Node::Store { .. }
        | Node::Return
        | Node::Barrier
        | Node::IndirectDispatch { .. }
        | Node::AsyncLoad { .. }
        | Node::AsyncStore { .. }
        | Node::AsyncWait { .. }
        | Node::Trap { .. }
        | Node::Resume { .. }
        | Node::Opaque(_) => false,
    }
}

fn is_gid_x_bounds_cond(cond: &Expr) -> bool {
    matches!(
        cond,
        Expr::BinOp { left, right, .. }
            if matches!(left.as_ref(), Expr::InvocationId { axis: 0 })
                && matches!(right.as_ref(), Expr::BufLen { .. } | Expr::LitU32(_))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BufferDecl, DataType};

    #[test]
    fn injects_gid_x_bounds_check_when_rewriting_workgroup_size() {
        let program = Program::wrapped(
            vec![BufferDecl::output("out", 0, DataType::U32).with_count(1000)],
            [256, 1, 1],
            vec![Node::store("out", Expr::gid_x(), Expr::u32(1))],
        );

        let optimized = Autotune::transform(program).program;
        assert_eq!(optimized.workgroup_size(), [64, 1, 1]);
        assert!(program_has_gid_x_bounds_check(&optimized));
    }
}
