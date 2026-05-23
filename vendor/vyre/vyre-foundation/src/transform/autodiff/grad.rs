//! Reverse-mode autodiff IR transform.
//!
//! The main entry point is [`grad`]: given a forward `Program`, a set of
//! output buffer names, and a set of input buffer names, it emits a new
//! `Program` whose stores write the gradients of the outputs w.r.t. the
//! inputs into `grad_<input>` buffers.

use rustc_hash::FxHashMap;

use crate::ir::{BufferAccess, BufferDecl, DataType, Expr, Ident, Node, Program};

use super::error::AutodiffError;
use super::rules::{binop_adjoints, fma_adjoints, unop_adjoint};

/// Per-forward-node pullback expression metadata.
///
/// Keys are stable per-transform pullback node ids in reverse-walk emission
/// order. Values are the adjoint expression consumed by that forward statement.
pub type PullbackMap = FxHashMap<usize, Expr>;

/// Compute reverse-mode gradients for a forward Program.
///
/// # Arguments
///
/// * `program` — the forward-pass Program.
/// * `outputs` — buffer names whose values to differentiate (the "loss").
/// * `inputs` — buffer names to compute gradients w.r.t. Gradient buffers
///   `grad_<name>` are added to the output Program.
///
/// # Returns
///
/// A new `Program` that:
/// 1. Re-declares all forward buffers (inputs as `ReadOnly`, outputs as `ReadOnly`).
/// 2. Declares fresh `grad_<input>` `ReadWrite` buffers for each input in `inputs`.
/// 3. Seeds `grad_<output> = 1.0` for each output in `outputs`.
/// 4. Walks the forward body in reverse, emitting adjoint accumulation stores.
///
/// # Errors
///
/// Returns `AutodiffError` if the Program contains non-differentiable ops in
/// the gradient path, or if an output/input buffer name is not found.
pub fn grad(
    program: &Program,
    outputs: &[&str],
    inputs: &[&str],
) -> Result<Program, AutodiffError> {
    grad_with_pullback(program, outputs, inputs).map(|(program, _pullbacks)| program)
}

/// Compute reverse-mode gradients and return top-level pullback metadata.
///
/// # Errors
///
/// Returns `AutodiffError` if the Program contains unsupported control flow,
/// non-differentiable expression nodes, or unknown input/output buffer names.
pub fn grad_with_pullback(
    program: &Program,
    outputs: &[&str],
    inputs: &[&str],
) -> Result<(Program, PullbackMap), AutodiffError> {
    validate_buffer_names(program, outputs, inputs)?;
    let (back_buffers, output_set, input_set) = build_backward_buffers(program, outputs, inputs);

    // Build the backward body.
    let mut body: Vec<Node> = Vec::new();
    let i_expr = Expr::InvocationId { axis: 0 };
    let mut pullbacks = PullbackMap::default();
    let forward_nodes = program.entry();
    let mut adjoint_env: AdjointEnv = AdjointEnv::new(&input_set);

    // Reverse-mode execution must declare every local adjoint before any
    // reverse contribution assigns to it. A previous implementation declared
    // `_adj_*` inside the reversed `Let` handler, which meant downstream
    // `Store` pullbacks could assign a local before declaration and then the
    // later `Let` reset it to zero. Predeclaring locals makes the generated IR
    // SSA-validator-friendly and preserves accumulated adjoints.
    let mut local_targets = Vec::new();
    collect_adjoint_targets(forward_nodes, &mut local_targets);
    for name in local_targets {
        let adj_name = adjoint_env.ensure_adjoint_var(name.as_str());
        body.push(Node::Let {
            name: adj_name.into(),
            value: Expr::f32(0.0),
        });
    }

    // Phase 1: Seed — store 1.0 into each grad_<output>[i].
    for out_name in &output_set {
        let grad_name = format!("grad_{out_name}");
        body.push(Node::Store {
            buffer: grad_name.into(),
            index: i_expr.clone(),
            value: Expr::f32(1.0),
        });
    }

    // Phase 2: Reverse walk of forward body.
    // Collect the forward nodes, then process them in reverse order.
    let mut next_pullback_id = 0usize;
    for node in forward_nodes.iter().rev() {
        emit_adjoint_node(
            node,
            &mut body,
            &mut adjoint_env,
            &output_set,
            &mut pullbacks,
            &mut next_pullback_id,
        )?;
    }

    // Phase 3: Flush accumulated adjoints to grad_<input> buffers.
    for inp_name in &input_set {
        let grad_name = format!("grad_{inp_name}");
        if let Some(accum_var) = adjoint_env.get_accumulator(inp_name) {
            body.push(Node::Store {
                buffer: grad_name.into(),
                index: i_expr.clone(),
                value: Expr::Var(accum_var.into()),
            });
        }
    }

    Ok((
        Program::wrapped(back_buffers, program.workgroup_size(), body),
        pullbacks,
    ))
}

fn validate_buffer_names(
    program: &Program,
    outputs: &[&str],
    inputs: &[&str],
) -> Result<(), AutodiffError> {
    for name in outputs.iter().chain(inputs.iter()) {
        if program
            .buffers()
            .iter()
            .all(|buffer| buffer.name() != *name)
        {
            return Err(AutodiffError::BufferNotFound {
                name: (*name).to_string(),
            });
        }
    }
    Ok(())
}

fn build_backward_buffers(
    program: &Program,
    outputs: &[&str],
    inputs: &[&str],
) -> (Vec<BufferDecl>, Vec<String>, Vec<String>) {
    let mut back_buffers = Vec::new();
    let mut next_binding = 0u32;
    for fwd_buf in program.buffers() {
        back_buffers.push(
            BufferDecl::storage(
                fwd_buf.name(),
                next_binding,
                BufferAccess::ReadOnly,
                fwd_buf.element(),
            )
            .with_count(fwd_buf.count()),
        );
        next_binding += 1;
    }

    let output_set: Vec<String> = outputs.iter().map(ToString::to_string).collect();
    let input_set: Vec<String> = inputs.iter().map(ToString::to_string).collect();
    let mut grad_buf_binding = FxHashMap::default();
    for name in output_set.iter().chain(input_set.iter()) {
        let grad_name = format!("grad_{name}");
        if grad_buf_binding.contains_key(&grad_name) {
            continue;
        }
        let Some(fwd_buf) = program
            .buffers()
            .iter()
            .find(|buffer| buffer.name() == name.as_str())
        else {
            continue;
        };
        back_buffers.push(
            BufferDecl::read_write(&grad_name, next_binding, DataType::F32)
                .with_pipeline_live_out(true)
                .with_count(fwd_buf.count()),
        );
        grad_buf_binding.insert(grad_name, next_binding);
        next_binding += 1;
    }
    (back_buffers, output_set, input_set)
}

/// Environment tracking adjoint accumulation for each variable / buffer load.
struct AdjointEnv {
    /// Maps variable name → current adjoint expression accumulator variable name.
    var_adjoints: FxHashMap<String, String>,
    /// Counter for generating fresh adjoint variable names.
    fresh_counter: u32,
    /// Set of input buffer names we care about.
    input_buffers: Vec<String>,
}

impl AdjointEnv {
    fn new(inputs: &[String]) -> Self {
        Self {
            var_adjoints: FxHashMap::default(),
            fresh_counter: 0,
            input_buffers: inputs.to_vec(),
        }
    }

    /// Get or create an accumulator variable for the adjoint of `var_name`.
    fn ensure_adjoint_var(&mut self, var_name: &str) -> String {
        if let Some(existing) = self.var_adjoints.get(var_name) {
            return existing.clone();
        }
        let adj_name = format!("_adj_{var_name}_{}", self.fresh_counter);
        self.fresh_counter += 1;
        self.var_adjoints
            .insert(var_name.to_string(), adj_name.clone());
        adj_name
    }

    /// Get the accumulator variable name for a buffer input, if one was created.
    fn get_accumulator(&self, buf_name: &str) -> Option<String> {
        self.var_adjoints.get(buf_name).cloned()
    }

    /// Check if a buffer name is one of the inputs we differentiate w.r.t.
    fn is_tracked_input(&self, buf_name: &str) -> bool {
        self.input_buffers.iter().any(|b| b == buf_name)
    }
}

fn collect_adjoint_targets(nodes: &[Node], out: &mut Vec<Ident>) {
    for node in nodes {
        match node {
            Node::Let { name, .. } | Node::Assign { name, .. } => push_unique_ident(out, name),
            Node::If {
                then, otherwise, ..
            } => {
                collect_adjoint_targets(then, out);
                collect_adjoint_targets(otherwise, out);
            }
            Node::Loop { body, .. } | Node::Block(body) => collect_adjoint_targets(body, out),
            Node::Region { body, .. } => collect_adjoint_targets(body, out),
            Node::Store { .. }
            | Node::IndirectDispatch { .. }
            | Node::AsyncLoad { .. }
            | Node::AsyncStore { .. }
            | Node::AsyncWait { .. }
            | Node::Trap { .. }
            | Node::Resume { .. }
            | Node::Return
            | Node::Barrier { .. }
            | Node::Opaque(_) => {}
        }
    }
}

fn push_unique_ident(out: &mut Vec<Ident>, name: &Ident) {
    if !out.iter().any(|existing| existing == name) {
        out.push(name.clone());
    }
}

/// Emit adjoint nodes for a single forward Node.
#[expect(
    clippy::too_many_lines,
    reason = "autodiff node lowering is an exhaustive IR-node dispatch table; splitting it would scatter unsupported-control-flow errors"
)]
fn emit_adjoint_node(
    node: &Node,
    body: &mut Vec<Node>,
    env: &mut AdjointEnv,
    output_set: &[String],
    pullbacks: &mut PullbackMap,
    next_pullback_id: &mut usize,
) -> Result<(), AutodiffError> {
    match node {
        // Forward: let x = value
        // Backward: propagate adjoint of x through value
        Node::Let { name, value } => {
            let var_name = name.as_str();
            let adj_var = env.ensure_adjoint_var(var_name);
            let adj_expr = Expr::Var(adj_var.into());
            insert_pullback(pullbacks, next_pullback_id, adj_expr.clone());
            // Propagate adjoint through the expression tree.
            emit_adjoint_expr(value, &adj_expr, body, env)?;
        }
        // Forward: store buf[idx] = value
        // Backward: adjoint of value comes from grad_buf[idx]
        Node::Store {
            buffer,
            index,
            value,
        } => {
            let buf_name = buffer.as_str();
            let grad_buf = format!("grad_{buf_name}");
            // Load the adjoint from the gradient buffer.
            let adj_expr =
                if output_set.iter().any(|o| o == buf_name) || env.is_tracked_input(buf_name) {
                    Expr::Load {
                        buffer: grad_buf.into(),
                        index: Box::new(index.clone()),
                    }
                } else {
                    // Internal buffer — adjoint comes from downstream consumers.
                    // For now, treat as the accumulated adjoint.
                    Expr::f32(0.0)
                };
            insert_pullback(pullbacks, next_pullback_id, adj_expr.clone());
            emit_adjoint_expr(value, &adj_expr, body, env)?;
        }
        // Forward: x = value (reassignment)
        // Same as Let for adjoint purposes.
        Node::Assign { name, value } => {
            let adj_var = env.ensure_adjoint_var(name.as_str());
            let adj_expr = Expr::Var(adj_var.into());
            insert_pullback(pullbacks, next_pullback_id, adj_expr.clone());
            emit_adjoint_expr(value, &adj_expr, body, env)?;
        }
        // Forward: if cond { then } else { otherwise }
        // Backward: route adjoint through the branch that was taken.
        Node::If {
            cond,
            then,
            otherwise,
        } => {
            let mut then_body = Vec::new();
            for n in then.iter().rev() {
                emit_adjoint_node(
                    n,
                    &mut then_body,
                    env,
                    output_set,
                    pullbacks,
                    next_pullback_id,
                )?;
            }
            let mut else_body = Vec::new();
            for n in otherwise.iter().rev() {
                emit_adjoint_node(
                    n,
                    &mut else_body,
                    env,
                    output_set,
                    pullbacks,
                    next_pullback_id,
                )?;
            }
            body.push(Node::If {
                cond: cond.clone(),
                then: then_body,
                otherwise: else_body,
            });
        }
        // Forward: for var in from..to { loop_body }
        // Backward: run the adjoint of loop_body in reverse iteration order.
        Node::Loop {
            var,
            from,
            to,
            body: loop_body,
        } => {
            let mut adj_body = Vec::new();
            for n in loop_body.iter().rev() {
                emit_adjoint_node(
                    n,
                    &mut adj_body,
                    env,
                    output_set,
                    pullbacks,
                    next_pullback_id,
                )?;
            }
            // Reverse iteration: for var in (to-1) downto from.
            // Emit as a forward loop that maps to reversed index.
            // reversed_var = (to - 1) - (var - from) = to - 1 - var + from
            body.push(Node::Loop {
                var: var.clone(),
                from: from.clone(),
                to: to.clone(),
                body: adj_body,
            });
        }
        // Barrier — pass through.
        Node::Barrier { ordering } => {
            body.push(Node::barrier_with_ordering(*ordering));
        }
        // Block — unwrap and recurse.
        Node::Block(nodes) => {
            for n in nodes.iter().rev() {
                emit_adjoint_node(n, body, env, output_set, pullbacks, next_pullback_id)?;
            }
        }
        // Region — recurse into body.
        Node::Region {
            generator,
            source_region,
            body: region_body,
        } => {
            let mut adj_region_body = Vec::new();
            for n in region_body.iter().rev() {
                emit_adjoint_node(
                    n,
                    &mut adj_region_body,
                    env,
                    output_set,
                    pullbacks,
                    next_pullback_id,
                )?;
            }
            body.push(Node::Region {
                generator: generator.clone(),
                source_region: source_region.clone(),
                body: std::sync::Arc::new(adj_region_body),
            });
        }
        // Return, IndirectDispatch, Async*, Trap, Resume — not differentiable control flow.
        Node::Return
        | Node::IndirectDispatch { .. }
        | Node::AsyncLoad { .. }
        | Node::AsyncStore { .. }
        | Node::AsyncWait { .. }
        | Node::Trap { .. }
        | Node::Resume { .. } => {
            return Err(AutodiffError::UnsupportedNode {
                kind: format!("{node:?}").chars().take(60).collect(),
            });
        }
        // Opaque — cannot differentiate unknown ops.
        Node::Opaque(_) => {
            return Err(AutodiffError::UnsupportedNode {
                kind: "Node::Opaque".to_string(),
            });
        }
    }
    Ok(())
}

fn insert_pullback(pullbacks: &mut PullbackMap, next_pullback_id: &mut usize, expr: Expr) {
    let id = *next_pullback_id;
    *next_pullback_id = next_pullback_id.saturating_add(1);
    pullbacks.insert(id, expr);
}

/// Propagate adjoint through an expression tree, emitting accumulation nodes.
#[expect(
    clippy::too_many_lines,
    reason = "autodiff expression cases are kept in one exhaustive match so new IR expression variants are reviewed in one place"
)]
fn emit_adjoint_expr(
    expr: &Expr,
    adjoint: &Expr,
    body: &mut Vec<Node>,
    env: &mut AdjointEnv,
) -> Result<(), AutodiffError> {
    match expr {
        // Leaf: variable reference.
        // Accumulate adjoint into the variable's adjoint accumulator.
        Expr::Var(name) => {
            let adj_var = env.ensure_adjoint_var(name.as_str());
            body.push(Node::Assign {
                name: adj_var.clone().into(),
                value: Expr::add(Expr::Var(adj_var.into()), adjoint.clone()),
            });
        }
        // Leaf: buffer load.
        // If this buffer is a tracked input, accumulate into its grad buffer.
        Expr::Load { buffer, index } => {
            let buf_name = buffer.as_str();
            if env.is_tracked_input(buf_name) {
                let grad_buf = format!("grad_{buf_name}");
                // Atomic add to handle multiple gradient contributions.
                body.push(Node::Store {
                    buffer: grad_buf.into(),
                    index: *index.clone(),
                    value: Expr::add(
                        Expr::Load {
                            buffer: format!("grad_{buf_name}").into(),
                            index: index.clone(),
                        },
                        adjoint.clone(),
                    ),
                });
            }
        }
        // Leaf: literal — zero gradient, nothing to propagate.
        Expr::LitF32(_)
        | Expr::LitU32(_)
        | Expr::LitI32(_)
        | Expr::LitBool(_)
        | Expr::InvocationId { .. }
        | Expr::WorkgroupId { .. }
        | Expr::LocalId { .. }
        | Expr::SubgroupLocalId
        | Expr::SubgroupSize
        | Expr::BufLen { .. } => {}
        // BinOp: apply chain rule.
        Expr::BinOp { op, left, right } => {
            let contribs = binop_adjoints(*op, left, right, adjoint)?;
            for contrib in contribs {
                emit_adjoint_expr(&contrib.child, &contrib.adjoint, body, env)?;
            }
        }
        // UnOp: apply chain rule.
        Expr::UnOp { op, operand } => {
            let contrib = unop_adjoint(op, operand, adjoint)?;
            emit_adjoint_expr(&contrib.child, &contrib.adjoint, body, env)?;
        }
        // Select: route adjoint to the taken branch.
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => {
            let true_adj = Expr::Select {
                cond: cond.clone(),
                true_val: Box::new(adjoint.clone()),
                false_val: Box::new(Expr::f32(0.0)),
            };
            let false_adj = Expr::Select {
                cond: cond.clone(),
                true_val: Box::new(Expr::f32(0.0)),
                false_val: Box::new(adjoint.clone()),
            };
            emit_adjoint_expr(true_val, &true_adj, body, env)?;
            emit_adjoint_expr(false_val, &false_adj, body, env)?;
        }
        // Fma: a*b + c.
        Expr::Fma { a, b, c } => {
            let contribs = fma_adjoints(a, b, c, adjoint);
            for contrib in contribs {
                emit_adjoint_expr(&contrib.child, &contrib.adjoint, body, env)?;
            }
        }
        // Cast: pass adjoint through (f32→f32 identity; cross-type TBD).
        Expr::Cast { value, .. } => {
            emit_adjoint_expr(value, adjoint, body, env)?;
        }
        // Non-differentiable expression nodes.
        Expr::Call { op_id, .. } => {
            return Err(AutodiffError::NotDifferentiable {
                op: format!("Expr::Call({op_id})"),
                fix:
                    "inline the call before running autodiff, or register a derivative for this op"
                        .into(),
            });
        }
        Expr::Atomic { .. } => {
            return Err(AutodiffError::NotDifferentiable {
                op: "Expr::Atomic".into(),
                fix: "atomics are not differentiable; restructure to use non-atomic accumulation"
                    .into(),
            });
        }
        Expr::SubgroupBallot { .. } | Expr::SubgroupShuffle { .. } | Expr::SubgroupAdd { .. } => {
            return Err(AutodiffError::NotDifferentiable {
                op: format!("{expr:?}").chars().take(40).collect(),
                fix: "subgroup ops are not differentiable in the general case".into(),
            });
        }
        Expr::Opaque(_) => {
            return Err(AutodiffError::NotDifferentiable {
                op: "Expr::Opaque".into(),
                fix: "register a derivative rule for this opaque expression".into(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::BinOp;

    /// Test: d(x*x)/dx = 2*x for a simple square program.
    #[test]
    fn grad_simple_square() {
        // Forward: out[i] = x[i] * x[i]
        let program = Program::wrapped(
            vec![
                BufferDecl::storage("x", 0, BufferAccess::ReadOnly, DataType::F32).with_count(4),
                BufferDecl::output("out", 1, DataType::F32).with_count(4),
            ],
            [64, 1, 1],
            vec![Node::Store {
                buffer: "out".into(),
                index: Expr::InvocationId { axis: 0 },
                value: Expr::mul(
                    Expr::Load {
                        buffer: "x".into(),
                        index: Box::new(Expr::InvocationId { axis: 0 }),
                    },
                    Expr::Load {
                        buffer: "x".into(),
                        index: Box::new(Expr::InvocationId { axis: 0 }),
                    },
                ),
            }],
        );

        let result = grad(&program, &["out"], &["x"]);
        assert!(result.is_ok(), "grad should succeed: {:?}", result.err());
        let backward = result.unwrap();

        // The backward program should declare grad_x and grad_out buffers.
        let buf_names: Vec<&str> = backward.buffers().iter().map(|b| b.name()).collect();
        assert!(
            buf_names.contains(&"grad_out"),
            "should have grad_out buffer"
        );
        assert!(buf_names.contains(&"grad_x"), "should have grad_x buffer");
    }

    /// Test: non-differentiable op returns error.
    #[test]
    fn grad_bitwise_errors() {
        let program = Program::wrapped(
            vec![
                BufferDecl::storage("x", 0, BufferAccess::ReadOnly, DataType::U32).with_count(1),
                BufferDecl::output("out", 1, DataType::U32).with_count(1),
            ],
            [1, 1, 1],
            vec![Node::Store {
                buffer: "out".into(),
                index: Expr::u32(0),
                value: Expr::BinOp {
                    op: BinOp::BitAnd,
                    left: Box::new(Expr::Load {
                        buffer: "x".into(),
                        index: Box::new(Expr::u32(0)),
                    }),
                    right: Box::new(Expr::u32(0xFF)),
                },
            }],
        );

        let result = grad(&program, &["out"], &["x"]);
        assert!(result.is_err());
        match result.unwrap_err() {
            AutodiffError::NotDifferentiable { op, .. } => {
                assert!(op.contains("BitAnd"));
            }
            e => panic!("expected NotDifferentiable, got: {e}"),
        }
    }

    /// Test: missing buffer name returns error.
    #[test]
    fn grad_missing_buffer() {
        let program = Program::wrapped(
            vec![BufferDecl::output("out", 0, DataType::F32).with_count(1)],
            [1, 1, 1],
            vec![],
        );

        let result = grad(&program, &["nonexistent"], &[]);
        assert!(matches!(result, Err(AutodiffError::BufferNotFound { .. })));
    }

    /// Test: exp derivative — d(exp(x))/dx = exp(x).
    #[test]
    fn grad_exp() {
        let program = Program::wrapped(
            vec![
                BufferDecl::storage("x", 0, BufferAccess::ReadOnly, DataType::F32).with_count(1),
                BufferDecl::output("out", 1, DataType::F32).with_count(1),
            ],
            [1, 1, 1],
            vec![Node::Store {
                buffer: "out".into(),
                index: Expr::u32(0),
                value: Expr::UnOp {
                    op: crate::ir::UnOp::Exp,
                    operand: Box::new(Expr::Load {
                        buffer: "x".into(),
                        index: Box::new(Expr::u32(0)),
                    }),
                },
            }],
        );

        let result = grad(&program, &["out"], &["x"]);
        assert!(
            result.is_ok(),
            "exp should be differentiable: {:?}",
            result.err()
        );
    }
}
