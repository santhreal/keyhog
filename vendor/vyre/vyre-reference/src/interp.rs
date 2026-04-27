//! Generic reference interpreter entry points.
//!
//! The stable statement-IR [`reference_eval`] entry point remains delegated to
//! the existing invocation simulator until `Program` stores graph nodes
//! directly.

use std::collections::HashMap;

use vyre::ir::{InterpCtx, Node, NodeId, NodeStorage, Program, Value as IrValue};

use crate::value::Value;

/// If the program satisfies the public top-level-Region model, return a
/// byte-identical clone. If not, the usual case is
/// `transform::optimize::region_inline` having flattened a Category-A wrapper;
/// in that case [`Program::reconcile_runnable_top_level`] matches
/// `Program::wrapped` again. When the first entry node is a `Store` (or the
/// entry is empty), we do **not** auto-wrap: those programs must still use
/// `Program::wrapped` explicitly, matching `region_gate` negative tests.
pub(crate) fn program_for_interpreter(program: &Program) -> Result<Program, vyre::Error> {
    if let Some(message) = program.top_level_region_violation() {
        if program.entry().is_empty() {
            return Err(vyre::Error::interp(format!(
                "reference interpreter requires a top-level Region-wrapped Program: {message}"
            )));
        }
        if matches!(program.entry().first(), Some(Node::Store { .. })) {
            return Err(vyre::Error::interp(format!(
                "reference interpreter requires a top-level Region-wrapped Program: {message}"
            )));
        }
        return Ok(program.clone().reconcile_runnable_top_level());
    }
    Ok(program.clone())
}

/// Execute a vyre IR program on the pure Rust reference interpreter.
///
/// The current public [`Program`] model is statement-oriented, so this stable
/// entry point delegates to the statement evaluator. Graph-shaped extension
/// nodes use [`run_storage_graph`].
pub fn reference_eval(program: &Program, inputs: &[Value]) -> Result<Vec<Value>, vyre::Error> {
    run_arena_reference(program, inputs)
}

/// Execute using the statement-IR reference evaluator.
pub fn run_arena_reference(program: &Program, inputs: &[Value]) -> Result<Vec<Value>, vyre::Error> {
    let program = program_for_interpreter(program)?;
    crate::hashmap_interp::run_hashmap_reference(&program, inputs)
}

/// Differential oracle retained for tests during the generic interpreter transition.
#[cfg(test)]
pub fn eval_hashmap_reference(
    program: &Program,
    inputs: &[Value],
) -> Result<Vec<Value>, vyre::Error> {
    run_arena_reference(program, inputs)
}

/// Interpret a compact [`NodeStorage`] graph and return output node values.
pub fn run_storage_graph(
    nodes: &[(NodeId, NodeStorage)],
    outputs: &[NodeId],
) -> Result<Vec<IrValue>, vyre::Error> {
    let graph = nodes.iter().cloned().collect::<HashMap<_, _>>();
    let mut ctx = InterpCtx::default();
    let mut states = HashMap::with_capacity(graph.len());

    for output in outputs {
        eval_storage_node(*output, &graph, &mut ctx, &mut states)?;
    }

    outputs
        .iter()
        .map(|id| ctx.get(*id).map_err(interp_error))
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VisitState {
    Visiting,
    Done,
}

fn eval_storage_node(
    id: NodeId,
    graph: &HashMap<NodeId, NodeStorage>,
    ctx: &mut InterpCtx,
    states: &mut HashMap<NodeId, VisitState>,
) -> Result<(), vyre::Error> {
    match states.get(&id).copied() {
        Some(VisitState::Done) => return Ok(()),
        Some(VisitState::Visiting) => return Err(cycle_error(id)),
        None => {}
    }

    let node = graph.get(&id).ok_or_else(|| missing_node_error(id))?;
    states.insert(id, VisitState::Visiting);
    let inputs = node.input_ids();
    for input in &inputs {
        eval_storage_node(*input, graph, ctx, states)?;
    }
    ctx.set_operands(inputs);
    let value = node.interpret(ctx).map_err(interp_error)?;
    ctx.set(id, value);
    states.insert(id, VisitState::Done);
    Ok(())
}

fn interp_error(error: vyre::ir::EvalError) -> vyre::Error {
    vyre::Error::interp(error.to_string())
}

fn missing_node_error(id: NodeId) -> vyre::Error {
    vyre::Error::interp(format!(
        "graph references missing node {}. Fix: include every dependency in the interpreter input graph.",
        id.0
    ))
}

fn cycle_error(id: NodeId) -> vyre::Error {
    vyre::Error::interp(format!(
        "graph contains a dependency cycle at node {}. Fix: submit an acyclic dataflow graph.",
        id.0
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre::ir::{BinOp, NodeStorage};

    #[test]
    fn generic_storage_graph_matches_recursive_oracle_for_10k_programs() {
        let mut rng = 0x9e37_79b9_u64;
        for case in 0..10_000 {
            let graph = random_graph(&mut rng, case);
            let output = graph.last().expect("Fix: generated graph is non-empty").0;
            let expected =
                recursive_value(output, &graph).expect("Fix: recursive oracle evaluates");
            let actual = run_storage_graph(&graph, &[output])
                .expect("Fix: generic graph interpreter evaluates")[0];
            assert_eq!(actual, expected, "case {case}");
        }
    }

    fn random_graph(rng: &mut u64, case: u32) -> Vec<(NodeId, NodeStorage)> {
        let len = 2 + (next(rng) as usize % 31);
        let mut graph = Vec::with_capacity(len);
        graph.push((NodeId(0), NodeStorage::LitU32(case)));
        graph.push((NodeId(1), NodeStorage::LitU32(next(rng))));
        for index in 2..len {
            let left = NodeId(next(rng) % index as u32);
            let right = NodeId(next(rng) % index as u32);
            let op = match next(rng) % 5 {
                0 => BinOp::Add,
                1 => BinOp::Sub,
                2 => BinOp::Mul,
                3 => BinOp::BitXor,
                _ => BinOp::BitAnd,
            };
            graph.push((NodeId(index as u32), NodeStorage::BinOp { op, left, right }));
        }
        graph
    }

    fn recursive_value(
        id: NodeId,
        graph: &[(NodeId, NodeStorage)],
    ) -> Result<IrValue, vyre::Error> {
        let node = graph
            .iter()
            .find(|(node_id, _)| *node_id == id)
            .map(|(_, node)| node)
            .ok_or_else(|| missing_node_error(id))?;
        match node {
            NodeStorage::LitU32(value) => Ok(IrValue::U32(*value)),
            NodeStorage::BinOp { op, left, right } => {
                let left = expect_u32(recursive_value(*left, graph)?)?;
                let right = expect_u32(recursive_value(*right, graph)?)?;
                let value = match op {
                    BinOp::Add => left.wrapping_add(right),
                    BinOp::Sub => left.wrapping_sub(right),
                    BinOp::Mul => left.wrapping_mul(right),
                    BinOp::BitXor => left ^ right,
                    BinOp::BitAnd => left & right,
                    _ => {
                        return Err(vyre::Error::interp(
                            "recursive parity oracle received unsupported op. Fix: keep test generation within the oracle domain.",
                        ));
                    }
                };
                Ok(IrValue::U32(value))
            }
            _ => Err(vyre::Error::interp(
                "recursive parity oracle received unsupported node. Fix: keep test generation within the oracle domain.",
            )),
        }
    }

    fn expect_u32(value: IrValue) -> Result<u32, vyre::Error> {
        match value {
            IrValue::U32(value) => Ok(value),
            other => Err(vyre::Error::interp(format!(
                "recursive parity oracle expected u32, got {other:?}. Fix: keep generated graphs scalar-u32 only."
            ))),
        }
    }

    fn next(rng: &mut u64) -> u32 {
        *rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
        (*rng >> 32) as u32
    }
}
