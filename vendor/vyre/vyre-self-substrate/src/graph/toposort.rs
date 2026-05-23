//! DAG topological-sort substrate consumer.
//!
//! Wires `vyre_primitives::graph::toposort::toposort` (zero prior
//! consumers) and `reachable::reachable` so the optimizer's pass
//! scheduler / megakernel scheduler / dispatch ordering can rely on
//! the same primitive downstream analyzer ships to user dialects. Replaces ad-hoc
//! Kahn's-algorithm reimplementations the optimizer carried inline.

#[cfg(test)]
use std::collections::HashSet;

use crate::dispatch_buffers::{
    decode_u32_output_exact, ensure_input_slots, u32_word_bytes, write_u32_slice_le_bytes,
    write_zero_bytes,
};
use crate::optimizer::dispatcher::{DispatchError, OptimizerDispatcher};
#[cfg(test)]
use vyre_primitives::graph::reachable::{reachable as reachable_cpu, UnknownNode};
#[cfg(test)]
use vyre_primitives::graph::toposort::{
    toposort as toposort_cpu, toposort_csr_into, toposort_program, validate_toposort_csr_inputs,
    validate_toposort_csr_order, ToposortCsrError, ToposortError,
};
#[cfg(not(test))]
use vyre_primitives::graph::toposort::{
    toposort_program, validate_toposort_csr_inputs, validate_toposort_csr_order, ToposortCsrError,
};

/// Caller-owned GPU dispatch scratch for topological-sort CSR queries.
#[derive(Debug, Default)]
pub struct ToposortGpuScratch {
    inputs: Vec<Vec<u8>>,
}

/// Topologically sort `(node_count, edges)`. Edges encode "from
/// depends on to", so `to` is emitted before `from`. Bumps the
/// dataflow-fixpoint substrate counter so the dispatch path
/// registers every ordering query.
///
/// # Errors
///
/// Forwards `ToposortError::Cycle` when the graph has a cycle and
/// `ToposortError::UnknownNode` when an edge references an
/// out-of-range node id.
#[cfg(test)]
pub fn reference_topo_order(
    node_count: u32,
    edges: &[(u32, u32)],
) -> Result<Vec<u32>, ToposortError> {
    use crate::observability::{bump, dataflow_fixpoint_calls};
    bump(&dataflow_fixpoint_calls);
    toposort_cpu(node_count, edges)
}

/// Topologically sort a dependency graph through the dispatcher using the
/// primitive-native CSR representation.
///
/// `offsets` has `node_count + 1` entries and `targets` stores outgoing edges
/// from each prerequisite node to its dependent nodes. This is the adjacency
/// shape consumed by [`toposort_program`].
///
/// # Errors
///
/// Returns [`DispatchError`] when CSR shape validation fails, the backend
/// rejects the primitive, or the returned order is not a full permutation of
/// `0..node_count` (cycle or malformed backend output).
pub fn topo_order_csr_via(
    dispatcher: &impl OptimizerDispatcher,
    node_count: u32,
    offsets: &[u32],
    targets: &[u32],
) -> Result<Vec<u32>, DispatchError> {
    let mut scratch = ToposortGpuScratch::default();
    let mut order = Vec::new();
    topo_order_csr_via_with_scratch_into(
        dispatcher,
        node_count,
        offsets,
        targets,
        &mut scratch,
        &mut order,
    )?;
    Ok(order)
}

/// Topologically sort a dependency graph through the dispatcher using caller-owned scratch.
pub fn topo_order_csr_via_with_scratch(
    dispatcher: &impl OptimizerDispatcher,
    node_count: u32,
    offsets: &[u32],
    targets: &[u32],
    scratch: &mut ToposortGpuScratch,
) -> Result<Vec<u32>, DispatchError> {
    let mut order = Vec::new();
    topo_order_csr_via_with_scratch_into(
        dispatcher, node_count, offsets, targets, scratch, &mut order,
    )?;
    Ok(order)
}

/// Topologically sort a dependency graph into caller-owned output storage.
pub fn topo_order_csr_via_with_scratch_into(
    dispatcher: &impl OptimizerDispatcher,
    node_count: u32,
    offsets: &[u32],
    targets: &[u32],
    scratch: &mut ToposortGpuScratch,
    order: &mut Vec<u32>,
) -> Result<(), DispatchError> {
    use crate::observability::{bump, dataflow_fixpoint_calls};
    bump(&dataflow_fixpoint_calls);

    let layout = validate_toposort_csr_inputs(node_count, offsets, targets)
        .map_err(map_toposort_csr_input_error)?;
    if layout.node_count == 0 {
        order.clear();
        return Ok(());
    }

    let program = toposort_program(
        layout.node_count,
        "offsets",
        "targets",
        "indeg_scratch",
        "queue_scratch",
        "order_out",
    );
    let node_bytes = u32_word_bytes(layout.node_words, "topo_order_csr_via node scratch")?;
    ensure_input_slots(&mut scratch.inputs, 5);
    write_u32_slice_le_bytes(&mut scratch.inputs[0], offsets);
    write_u32_slice_le_bytes(&mut scratch.inputs[1], targets);
    write_zero_bytes(&mut scratch.inputs[2], node_bytes);
    write_zero_bytes(&mut scratch.inputs[3], node_bytes);
    write_zero_bytes(&mut scratch.inputs[4], node_bytes);
    let outputs = dispatcher.dispatch(&program, &scratch.inputs, Some([1, 1, 1]))?;
    if outputs.is_empty() {
        return Err(DispatchError::BackendError(format!(
            "Fix: topo_order_csr_via expected exactly one order output, got {}.",
            outputs.len()
        )));
    }

    decode_u32_output_exact(&outputs[0], layout.node_words, "topo_order_csr_via", order)?;
    map_toposort_csr_error(validate_toposort_csr_order(
        node_count, offsets, targets, order,
    ))
}

/// Compute the set of nodes reachable from `sources` over `edges`.
/// Bumps the dataflow-fixpoint substrate counter.
///
/// # Errors
///
/// Returns `UnknownNode` when an edge names a node id outside
/// `0..node_count`.
#[cfg(test)]
pub fn reference_reachable_set(
    node_count: u32,
    edges: &[(u32, u32)],
    sources: &[u32],
) -> Result<HashSet<u32>, UnknownNode> {
    use crate::observability::{bump, dataflow_fixpoint_calls};
    bump(&dataflow_fixpoint_calls);
    reachable_cpu(node_count, edges, sources)
}

/// Convenience: returns true iff every node in `targets` is in the
/// reachable set of `sources`. Useful for "would running pass set
/// S leave every required predecessor satisfied?" queries.
#[cfg(test)]
pub fn all_reachable(
    node_count: u32,
    edges: &[(u32, u32)],
    sources: &[u32],
    targets: &[u32],
) -> Result<bool, UnknownNode> {
    let reach = reference_reachable_set(node_count, edges, sources)?;
    Ok(targets.iter().all(|t| reach.contains(t)))
}

fn map_toposort_csr_error(result: Result<(), ToposortCsrError>) -> Result<(), DispatchError> {
    match result {
        Ok(()) => Ok(()),
        Err(ToposortCsrError::BadCsr { message }) => Err(DispatchError::BadInputs(message)),
        Err(ToposortCsrError::BadOrder { message }) => Err(DispatchError::BackendError(message)),
        Err(other) => Err(DispatchError::BackendError(format!(
            "Fix: topo_order_csr_via received unknown primitive CSR validation error: {other:?}."
        ))),
    }
}

fn map_toposort_csr_input_error(error: ToposortCsrError) -> DispatchError {
    match error {
        ToposortCsrError::BadCsr { message } => DispatchError::BadInputs(message),
        ToposortCsrError::BadOrder { message } => DispatchError::BackendError(message),
        other => DispatchError::BackendError(format!(
            "Fix: topo_order_csr_via received unknown primitive CSR validation error: {other:?}."
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch_buffers::u32_slice_to_le_bytes;
    use vyre_foundation::ir::Program;

    #[test]
    fn topo_order_chain_emits_dependency_first() {
        // 0 depends on 1 depends on 2. Order should be [2, 1, 0]
        // (Kahn's algorithm on the reverse-dependency graph as
        // encoded — 'to comes first').
        let order = reference_topo_order(3, &[(0, 1), (1, 2)]).unwrap();
        // Verify the ordering invariant: every (from, to) edge has
        // to before from in the output.
        let pos: std::collections::HashMap<u32, usize> =
            order.iter().enumerate().map(|(i, &n)| (n, i)).collect();
        for &(from, to) in &[(0u32, 1u32), (1, 2)] {
            assert!(
                pos[&to] < pos[&from],
                "to ({to}) must precede from ({from}) in toposort"
            );
        }
    }

    #[test]
    fn topo_order_detects_cycle() {
        // 0 -> 1 -> 0 cycle.
        let err = reference_topo_order(2, &[(0, 1), (1, 0)]);
        assert!(matches!(err, Err(ToposortError::Cycle { .. })));
    }

    #[test]
    fn topo_order_rejects_unknown_node() {
        let err = reference_topo_order(2, &[(0, 5)]);
        assert!(matches!(err, Err(ToposortError::UnknownNode { .. })));
    }

    /// Closure-bar: substrate output equals primitive output.
    #[test]
    fn matches_primitive_directly() {
        let edges = [(0u32, 1u32), (1, 2), (0, 2)];
        let via_substrate = reference_topo_order(3, &edges).unwrap();
        let via_primitive = toposort_cpu(3, &edges).unwrap();
        assert_eq!(via_substrate, via_primitive);
    }

    #[test]
    fn reachable_walks_directed_chain() {
        // 0 -> 1 -> 2 -> 3. From {0}, every node is reachable.
        let edges = [(0u32, 1u32), (1, 2), (2, 3)];
        let reach = reference_reachable_set(4, &edges, &[0]).unwrap();
        for n in 0..4 {
            assert!(reach.contains(&n), "node {n} must be reachable from 0");
        }
    }

    #[test]
    fn reachable_does_not_walk_reverse_edges() {
        // 0 -> 1. From {1}, only 1 is reachable.
        let reach = reference_reachable_set(2, &[(0, 1)], &[1]).unwrap();
        assert_eq!(reach.len(), 1);
        assert!(reach.contains(&1));
    }

    /// Adversarial: empty sources yield empty reachable.
    #[test]
    fn reachable_empty_sources_yields_empty_set() {
        let reach = reference_reachable_set(4, &[(0, 1), (1, 2)], &[]).unwrap();
        assert!(reach.is_empty());
    }

    /// Adversarial: a self-loop in sources must terminate (visited
    /// guard). Naive code that doesn't dedupe would loop forever.
    #[test]
    fn reachable_self_loop_terminates() {
        // 0 -> 0 (self-loop), 1 isolated.
        let reach = reference_reachable_set(2, &[(0, 0)], &[0]).unwrap();
        assert_eq!(reach.len(), 1);
        assert!(reach.contains(&0));
    }

    #[test]
    fn all_reachable_satisfies_query() {
        let edges = [(0u32, 1u32), (1, 2), (0, 2)];
        // From {0}, can we reach {1, 2}? Yes.
        assert!(all_reachable(3, &edges, &[0], &[1, 2]).unwrap());
        // From {2}, can we reach {0}? No (DAG is one-way).
        assert!(!all_reachable(3, &edges, &[2], &[0]).unwrap());
    }

    struct ToposortDispatcher;

    impl OptimizerDispatcher for ToposortDispatcher {
        fn dispatch(
            &self,
            _program: &Program,
            inputs: &[Vec<u8>],
            grid_override: Option<[u32; 3]>,
        ) -> Result<Vec<Vec<u8>>, DispatchError> {
            assert_eq!(grid_override, Some([1, 1, 1]));
            assert_eq!(inputs.len(), 5);
            let offsets = read_u32s(&inputs[0]);
            let targets = read_u32s(&inputs[1]);
            let n = offsets.len() - 1;
            let mut out = Vec::with_capacity(n);
            toposort_csr_into(n as u32, &offsets, &targets, &mut out).map_err(|err| {
                DispatchError::BackendError(format!(
                    "Fix: test dispatcher must use the primitive CSR oracle; got {err:?}."
                ))
            })?;
            out.resize(n, 0);
            Ok(vec![u32_slice_to_le_bytes(&out)])
        }
    }

    #[test]
    fn topo_order_csr_via_dispatches_primitive_order() {
        let order = topo_order_csr_via(&ToposortDispatcher, 3, &[0, 2, 3, 3], &[1, 2, 2]).unwrap();
        let pos: std::collections::HashMap<u32, usize> =
            order.iter().enumerate().map(|(i, &n)| (n, i)).collect();
        assert!(pos[&0] < pos[&1]);
        assert!(pos[&0] < pos[&2]);
        assert!(pos[&1] < pos[&2]);
    }

    #[test]
    fn topo_order_csr_via_with_scratch_into_reuses_storage() {
        let mut scratch = ToposortGpuScratch::default();
        let mut order = Vec::with_capacity(3);

        topo_order_csr_via_with_scratch_into(
            &ToposortDispatcher,
            3,
            &[0, 2, 3, 3],
            &[1, 2, 2],
            &mut scratch,
            &mut order,
        )
        .unwrap();
        let order_capacity = order.capacity();
        let input_capacities = scratch.inputs.iter().map(Vec::capacity).collect::<Vec<_>>();
        assert_eq!(order.len(), 3);

        topo_order_csr_via_with_scratch_into(
            &ToposortDispatcher,
            3,
            &[0, 1, 2, 2],
            &[1, 2],
            &mut scratch,
            &mut order,
        )
        .unwrap();
        assert_eq!(order.capacity(), order_capacity);
        assert_eq!(
            scratch.inputs.iter().map(Vec::capacity).collect::<Vec<_>>(),
            input_capacities
        );
        assert_eq!(order.len(), 3);
    }

    #[test]
    fn topo_order_csr_via_rejects_cycle_like_partial_output() {
        let err = topo_order_csr_via(&ToposortDispatcher, 2, &[0, 1, 2], &[1, 0]).unwrap_err();
        assert!(matches!(err, DispatchError::BackendError(_)));
    }

    #[test]
    fn topo_order_csr_via_uses_primitive_order_contract() {
        struct InvertedOrderDispatcher;

        impl OptimizerDispatcher for InvertedOrderDispatcher {
            fn dispatch(
                &self,
                _program: &Program,
                _inputs: &[Vec<u8>],
                _grid_override: Option<[u32; 3]>,
            ) -> Result<Vec<Vec<u8>>, DispatchError> {
                Ok(vec![u32_slice_to_le_bytes(&[1, 0])])
            }
        }

        let err = topo_order_csr_via(&InvertedOrderDispatcher, 2, &[0, 1, 1], &[1]).unwrap_err();
        assert!(matches!(err, DispatchError::BackendError(_)));
    }

    #[test]
    fn topo_order_csr_via_rejects_bad_csr() {
        let err = topo_order_csr_via(&ToposortDispatcher, 2, &[0, 2, 1], &[1]).unwrap_err();
        assert!(matches!(err, DispatchError::BadInputs(_)));
    }

    #[test]
    fn production_source_keeps_cpu_toposort_helpers_out_of_via_path() {
        let source = include_str!("toposort.rs");
        let via_section = source
            .split("pub fn topo_order_csr_via")
            .nth(1)
            .expect("via section should exist")
            .split("#[cfg(test)]\npub fn reference_reachable_set")
            .next()
            .expect("test-only reference marker should exist");

        assert!(!via_section.contains("_cpu"));
        assert!(!via_section.contains("reference_"));
        assert!(!via_section.contains("fill_"));
    }

    #[test]
    fn test_dispatcher_uses_primitive_csr_oracle_not_local_kahn_clone() {
        let source = include_str!("toposort.rs");
        let dispatcher_section = source
            .split("struct ToposortDispatcher;")
            .nth(1)
            .expect("test dispatcher section should exist")
            .split("#[test]\n    fn topo_order_csr_via_dispatches_primitive_order")
            .next()
            .expect("dispatcher section should end before dispatch tests");

        assert!(dispatcher_section.contains("toposort_csr_into"));
        assert!(
            !dispatcher_section.contains("indeg")
                && !dispatcher_section.contains("queue")
                && !dispatcher_section.contains("while let Some"),
            "Fix: self-substrate topological-sort tests must not maintain a second Kahn implementation; use the primitive CSR oracle."
        );
    }

    fn read_u32s(bytes: &[u8]) -> Vec<u32> {
        bytes
            .chunks_exact(std::mem::size_of::<u32>())
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect()
    }
}
