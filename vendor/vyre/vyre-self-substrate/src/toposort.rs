//! DAG topological-sort substrate consumer.
//!
//! Wires `vyre_primitives::graph::toposort::toposort` (zero prior
//! consumers) and `reachable::reachable` so the optimizer's pass
//! scheduler / megakernel scheduler / dispatch ordering can rely on
//! the same primitive surgec ships to user dialects. Replaces ad-hoc
//! Kahn's-algorithm reimplementations the optimizer carried inline.

use std::collections::HashSet;

use vyre_primitives::graph::reachable::{reachable as reachable_cpu, UnknownNode};
use vyre_primitives::graph::toposort::{toposort as toposort_cpu, ToposortError};

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
pub fn topo_order(node_count: u32, edges: &[(u32, u32)]) -> Result<Vec<u32>, ToposortError> {
    use crate::observability::{bump, dataflow_fixpoint_calls};
    bump(&dataflow_fixpoint_calls);
    toposort_cpu(node_count, edges)
}

/// Compute the set of nodes reachable from `sources` over `edges`.
/// Bumps the dataflow-fixpoint substrate counter.
///
/// # Errors
///
/// Returns `UnknownNode` when an edge names a node id outside
/// `0..node_count`.
pub fn reachable_set(
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
pub fn all_reachable(
    node_count: u32,
    edges: &[(u32, u32)],
    sources: &[u32],
    targets: &[u32],
) -> Result<bool, UnknownNode> {
    let reach = reachable_set(node_count, edges, sources)?;
    Ok(targets.iter().all(|t| reach.contains(t)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topo_order_chain_emits_dependency_first() {
        // 0 depends on 1 depends on 2. Order should be [2, 1, 0]
        // (Kahn's algorithm on the reverse-dependency graph as
        // encoded — 'to comes first').
        let order = topo_order(3, &[(0, 1), (1, 2)]).unwrap();
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
        let err = topo_order(2, &[(0, 1), (1, 0)]);
        assert!(matches!(err, Err(ToposortError::Cycle { .. })));
    }

    #[test]
    fn topo_order_rejects_unknown_node() {
        let err = topo_order(2, &[(0, 5)]);
        assert!(matches!(err, Err(ToposortError::UnknownNode { .. })));
    }

    /// Closure-bar: substrate output equals primitive output.
    #[test]
    fn matches_primitive_directly() {
        let edges = [(0u32, 1u32), (1, 2), (0, 2)];
        let via_substrate = topo_order(3, &edges).unwrap();
        let via_primitive = toposort_cpu(3, &edges).unwrap();
        assert_eq!(via_substrate, via_primitive);
    }

    #[test]
    fn reachable_walks_directed_chain() {
        // 0 -> 1 -> 2 -> 3. From {0}, every node is reachable.
        let edges = [(0u32, 1u32), (1, 2), (2, 3)];
        let reach = reachable_set(4, &edges, &[0]).unwrap();
        for n in 0..4 {
            assert!(reach.contains(&n), "node {n} must be reachable from 0");
        }
    }

    #[test]
    fn reachable_does_not_walk_reverse_edges() {
        // 0 -> 1. From {1}, only 1 is reachable.
        let reach = reachable_set(2, &[(0, 1)], &[1]).unwrap();
        assert_eq!(reach.len(), 1);
        assert!(reach.contains(&1));
    }

    /// Adversarial: empty sources yield empty reachable.
    #[test]
    fn reachable_empty_sources_yields_empty_set() {
        let reach = reachable_set(4, &[(0, 1), (1, 2)], &[]).unwrap();
        assert!(reach.is_empty());
    }

    /// Adversarial: a self-loop in sources must terminate (visited
    /// guard). Naive code that doesn't dedupe would loop forever.
    #[test]
    fn reachable_self_loop_terminates() {
        // 0 -> 0 (self-loop), 1 isolated.
        let reach = reachable_set(2, &[(0, 0)], &[0]).unwrap();
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
}
