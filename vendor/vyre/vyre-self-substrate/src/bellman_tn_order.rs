//! Tensor-network contraction order via shortest-path on the contraction-cost graph.
//!
//! Extends `tensor_network_fusion_order` (#35). Instead of a greedy heuristic,
//! we frame the search for the optimal contraction order of a Region chain as
//! finding the shortest path in a state graph where:
//! - Node = subset of contracted tensors (represented as an integer bitset or ID).
//! - Edge = contracting two adjacent sub-networks.
//! - Weight = FLOP cost of that specific contraction step.
//!
//! We dispatch `vyre_primitives::math::bellman_shortest_path` to find the
//! globally optimal sequence of pairwise fusions.

use vyre_foundation::ir::Program;
use vyre_primitives::math::bellman_shortest_path::bellman_shortest_path;

/// Canonical self-substrate op ID for the Bellman TN order.
pub const OP_ID: &str = "vyre-libs::self_substrate::bellman_tn_order";

/// Compile a Program that finds the optimal tensor-network contraction
/// order by running Bellman-Ford over the state space of contractions.
///
/// `n_nodes` is the number of possible contraction states (e.g. `2^N` for N tensors).
/// `n_edges` is the number of valid contraction transitions.
/// The output `dist` buffer will contain the minimum cost to reach each state.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn bellman_tn_order_program(
    src: &str,
    dst: &str,
    weight: &str,
    dist: &str,
    next_dist: &str,
    changed: &str,
    n_nodes: u32,
    n_edges: u32,
    max_iterations: u32,
) -> Program {
    use crate::observability::{bellman_tn_order_calls, bump};
    bump(&bellman_tn_order_calls);
    // Composes the tier-2.5 primitive directly.
    bellman_shortest_path(
        src,
        dst,
        weight,
        dist,
        next_dist,
        changed,
        n_nodes,
        n_edges,
        max_iterations,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_primitives::math::bellman_shortest_path::cpu_ref;

    #[test]
    fn test_tn_order_program_structure() {
        let p = bellman_tn_order_program("s", "d", "w", "dist", "nd", "c", 8, 12, 5);
        assert_eq!(
            p.buffers().len(),
            6,
            "Must expose 6 buffers for Bellman-Ford"
        );
        assert!(p.buffers().iter().any(|b| b.name() == "dist"));
    }

    #[test]
    fn test_tn_contraction_cost_graph_parity() {
        // Non-trivial vyre IR shape: A chain of 3 tensors (A, B, C)
        // dimensions: A(10x20), B(20x30), C(30x40).
        // States:
        // 0: [A, B, C]
        // 1: [(AB), C]  cost = 10*20*30 = 6000
        // 2: [A, (BC)]  cost = 20*30*40 = 24000
        // 3: [(ABC)] from 1: cost = 10*30*40 = 12000
        // 4: [(ABC)] from 2: cost = 10*20*40 = 8000

        // Edge list (src, dst, weight)
        let src = vec![0, 0, 1, 2];
        let dst = vec![1, 2, 3, 3];
        let weight = vec![6000, 24000, 12000, 8000];

        // 4 nodes, start at 0
        let mut dist = vec![u32::MAX; 4];
        dist[0] = 0; // source is state 0

        let (final_dist, _) = cpu_ref(&src, &dst, &weight, &dist, 4, 10);

        // Optimal path to 3:
        // 0 -> 1 -> 3: 6000 + 12000 = 18000
        // 0 -> 2 -> 3: 24000 + 8000 = 32000
        // So final_dist[3] should be 18000.
        assert_eq!(final_dist[1], 6000);
        assert_eq!(final_dist[2], 24000);
        assert_eq!(final_dist[3], 18000);
    }

    #[test]
    fn test_tn_chain_4_tensors_optimal() {
        // 4 tensors, dimensions: 10, 20, 30, 40, 50
        // We'll mock a small DP graph for Matrix Chain Multiplication.
        // Let nodes be represented by intervals [i, j].
        // Node 0: start, Node 1: ends. Just some mock topology.
        let src = vec![0, 0, 0, 1, 2, 3];
        let dst = vec![1, 2, 3, 4, 4, 4];
        let weight = vec![100, 200, 300, 50, 40, 10]; // mock costs

        let mut dist = vec![u32::MAX; 5];
        dist[0] = 0;

        let (final_dist, _) = cpu_ref(&src, &dst, &weight, &dist, 5, 10);

        // 0->1->4 (150)
        // 0->2->4 (240)
        // 0->3->4 (310)
        assert_eq!(final_dist[4], 150);
    }

    #[test]
    fn test_multi_stage_order_refining() {
        // Build a Program with 3 separate Bellman regions.
        let p1 = bellman_tn_order_program("s", "d", "w", "dist1", "nd1", "c1", 4, 4, 5);
        let p2 = bellman_tn_order_program("s", "d", "w", "dist2", "nd2", "c2", 4, 4, 5);
        let p3 = bellman_tn_order_program("s", "d", "w", "dist3", "nd3", "c3", 4, 4, 5);

        let mut entry = p1.entry().to_vec();
        entry.extend(p2.entry().to_vec());
        entry.extend(p3.entry().to_vec());

        let mut buffers = p1.buffers().to_vec();
        buffers.extend(p2.buffers().to_vec());
        buffers.extend(p3.buffers().to_vec());

        let final_p = Program::wrapped(buffers, [256, 1, 1], entry);
        // Assert we have at least 3 regions
        let region_count = final_p
            .entry()
            .iter()
            .filter(|n| matches!(n, vyre_foundation::ir::Node::Region { .. }))
            .count();
        assert!(region_count >= 3);
    }

    #[test]
    fn test_end_to_end_tn_parity() {
        // Same shape as `vyre_primitives::math::bellman_shortest_path::tests::test_parity_small_graph`.
        let src = vec![0, 1, 2, 0];
        let dst = vec![1, 2, 3, 3];
        let weight = vec![10, 20, 30, 100];
        let dist_init = vec![0, u32::MAX, u32::MAX, u32::MAX];

        let p = bellman_tn_order_program("s", "d", "w", "dist", "nd", "c", 4, 4, 10);

        let (expected_dist, _) = cpu_ref(&src, &dst, &weight, &dist_init, 4, 10);

        use std::sync::Arc;
        use vyre_reference::reference_eval;
        use vyre_reference::value::Value;

        let to_value = |data: &[u32]| {
            let bytes: Vec<u8> = data.iter().flat_map(|v| v.to_le_bytes()).collect();
            Value::Bytes(Arc::from(bytes))
        };

        let inputs = vec![
            to_value(&dist_init),
            to_value(&dist_init),
            to_value(&[0]),
            to_value(&src),
            to_value(&dst),
            to_value(&weight),
        ];

        let results = reference_eval(&p, &inputs).expect("Fix: interpreter failed");
        let actual_bytes = results[0].to_bytes();
        let actual_dist: Vec<u32> = actual_bytes
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect();
        assert_eq!(actual_dist, expected_dist);
    }
}
