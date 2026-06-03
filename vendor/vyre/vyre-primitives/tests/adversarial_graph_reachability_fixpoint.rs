//! Adversarial contract tests for graph reachability, fixpoint, and
//! traversal invariants.
//!
//! Coverage: reachable, toposort, scc_decompose, path_reconstruct,
//! tensor_scc, csr_forward_or_changed, dominator_frontier, and
//! fixpoint convergence semantics. GPU acquisition: none  -  every
//! assertion uses CPU reference oracles.
//!
//! Implementation lives in two `include!`-d chunks under `__split/`.
#![cfg(feature = "graph")]
#![cfg(feature = "fixpoint")]
#![cfg(feature = "math")]

use std::collections::HashSet;

use vyre_primitives::fixpoint::bitset_fixpoint::*;
use vyre_primitives::graph::csr_forward_or_changed::cpu_ref as csr_cpu_ref;
use vyre_primitives::graph::dominator_frontier::cpu_ref as dom_cpu_ref;
use vyre_primitives::graph::path_reconstruct::cpu_ref as path_cpu_ref;
use vyre_primitives::graph::reachable::{reachable, reachable_program};
use vyre_primitives::graph::scc_decompose::cpu_ref as scc_cpu_ref;
use vyre_primitives::graph::toposort::{toposort, ToposortError};
use vyre_primitives::math::tensor_scc::{cpu_ref as tensor_scc_cpu_ref, tensor_scc_fixpoint};

// ---------------------------------------------------------------------------
// Reachable  -  directed reachability
// ---------------------------------------------------------------------------

fn hs(items: &[u32]) -> HashSet<u32> {
    items.iter().copied().collect()
}

#[test]
fn reachable_empty_graph_empty_sources() {
    let got = reachable(0, &[], &[]).unwrap();
    assert!(got.is_empty());
}

#[test]
fn reachable_empty_graph_non_empty_sources() {
    // Sources outside node count are still reported as reachable from themselves
    let got = reachable(0, &[], &[0, 1, 2]).unwrap();
    assert_eq!(got, hs(&[0, 1, 2]));
}

#[test]
fn reachable_single_node_self_loop() {
    let got = reachable(1, &[(0, 0)], &[0]).unwrap();
    assert_eq!(got, hs(&[0]));
}

#[test]
fn reachable_chain_of_five() {
    let edges: Vec<(u32, u32)> = (0..4).map(|i| (i, i + 1)).collect();
    let got = reachable(5, &edges, &[0]).unwrap();
    assert_eq!(got, hs(&[0, 1, 2, 3, 4]));
}

#[test]
fn reachable_fork_join() {
    // 0 -> 1, 0 -> 2, 1 -> 3, 2 -> 3
    let got = reachable(4, &[(0, 1), (0, 2), (1, 3), (2, 3)], &[0]).unwrap();
    assert_eq!(got, hs(&[0, 1, 2, 3]));
}

#[test]
fn reachable_multiple_sources() {
    let got = reachable(4, &[(0, 1), (2, 3)], &[0, 2]).unwrap();
    assert_eq!(got, hs(&[0, 1, 2, 3]));
}

#[test]
fn reachable_cycle_of_three() {
    let got = reachable(3, &[(0, 1), (1, 2), (2, 0)], &[0]).unwrap();
    assert_eq!(got, hs(&[0, 1, 2]));
}

#[test]
fn reachable_cycle_of_three_source_in_middle() {
    let got = reachable(3, &[(0, 1), (1, 2), (2, 0)], &[1]).unwrap();
    assert_eq!(got, hs(&[0, 1, 2]));
}

#[test]
fn reachable_disconnected_component_excluded() {
    let got = reachable(6, &[(0, 1), (1, 2), (3, 4), (4, 5)], &[0]).unwrap();
    assert_eq!(got, hs(&[0, 1, 2]));
    assert!(!got.contains(&3));
    assert!(!got.contains(&4));
    assert!(!got.contains(&5));
}

#[test]
fn reachable_unknown_node_from_edge_is_rejected() {
    let err = reachable(3, &[(0, 1), (5, 1)], &[0]).unwrap_err();
    assert_eq!(err.index, 1);
    assert_eq!(err.node, 5);
    assert_eq!(err.node_count, 3);
}

#[test]
fn reachable_unknown_to_node_from_edge_is_rejected() {
    let err = reachable(3, &[(0, 1), (1, 5)], &[0]).unwrap_err();
    assert_eq!(err.index, 1);
    assert_eq!(err.node, 5);
}

#[test]
fn reachable_program_builder_non_empty() {
    let p = reachable_program(4, 4, "src", "reach", 3);
    assert!(!p.is_explicit_noop());
    assert!(!p.buffers().is_empty());
}

#[test]
fn reachable_program_zero_iters_seeds_only() {
    let p = reachable_program(4, 4, "src", "reach", 0);
    assert!(!p.is_explicit_noop());
}

#[test]
fn reachable_program_declares_scratch_buffers() {
    let p = reachable_program(4, 4, "src", "reach", 2);
    let names: Vec<&str> = p.buffers().iter().map(|b| b.name()).collect();
    assert!(names.contains(&"reach_frontier_a"));
    assert!(names.contains(&"reach_frontier_b"));
}

// ---------------------------------------------------------------------------
// Topological sort
// ---------------------------------------------------------------------------

#[test]
fn toposort_empty_graph() {
    assert_eq!(toposort(0, &[]), Ok(Vec::new()));
}

#[test]
fn toposort_single_node_no_edges() {
    assert_eq!(toposort(1, &[]), Ok(vec![0]));
}

#[test]
fn toposort_two_nodes_one_edge() {
    // 0 depends on 1
    let got = toposort(2, &[(0, 1)]).unwrap();
    assert_eq!(got, vec![1, 0]);
}

#[test]
fn toposort_linear_chain() {
    let edges: Vec<(u32, u32)> = (0..9).map(|i| (i, i + 1)).collect();
    let got = toposort(10, &edges).unwrap();
    let pos = |v: u32| got.iter().position(|&x| x == v).unwrap();
    for i in 0..9 {
        assert!(
            pos(i + 1) < pos(i),
            "chain toposort must place {i} after {}",
            i + 1
        );
    }
}

#[test]
fn toposort_cycle_of_two_rejected() {
    let err = toposort(2, &[(0, 1), (1, 0)]).unwrap_err();
    assert!(matches!(err, ToposortError::Cycle { .. }));
}

#[test]
fn toposort_cycle_of_three_rejected() {
    let err = toposort(3, &[(0, 1), (1, 2), (2, 0)]).unwrap_err();
    assert!(matches!(err, ToposortError::Cycle { .. }));
}

#[test]
fn toposort_self_loop_rejected() {
    let err = toposort(2, &[(0, 0)]).unwrap_err();
    assert!(matches!(err, ToposortError::Cycle { .. }));
}

#[test]
fn toposort_unknown_node_rejected() {
    let err = toposort(2, &[(0, 5)]).unwrap_err();
    assert!(matches!(
        err,
        ToposortError::UnknownNode { edge: 0, node: 5 }
    ));
}

#[test]
fn toposort_diamond_respects_partial_order() {
    let got = toposort(4, &[(0, 1), (0, 2), (1, 3), (2, 3)]).unwrap();
    let pos = |v: u32| got.iter().position(|&x| x == v).unwrap();
    assert!(pos(3) < pos(1));
    assert!(pos(3) < pos(2));
    assert!(pos(1) < pos(0));
    assert!(pos(2) < pos(0));
}

#[test]
fn toposort_parallel_edges_ok() {
    let got = toposort(2, &[(0, 1), (0, 1)]).unwrap();
    assert_eq!(got, vec![1, 0]);
}

#[test]
fn toposort_u32_max_indegree_saturates() {
    // Create a node with many incoming edges to test saturating_add.
    let mut edges = Vec::new();
    for i in 1..10 {
        edges.push((0, i));
    }
    let got = toposort(10, &edges).unwrap();
    assert_eq!(got.len(), 10);
}

// ---------------------------------------------------------------------------
// SCC decomposition
// ---------------------------------------------------------------------------

#[test]
fn scc_intersection_stamps_pivot() {
    let out = scc_cpu_ref(4, &[0b0011], &[0b0011], &[u32::MAX; 4], 0);
    assert_eq!(&out[0..2], &[0, 0]);
    assert_eq!(&out[2..4], &[u32::MAX, u32::MAX]);
}

#[test]
fn scc_disjoint_forward_backward_yields_no_change() {
    let comp_in = vec![u32::MAX; 4];
    let out = scc_cpu_ref(4, &[0b0001], &[0b1000], &comp_in, 0);
    assert_eq!(out, comp_in);
}

#[test]
fn scc_first_pivot_wins() {
    let comp_in = vec![u32::MAX; 4];
    let forward = vec![0b1111];
    let backward = vec![0b1111];
    let after_first = scc_cpu_ref(4, &forward, &backward, &comp_in, 5);
    assert_eq!(after_first, vec![5, 5, 5, 5]);
    let after_second = scc_cpu_ref(4, &forward, &backward, &after_first, 9);
    assert_eq!(
        after_second,
        vec![5, 5, 5, 5],
        "second pivot must not overwrite"
    );
}

#[test]
fn scc_unassigned_node_gets_second_pivot() {
    let comp_in = vec![u32::MAX; 4];
    let after_first = scc_cpu_ref(4, &[0b0001], &[0b0001], &comp_in, 5);
    assert_eq!(after_first[0], 5);
    assert_eq!(after_first[2], u32::MAX);
    let after_second = scc_cpu_ref(4, &[0b0100], &[0b0100], &after_first, 9);
    assert_eq!(after_second[0], 5);
    assert_eq!(after_second[2], 9);
}

#[test]
fn scc_empty_intersection_all_unassigned() {
    let comp_in = vec![u32::MAX; 4];
    let out = scc_cpu_ref(4, &[0b0001], &[0b0010], &comp_in, 0);
    assert_eq!(out, comp_in);
}

// ---------------------------------------------------------------------------
// Path reconstruction
// ---------------------------------------------------------------------------

#[test]
fn path_reconstruct_walks_to_root() {
    let mut scratch = Vec::with_capacity(8);
    let len = path_cpu_ref(&[0, 0, 1, 2], 3, 4, &mut scratch);
    assert_eq!(len, 4);
    assert_eq!(&scratch[..4], &[3, 2, 1, 0]);
}

#[test]
fn path_reconstruct_max_depth_caps() {
    let mut scratch = Vec::with_capacity(8);
    let len = path_cpu_ref(&[1, 0], 0, 8, &mut scratch);
    assert_eq!(len, 8);
    assert_eq!(&scratch[..], &[0, 1, 0, 1, 0, 1, 0, 1]);
}

#[test]
fn path_reconstruct_tail_zero_padded() {
    let mut scratch = Vec::with_capacity(8);
    let len = path_cpu_ref(&[0, 0, 1, 2], 3, 8, &mut scratch);
    assert_eq!(len, 4);
    assert_eq!(&scratch[..4], &[3, 2, 1, 0]);
    assert_eq!(&scratch[4..], &[0, 0, 0, 0]);
}

#[test]
fn path_reconstruct_single_node() {
    let mut scratch = Vec::with_capacity(4);
    let len = path_cpu_ref(&[0], 0, 4, &mut scratch);
    assert_eq!(len, 1);
    assert_eq!(scratch[0], 0);
    assert_eq!(&scratch[1..], &[0, 0, 0]);
}

#[test]
fn path_reconstruct_oob_parent_terminates_early() {
    let mut scratch = Vec::with_capacity(4);
    // parent[3] is OOB, so when current=3, next = unwrap_or(current) = 3,
    // which equals current → break.
    let len = path_cpu_ref(&[0, 0, 1], 3, 4, &mut scratch);
    assert_eq!(len, 1);
    assert_eq!(scratch[0], 3);
}

#[test]
fn path_reconstruct_zero_max_depth_emits_trap_program() {
    // Primitive builders are infallible: invalid shapes become IR traps,
    // not host panics. Verify max_depth == 0 produces a trap node.
    let p = vyre_primitives::graph::path_reconstruct::path_reconstruct(
        "parent", "target", "out", "len", 0,
    );
    let entry = p.entry();
    let has_trap = entry.iter().any(|n| {
        use vyre_foundation::ir::Node;
        if let Node::Region { body, .. } = n {
            body.iter().any(|inner| matches!(inner, Node::Trap { .. }))
        } else {
            matches!(n, Node::Trap { .. })
        }
    });
    assert!(
        has_trap,
        "max_depth == 0 must produce a trap program, not panic"
    );
}

// ---------------------------------------------------------------------------
// Tensor SCC (bounded bit-matrix fixpoint)
// ---------------------------------------------------------------------------

#[test]
fn tensor_scc_closes_cycle_inside_group() {
    let rows = [0b0010u32, 0b0100, 0b0001, 0b1000];
    assert_eq!(tensor_scc_cpu_ref(&rows, 0b0001, 0b0111, 8), 0b0111);
}

#[test]
fn tensor_scc_masks_edges_outside_group() {
    let rows = [0b1010u32, 0b0100, 0b0000, 0b0001];
    assert_eq!(tensor_scc_cpu_ref(&rows, 0b0001, 0b0011, 8), 0b0011);
}

#[test]
fn tensor_scc_no_edges_isolated() {
    let rows = [0u32; 4];
    assert_eq!(tensor_scc_cpu_ref(&rows, 0b0001, 0b1111, 8), 0b0001);
}

#[test]
fn tensor_scc_converges_before_limit() {
    let rows = [0b0010u32, 0b0100, 0b0001];
    // Cycle 0->1->2->0; starting from 0b0001 with group=0b0111
    // Iter 0: active=0b0001, next adds row0=0b0010 -> 0b0011
    // Iter 1: active=0b0011, next adds row0+row1 -> 0b0011 | 0b0110 = 0b0111
    // Iter 2: active=0b0111, next adds row0+row1+row2 -> already stable
    // Should converge in 2 iters, but we give 100.
    assert_eq!(tensor_scc_cpu_ref(&rows, 0b0001, 0b0111, 100), 0b0111);
}

#[test]
fn tensor_scc_group_mask_zero_annihilates() {
    let rows = [0b1111u32; 4];
    assert_eq!(tensor_scc_cpu_ref(&rows, 0b1111, 0b0000, 8), 0b0000);
}

#[test]
fn tensor_scc_seed_outside_group_is_masked() {
    let rows = [0b1111u32; 4];
    assert_eq!(tensor_scc_cpu_ref(&rows, 0b1000, 0b0111, 8), 0b0000);
}

#[test]
fn tensor_scc_program_buffer_counts() {
    let p = tensor_scc_fixpoint("rows", "seed", "group", "out", 4, 8);
    assert_eq!(p.workgroup_size(), [1, 1, 1]);
    assert_eq!(p.buffers()[0].count(), 4);
    assert_eq!(p.buffers()[3].count(), 1);
}

// ---------------------------------------------------------------------------
// CSR forward-or-changed (in-place expansion with sticky flag)
// ---------------------------------------------------------------------------

#[test]
fn csr_forward_or_changed_expands_frontier() {
    let (frontier, changed) = csr_cpu_ref(
        4,
        &[0, 2, 3, 4, 4],
        &[1, 2, 3, 3],
        &[1, 1, 1, 1],
        &[0b0001],
        1,
    );
    assert_eq!(frontier, vec![0b1111]);
    assert_eq!(changed, 1);
}

#[test]
fn csr_forward_or_changed_no_change_when_frontier_unchanged() {
    let (frontier, changed) = csr_cpu_ref(
        4,
        &[0, 2, 3, 4, 4],
        &[1, 2, 3, 3],
        &[1, 1, 1, 1],
        &[0b1111],
        1,
    );
    assert_eq!(frontier, vec![0b1111]);
    assert_eq!(changed, 0, "saturated frontier must signal no change");
}

#[test]
fn csr_forward_or_changed_empty_frontier() {
    let (frontier, changed) =
        csr_cpu_ref(4, &[0, 2, 3, 4, 4], &[1, 2, 3, 3], &[1, 1, 1, 1], &[0], 1);
    assert_eq!(frontier, vec![0]);
    assert_eq!(changed, 0);
}

#[test]
fn csr_forward_or_changed_edge_mask_blocks() {
    let (frontier, changed) = csr_cpu_ref(
        4,
        &[0, 2, 3, 4, 4],
        &[1, 2, 3, 3],
        &[0b10, 0b01, 0b01, 0b01],
        &[0b0001],
        0b01,
    );
    // In-place expansion: node 0 adds node 2 (allowed edge), then node 2
    // (now set in the same buffer) adds node 3, producing {0,2,3}.
    assert_eq!(
        frontier,
        vec![0b1101],
        "in-place expansion cascades within one pass"
    );
    assert_eq!(changed, 1);
}

#[test]
fn csr_forward_or_changed_zero_nodes() {
    let (frontier, changed) = csr_cpu_ref(0, &[0], &[], &[], &[], 1);
    assert!(frontier.is_empty());
    assert_eq!(changed, 0);
}

// ---------------------------------------------------------------------------
// Dominator frontier
// ---------------------------------------------------------------------------

#[test]
fn dominator_frontier_empty_seed_empty_frontier() {
    let out = dom_cpu_ref(4, &[0, 0, 0, 0, 0], &[], &[0, 0, 0, 0, 0], &[], &[0]);
    assert_eq!(out, vec![0]);
}

#[test]
fn dominator_frontier_single_node_no_predecessors() {
    let out = dom_cpu_ref(2, &[0, 0, 0], &[], &[0, 0, 0], &[], &[0b01]);
    assert_eq!(out, vec![0]);
}

#[test]
fn dominator_frontier_join_node_appears() {
    // CFG: 0 -> 1, 0 -> 2, 1 -> 3, 2 -> 3
    let pred_offsets = vec![0u32, 0, 1, 2, 4];
    let pred_targets = vec![0u32, 0, 1, 2];
    // Dominator sets: 0 dominates everyone; 1 dominates {1}; 2 dominates {2}; 3 dominates {3}
    let dom_offsets = vec![0u32, 4, 5, 6, 7];
    let dom_targets = vec![0u32, 1, 2, 3, 1, 2, 3];
    let out = dom_cpu_ref(
        4,
        &dom_offsets,
        &dom_targets,
        &pred_offsets,
        &pred_targets,
        &[0b0010],
    );
    assert_eq!(out, vec![0b1000], "df(1) must include join node 3");
}

#[test]
#[should_panic(expected = "complete seed bitset")]
fn dominator_frontier_missing_seed_fails_loudly() {
    let _ = dom_cpu_ref(2, &[0, 0, 0], &[], &[0, 0, 0], &[], &[]);
}

// ---------------------------------------------------------------------------
// Fixpoint convergence invariants
// ---------------------------------------------------------------------------

#[test]
fn fixpoint_reference_eval_equal_is_zero() {
    assert_eq!(reference_eval(&[0b1010], &[0b1010]), 0);
    assert_eq!(reference_eval(&[0xFFFF_FFFF; 16], &[0xFFFF_FFFF; 16]), 0);
    assert_eq!(reference_eval(&[], &[]), 0);
}

#[test]
fn fixpoint_reference_eval_different_is_one() {
    assert_eq!(reference_eval(&[0b1010], &[0b1011]), 1);
    assert_eq!(reference_eval(&[0; 16], &[1; 16]), 1);
}

#[test]
fn fixpoint_reference_eval_mismatched_lengths_is_one() {
    assert_eq!(reference_eval(&[0, 0], &[0]), 1);
}

#[test]
fn fixpoint_warm_start_zero_seed_equals_cold() {
    let (updated, flag) = reference_eval_warm_start(&[0b0001], &[0b0001], &[0]);
    assert_eq!(updated, vec![0b0001]);
    assert_eq!(flag, 0);
}

#[test]
fn fixpoint_warm_start_seed_overwrites_current() {
    let (updated, flag) = reference_eval_warm_start(&[0b0001], &[0b0011], &[0b1111]);
    assert_eq!(updated, vec![0b1111]);
    assert_eq!(flag, 1, "c0 (0b0001) != next (0b0011) → flag must be 1");
}

#[test]
fn fixpoint_warm_start_empty_bitsets() {
    let (updated, flag) = reference_eval_warm_start(&[], &[], &[]);
    assert!(updated.is_empty());
    assert_eq!(flag, 0);
}

#[test]
fn fixpoint_warm_start_large_bitsets() {
    let current = vec![0xAAAAAAAAu32; 1024];
    let next = vec![0xBBBBBBBBu32; 1024];
    let seed = vec![0x11111111u32; 1024];
    let (updated, flag) = reference_eval_warm_start(&current, &next, &seed);
    assert_eq!(updated.len(), 1024);
    assert_eq!(updated[0], 0xBBBBBBBB);
    assert_eq!(flag, 1);
}

#[test]
fn fixpoint_monotonic_growth_invariant() {
    // Simulate two fixpoint steps: current0 -> next0 -> current1
    let current0 = vec![0b0001u32];
    let next0 = vec![0b0011u32];
    let next1 = vec![0b0011u32]; // no further growth

    let flag0 = reference_eval(&current0, &next0);
    assert_eq!(flag0, 1, "first step must signal change");

    let flag1 = reference_eval(&next0, &next1);
    assert_eq!(flag1, 0, "second step must signal convergence");
}

#[test]
fn fixpoint_idempotence_after_convergence() {
    let converged = vec![0b1111u32];
    let flag = reference_eval(&converged, &converged);
    assert_eq!(flag, 0, "identical inputs must always yield 0");
}

#[test]
fn fixpoint_warm_start_anticipates_transfer() {
    // current = 0b0001, transfer says next = 0b0011, seed = 0b0010 anticipates delta.
    // c0 != next → flag must still be 1 because transfer added new bits.
    let (updated, flag) = reference_eval_warm_start(&[0b0001], &[0b0011], &[0b0010]);
    assert_eq!(updated, vec![0b0011]);
    assert_eq!(flag, 1);
}
