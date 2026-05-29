//! Failure-oriented adversarial integration tests for graph primitives.
//!
//! Coverage: csr_forward_traverse, csr_backward_traverse, toposort,
//! scc_decompose, path_reconstruct  -  hostile boundaries, empty graphs,
//! edge-kind diversity (M8), malformed CSR, cross-word bitsets.
#![cfg(all(feature = "graph", feature = "cpu-parity"))]

use vyre_primitives::graph::csr_backward_traverse::cpu_ref as bwd_cpu_ref;
use vyre_primitives::graph::csr_forward_traverse::cpu_ref as fwd_cpu_ref;
use vyre_primitives::graph::path_reconstruct::cpu_ref as path_cpu_ref;
use vyre_primitives::graph::scc_decompose::cpu_ref as scc_cpu_ref;
use vyre_primitives::graph::toposort::{toposort, ToposortError};

// ---------------------------------------------------------------------------
// csr_forward_traverse
// ---------------------------------------------------------------------------

#[test]
fn forward_empty_graph() {
    let got = fwd_cpu_ref(0, &[0], &[], &[], &[], 0xFFFF_FFFF);
    assert!(got.is_empty());
}

#[test]
fn forward_single_node_no_edges() {
    let got = fwd_cpu_ref(1, &[0, 0], &[0], &[0], &[0b0001], 0xFFFF_FFFF);
    assert_eq!(got, vec![0]);
}

#[test]
fn forward_self_loops_only() {
    let got = fwd_cpu_ref(2, &[0, 1, 2], &[0, 1], &[1, 1], &[0b0011], 0xFFFF_FFFF);
    assert_eq!(got, vec![0b0011]);
}

#[test]
fn forward_disconnected_components() {
    let got = fwd_cpu_ref(
        4,
        &[0, 1, 1, 2, 2],
        &[1, 3],
        &[1, 1],
        &[0b0001],
        0xFFFF_FFFF,
    );
    assert_eq!(got, vec![0b0010]);
}

#[test]
fn forward_max_node_count_cross_word() {
    let mut offsets = vec![0u32; 66];
    offsets[64] = 0;
    offsets[65] = 1;
    let mut frontier = vec![0u32; 3];
    frontier[2] = 1;
    let got = fwd_cpu_ref(65, &offsets, &[0], &[1], &frontier, 0xFFFF_FFFF);
    assert_eq!(got.len(), 3);
    assert_eq!(got[0], 1);
    assert_eq!(got[1], 0);
    assert_eq!(got[2], 0);
}

#[test]
fn forward_edge_mask_filters_all() {
    let got = fwd_cpu_ref(
        4,
        &[0, 2, 3, 4, 4],
        &[1, 2, 3, 3],
        &[0b01, 0b01, 0b01, 0b01],
        &[0b0001],
        0b10,
    );
    assert_eq!(got, vec![0]);
}

#[test]
fn forward_edge_kind_diversity_m8() {
    // DOMINANCE=0x01, ASSIGNMENT=0x02. Mask only DOMINANCE.
    let got = fwd_cpu_ref(4, &[0, 2, 2, 2, 2], &[1, 2], &[0x01, 0x02], &[0b0001], 0x01);
    assert_eq!(
        got,
        vec![0b0010],
        "broken impl ignoring kind_mask would produce 0b0110"
    );
}

// ---------------------------------------------------------------------------
// csr_backward_traverse
// ---------------------------------------------------------------------------

#[test]
fn backward_empty_graph() {
    let got = bwd_cpu_ref(0, &[0], &[], &[], &[], 0xFFFF_FFFF);
    assert!(got.is_empty());
}

#[test]
fn backward_single_node_no_edges() {
    let got = bwd_cpu_ref(1, &[0, 0], &[0], &[0], &[0b0001], 0xFFFF_FFFF);
    assert_eq!(got, vec![0]);
}

#[test]
fn backward_self_loops_only() {
    let got = bwd_cpu_ref(2, &[0, 1, 2], &[0, 1], &[1, 1], &[0b0001], 0xFFFF_FFFF);
    assert_eq!(got, vec![0b0001]);
}

#[test]
fn backward_disconnected_components() {
    let got = bwd_cpu_ref(
        4,
        &[0, 1, 1, 2, 2],
        &[1, 3],
        &[1, 1],
        &[0b1000],
        0xFFFF_FFFF,
    );
    assert_eq!(got, vec![0b0100]);
}

#[test]
fn backward_edge_kind_diversity_m8() {
    let got = bwd_cpu_ref(4, &[0, 2, 2, 2, 2], &[1, 2], &[0x01, 0x02], &[0b0010], 0x01);
    assert_eq!(
        got,
        vec![0b0001],
        "broken impl ignoring kind_mask would produce 0"
    );
}

// ---------------------------------------------------------------------------
// toposort
// ---------------------------------------------------------------------------

#[test]
fn toposort_single_node() {
    assert_eq!(toposort(1, &[]), Ok(vec![0]));
}

#[test]
fn toposort_self_loops_rejected() {
    let err = toposort(3, &[(0, 0), (1, 1), (2, 2)]).expect_err("self-loops are cycles");
    assert!(matches!(err, ToposortError::Cycle { .. }));
}

#[test]
fn toposort_disconnected_components() {
    let got = toposort(4, &[(0, 1), (2, 3)]).unwrap();
    assert_eq!(got.len(), 4);
    let pos = |v: u32| got.iter().position(|&x| x == v).unwrap();
    assert!(pos(1) < pos(0));
    assert!(pos(3) < pos(2));
}

#[test]
fn toposort_large_graph_cycle_diagnostic() {
    let mut edges: Vec<(u32, u32)> = (0..99).map(|i| (i, i + 1)).collect();
    edges.push((99, 50));
    let err = toposort(100, &edges).expect_err("cycle must be detected");
    match err {
        ToposortError::Cycle { node } => {
            assert!((50..=99).contains(&node));
        }
        other => panic!("expected Cycle, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// scc_decompose
// ---------------------------------------------------------------------------

#[test]
fn scc_empty_graph() {
    let out = scc_cpu_ref(0, &[], &[], &[], 0);
    assert!(out.is_empty());
}

#[test]
fn scc_self_loop() {
    let out = scc_cpu_ref(1, &[0b0001], &[0b0001], &[u32::MAX; 1], 0);
    assert_eq!(out, vec![0]);
}

#[test]
fn scc_disconnected_components() {
    let forward = vec![0b0101];
    let backward = vec![0b0101];
    let comp_in = vec![u32::MAX; 4];
    let out = scc_cpu_ref(4, &forward, &backward, &comp_in, 0);
    assert_eq!(out[0], 0);
    assert_eq!(out[1], u32::MAX);
    assert_eq!(out[2], 0);
    assert_eq!(out[3], u32::MAX);
}

#[test]
fn scc_multi_word_cross_boundary() {
    let mut forward = vec![0u32; 3];
    let mut backward = vec![0u32; 3];
    forward[1] = 1; // node 32
    forward[2] = 1; // node 64
    backward[1] = 1;
    backward[2] = 1;
    let comp_in = vec![u32::MAX; 65];
    let out = scc_cpu_ref(65, &forward, &backward, &comp_in, 42);
    assert_eq!(out[32], 42);
    assert_eq!(out[64], 42);
    assert_eq!(out[0], u32::MAX);
    assert_eq!(out[31], u32::MAX);
    assert_eq!(out[33], u32::MAX);
    assert_eq!(out[63], u32::MAX);
}

// ---------------------------------------------------------------------------
// path_reconstruct
// ---------------------------------------------------------------------------

#[test]
fn path_parent_self_loops() {
    let mut scratch = Vec::with_capacity(4);
    let len = path_cpu_ref(&[0, 1], 1, 4, &mut scratch);
    assert_eq!(len, 1);
    assert_eq!(scratch[0], 1);
    assert_eq!(&scratch[1..], &[0, 0, 0]);
}

#[test]
fn path_deep_chain() {
    let parent = &[0, 0, 1, 2, 3];
    let mut scratch = Vec::with_capacity(8);
    let len = path_cpu_ref(parent, 4, 8, &mut scratch);
    assert_eq!(len, 5);
    assert_eq!(&scratch[..5], &[4, 3, 2, 1, 0]);
}

#[test]
fn path_target_not_in_parent() {
    let mut scratch = Vec::with_capacity(4);
    let len = path_cpu_ref(&[0, 0, 1], 5, 4, &mut scratch);
    assert_eq!(len, 1);
    assert_eq!(scratch[0], 5);
}

#[test]
fn path_max_depth_zero() {
    let mut scratch = Vec::with_capacity(4);
    let len = path_cpu_ref(&[0, 0, 1, 2], 3, 0, &mut scratch);
    assert_eq!(len, 0);
    assert!(scratch.is_empty());
}

#[test]
fn path_max_depth_one() {
    let mut scratch = Vec::with_capacity(4);
    let len = path_cpu_ref(&[0, 0, 1, 2], 3, 1, &mut scratch);
    assert_eq!(len, 1);
    assert_eq!(scratch[0], 3);
}
