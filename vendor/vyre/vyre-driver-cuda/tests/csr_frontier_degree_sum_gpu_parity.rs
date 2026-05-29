//! Parity test: GPU csr_frontier_degree_sum matches CPU oracle.

#![cfg(test)]

mod common;

use common::{bytes_u32, u32_bytes, with_live_backend};
use vyre::ir::Program;
use vyre::DispatchConfig;
use vyre_primitives::graph::csr_frontier_degree_sum::{
    csr_frontier_degree_sum, csr_frontier_degree_sum_cpu,
};
use vyre_primitives::graph::program_graph::ProgramGraphShape;

fn run(
    program: &Program,
    pg_nodes: &[u32],
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    pg_node_tags: &[u32],
    frontier: &[u32],
    grid_x: u32,
) -> u32 {
    let inputs: Vec<Vec<u8>> = vec![
        u32_bytes(pg_nodes),
        u32_bytes(edge_offsets),
        u32_bytes(edge_targets),
        u32_bytes(edge_kind_mask),
        u32_bytes(pg_node_tags),
        u32_bytes(frontier),
        // degree_sum_out: 1 word, zero-init.
        vec![0u8; 4],
    ];
    let mut config = DispatchConfig::default();
    config.grid_override = Some([grid_x, 1, 1]);
    let outputs = with_live_backend("CSR frontier degree sum", |backend| {
        backend
            .dispatch(program, &inputs, &config)
            .unwrap_or_else(|error| {
                panic!("Fix: CUDA CSR frontier degree-sum dispatch failed: {error}")
            })
    });
    bytes_u32(&outputs[0])[0]
}

#[test]
fn cuda_csr_frontier_degree_sum_chain() {
    // 0 -> 1 -> 2 -> 3, frontier = {0, 1, 2}.
    let n = 4u32;
    let edge_offsets = vec![0u32, 1, 2, 3, 3];
    let edge_targets = vec![1u32, 2, 3];
    let edge_kind_mask = vec![1u32; 3];
    let pg_nodes = vec![0u32; n as usize];
    let pg_node_tags = vec![0u32; n as usize];
    let frontier = vec![0b0111u32]; // nodes 0, 1, 2
    let cpu = csr_frontier_degree_sum_cpu(&frontier, &edge_offsets, n);
    let program = csr_frontier_degree_sum(ProgramGraphShape::new(n, 3));
    let gpu = run(
        &program,
        &pg_nodes,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
        &pg_node_tags,
        &frontier,
        1,
    );
    assert_eq!(gpu, cpu);
    assert_eq!(gpu, 3); // 1+1+1 outgoing edges from 0,1,2
}

#[test]
fn cuda_csr_frontier_degree_sum_diamond() {
    // 0 -> {1, 2} -> 3, frontier = {0}.
    let n = 4u32;
    let edge_offsets = vec![0u32, 2, 3, 4, 4];
    let edge_targets = vec![1u32, 2, 3, 3];
    let edge_kind_mask = vec![1u32; 4];
    let pg_nodes = vec![0u32; n as usize];
    let pg_node_tags = vec![0u32; n as usize];
    let frontier = vec![0b0001u32];
    let cpu = csr_frontier_degree_sum_cpu(&frontier, &edge_offsets, n);
    let program = csr_frontier_degree_sum(ProgramGraphShape::new(n, 4));
    let gpu = run(
        &program,
        &pg_nodes,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
        &pg_node_tags,
        &frontier,
        1,
    );
    assert_eq!(gpu, cpu);
    assert_eq!(gpu, 2);
}

#[test]
fn cuda_csr_frontier_degree_sum_empty_frontier() {
    let n = 5u32;
    let edge_offsets = vec![0u32, 3, 7, 9, 9, 12];
    let edge_targets = vec![1u32; 12];
    let edge_kind_mask = vec![1u32; 12];
    let pg_nodes = vec![0u32; n as usize];
    let pg_node_tags = vec![0u32; n as usize];
    let frontier = vec![0u32];
    let cpu = csr_frontier_degree_sum_cpu(&frontier, &edge_offsets, n);
    let program = csr_frontier_degree_sum(ProgramGraphShape::new(n, 12));
    let gpu = run(
        &program,
        &pg_nodes,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
        &pg_node_tags,
        &frontier,
        1,
    );
    assert_eq!(gpu, cpu);
    assert_eq!(gpu, 0);
}

#[test]
fn cuda_csr_frontier_degree_sum_full_frontier() {
    let n = 5u32;
    let edge_offsets = vec![0u32, 3, 7, 9, 9, 12];
    let edge_targets = vec![1u32; 12];
    let edge_kind_mask = vec![1u32; 12];
    let pg_nodes = vec![0u32; n as usize];
    let pg_node_tags = vec![0u32; n as usize];
    let frontier = vec![0b11111u32];
    let cpu = csr_frontier_degree_sum_cpu(&frontier, &edge_offsets, n);
    let program = csr_frontier_degree_sum(ProgramGraphShape::new(n, 12));
    let gpu = run(
        &program,
        &pg_nodes,
        &edge_offsets,
        &edge_targets,
        &edge_kind_mask,
        &pg_node_tags,
        &frontier,
        1,
    );
    assert_eq!(gpu, cpu);
    assert_eq!(gpu, 12);
}
