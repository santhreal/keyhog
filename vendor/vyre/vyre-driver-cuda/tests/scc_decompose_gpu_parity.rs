//! Parity test: GPU scc_decompose matches CPU oracle.

#![cfg(test)]

mod common;

use common::{bytes_u32, u32_bytes, with_live_backend};
use vyre::DispatchConfig;
use vyre_primitives::graph::scc_decompose::{cpu_ref, scc_decompose};

fn run(
    node_count: u32,
    forward: &[u32],
    backward: &[u32],
    component_in: &[u32],
    pivot: u32,
) -> Vec<u32> {
    let program = scc_decompose(node_count, "fwd", "bwd", "comp", pivot);
    let inputs: Vec<Vec<u8>> = vec![
        u32_bytes(forward),
        u32_bytes(backward),
        u32_bytes(component_in),
    ];
    let mut config = DispatchConfig::default();
    // Workgroup is [1,1,1] in this Program; one thread per node.
    config.grid_override = Some([node_count.max(1), 1, 1]);
    let outputs = with_live_backend("SCC decompose", |backend| {
        backend
            .dispatch(&program, &inputs, &config)
            .unwrap_or_else(|error| panic!("Fix: CUDA SCC decompose dispatch failed: {error}"))
    });
    let mut out = bytes_u32(&outputs[0]);
    out.truncate(node_count as usize);
    out
}

#[test]
fn cuda_scc_decompose_first_pivot_stamps_intersection() {
    // 4 nodes. Forward/backward closures both = {0, 1, 2}, intersection {0, 1, 2}.
    let forward = vec![0b0111u32];
    let backward = vec![0b0111u32];
    let component_in = vec![u32::MAX; 4];
    let pivot = 5;
    let cpu = cpu_ref(4, &forward, &backward, &component_in, pivot);
    let gpu = run(4, &forward, &backward, &component_in, pivot);
    assert_eq!(gpu, cpu);
    assert_eq!(gpu, vec![5, 5, 5, u32::MAX]);
}

#[test]
fn cuda_scc_decompose_only_intersect_stamped() {
    // forward = {0, 1, 2, 3}, backward = {1, 2}. Intersection = {1, 2}.
    let forward = vec![0b1111u32];
    let backward = vec![0b0110u32];
    let component_in = vec![u32::MAX; 4];
    let pivot = 7;
    let cpu = cpu_ref(4, &forward, &backward, &component_in, pivot);
    let gpu = run(4, &forward, &backward, &component_in, pivot);
    assert_eq!(gpu, cpu);
    assert_eq!(gpu, vec![u32::MAX, 7, 7, u32::MAX]);
}

#[test]
fn cuda_scc_decompose_second_pivot_does_not_overwrite() {
    // First pivot already stamped {1, 2} with 5. Second pivot reaches {0, 1}
    //  -  only slot 0 should be overwritten (1 stays at 5).
    let component_in = vec![u32::MAX, 5, 5, u32::MAX];
    let forward = vec![0b0011u32];
    let backward = vec![0b0011u32];
    let pivot = 9;
    let cpu = cpu_ref(4, &forward, &backward, &component_in, pivot);
    let gpu = run(4, &forward, &backward, &component_in, pivot);
    assert_eq!(gpu, cpu);
    assert_eq!(gpu, vec![9, 5, 5, u32::MAX]);
}

#[test]
fn cuda_scc_decompose_disjoint_intersect_yields_no_writes() {
    // forward = {0, 1}, backward = {2, 3}. Intersection empty.
    let forward = vec![0b0011u32];
    let backward = vec![0b1100u32];
    let component_in = vec![u32::MAX; 4];
    let pivot = 11;
    let cpu = cpu_ref(4, &forward, &backward, &component_in, pivot);
    let gpu = run(4, &forward, &backward, &component_in, pivot);
    assert_eq!(gpu, cpu);
    assert_eq!(gpu, vec![u32::MAX; 4]);
}
