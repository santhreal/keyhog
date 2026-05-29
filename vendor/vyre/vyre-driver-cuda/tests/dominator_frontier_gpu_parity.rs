//! Parity test: GPU dominance frontier matches the reference oracle.

#![cfg(test)]

mod common;

use common::with_cuda_optimizer_dispatcher;
use vyre_self_substrate::dominator_frontier::{
    compute_dominance_frontier as reference_compute_dominance_frontier,
    compute_dominance_frontier_via,
};

#[test]
fn cuda_dominance_frontier_via_chain_is_empty() {
    // dom: 0->{0,1,2,3}; 1->{1,2,3}; 2->{2,3}; 3->{3}
    let dom_offsets = vec![0u32, 4, 7, 9, 10];
    let dom_targets = vec![0u32, 1, 2, 3, 1, 2, 3, 2, 3, 3];
    // pred: 0->{}; 1->{0}; 2->{1}; 3->{2}
    let pred_offsets = vec![0u32, 0, 1, 2, 3];
    let pred_targets = vec![0u32, 1, 2];
    let seed = vec![0b0001u32];
    let gpu = with_cuda_optimizer_dispatcher("dominance frontier chain", |dispatcher| {
        compute_dominance_frontier_via(
            dispatcher,
            4,
            &dom_offsets,
            &dom_targets,
            &pred_offsets,
            &pred_targets,
            &seed,
        )
        .expect("dispatch")
    });
    let reference = reference_compute_dominance_frontier(
        4,
        &dom_offsets,
        &dom_targets,
        &pred_offsets,
        &pred_targets,
        &seed,
    );
    assert_eq!(gpu, reference);
}

#[test]
fn cuda_dominance_frontier_via_diamond_seed_is_merge_node() {
    // dom: 0->{0,1,2,3}; 1->{1}; 2->{2}; 3->{3}
    let dom_offsets = vec![0u32, 4, 5, 6, 7];
    let dom_targets = vec![0u32, 1, 2, 3, 1, 2, 3];
    // pred: 0->{}; 1->{0}; 2->{0}; 3->{1, 2}
    let pred_offsets = vec![0u32, 0, 1, 2, 4];
    let pred_targets = vec![0u32, 0, 1, 2];
    let seed = vec![0b0010u32]; // seed = {1}
    let gpu = with_cuda_optimizer_dispatcher("dominance frontier diamond", |dispatcher| {
        compute_dominance_frontier_via(
            dispatcher,
            4,
            &dom_offsets,
            &dom_targets,
            &pred_offsets,
            &pred_targets,
            &seed,
        )
        .expect("dispatch")
    });
    let reference = reference_compute_dominance_frontier(
        4,
        &dom_offsets,
        &dom_targets,
        &pred_offsets,
        &pred_targets,
        &seed,
    );
    assert_eq!(gpu, reference);
    // Sanity: frontier should be {3}.
    assert_eq!(gpu, vec![0b1000u32]);
}
