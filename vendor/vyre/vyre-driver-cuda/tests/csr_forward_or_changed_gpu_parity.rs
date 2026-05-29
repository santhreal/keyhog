//! Parity test: GPU iterated forward closure matches CPU iterated closure.

#![cfg(test)]

mod common;

use common::with_cuda_optimizer_dispatcher;
use vyre_self_substrate::csr_forward_or_changed::{
    forward_closure_via_change_flag_gpu, reference_forward_closure_via_change_flag,
};

fn assert_forward_closure_matches(
    label: &str,
    n: u32,
    off: &[u32],
    tgt: &[u32],
    msk: &[u32],
    seed: &[u32],
    allow: u32,
    max_iters: u32,
) -> Vec<u32> {
    let cpu = reference_forward_closure_via_change_flag(n, off, tgt, msk, seed, allow, max_iters);
    with_cuda_optimizer_dispatcher(label, |dispatcher| {
        let gpu = forward_closure_via_change_flag_gpu(
            dispatcher, n, off, tgt, msk, seed, allow, max_iters,
        )
        .expect("dispatch");
        assert_eq!(gpu, cpu, "{label}: closure divergence");
        gpu
    })
}

#[test]
fn cuda_forward_closure_chain_matches_cpu() {
    // Chain 0 -> 1 -> 2 -> 3.
    let off = vec![0u32, 1, 2, 3, 3];
    let tgt = vec![1u32, 2, 3];
    let msk = vec![1u32, 1, 1];
    let seed = vec![0b0001u32];
    let gpu = assert_forward_closure_matches(
        "chain closure",
        4,
        &off,
        &tgt,
        &msk,
        &seed,
        0xFFFF_FFFF,
        16,
    );
    assert_eq!(gpu, vec![0b1111u32]);
}

#[test]
fn cuda_forward_closure_disconnected() {
    // 0 -> 1, 2 -> 3, no cross.
    let off = vec![0u32, 1, 1, 2, 2];
    let tgt = vec![1u32, 3];
    let msk = vec![1u32, 1];
    let seed = vec![0b0001u32]; // only {0}
    let gpu = assert_forward_closure_matches(
        "disconnected closure",
        4,
        &off,
        &tgt,
        &msk,
        &seed,
        0xFFFF_FFFF,
        16,
    );
    assert_eq!(gpu, vec![0b0011u32]);
}

#[test]
fn cuda_forward_closure_self_loop_terminates() {
    let off = vec![0u32, 1, 1];
    let tgt = vec![0u32];
    let msk = vec![1u32];
    let seed = vec![0b01u32];
    assert_forward_closure_matches(
        "self-loop closure",
        2,
        &off,
        &tgt,
        &msk,
        &seed,
        0xFFFF_FFFF,
        50,
    );
}

#[test]
fn cuda_forward_closure_allow_mask_filters() {
    let off = vec![0u32, 1, 1];
    let tgt = vec![1u32];
    let msk = vec![0b0010u32];
    let seed = vec![0b01u32];
    let allow = 0b0001;
    let gpu =
        assert_forward_closure_matches("allow-mask closure", 2, &off, &tgt, &msk, &seed, allow, 16);
    assert_eq!(gpu, vec![0b01u32]);
}

#[test]
fn cuda_forward_closure_diamond() {
    // Diamond 0 -> {1, 2} -> 3.
    let off = vec![0u32, 2, 3, 4, 4];
    let tgt = vec![1u32, 2, 3, 3];
    let msk = vec![1u32, 1, 1, 1];
    let seed = vec![0b0001u32];
    let gpu = assert_forward_closure_matches(
        "diamond closure",
        4,
        &off,
        &tgt,
        &msk,
        &seed,
        0xFFFF_FFFF,
        16,
    );
    assert_eq!(gpu, vec![0b1111u32]);
}
