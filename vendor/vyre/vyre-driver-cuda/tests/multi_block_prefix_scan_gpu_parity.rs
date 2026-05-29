//! Parity test for reduce::multi_block_prefix_scan_sum_u32  -  covers
//! both the small-input fast path (n ≤ BLOCK_LANES) and the multi-pass
//! Blelloch chain.

#![cfg(test)]

mod common;

use common::{bytes_u32, u32_bytes, with_live_backend};
use vyre::DispatchConfig;
use vyre_primitives::reduce::multi_block_prefix_scan::{
    cpu_ref as mbps_cpu, multi_block_prefix_scan_sum_u32, BLOCK_LANES,
};

fn run_mbps(input: &[u32]) -> Vec<u32> {
    use vyre::ir::BufferAccess;
    let n = input.len() as u32;
    let program = multi_block_prefix_scan_sum_u32("input", "output", n);
    // Only ReadOnly / ReadWrite storage buffers consume input slots.
    // BufferDecl::output (WriteOnly) and BufferDecl::workgroup do not.
    let mut inputs: Vec<Vec<u8>> = Vec::new();
    for buf in program.buffers().iter() {
        let access = buf.access();
        // Output buffers (BufferDecl::output) and workgroup-local
        // scratch (BufferDecl::workgroup) do not take an input slot.
        // Storage ReadOnly + ReadWrite (non-output) do.
        let needs_input = matches!(access, BufferAccess::ReadOnly | BufferAccess::ReadWrite)
            && !buf.is_output()
            && !matches!(access, BufferAccess::Workgroup);
        if !needs_input {
            continue;
        }
        let elements = buf.count() as usize;
        if buf.name() == "input" {
            inputs.push(u32_bytes(input));
        } else {
            inputs.push(vec![0u8; elements.max(1) * 4]);
        }
    }
    let mut config = DispatchConfig::default();
    // Small fast path uses `prefix_scan` workgroup; large path uses
    // multi-block dispatch where the substrate handles grid_x.
    if n <= BLOCK_LANES {
        config.grid_override = Some([1, 1, 1]);
    }
    let outputs = with_live_backend("multi-block prefix scan", |backend| {
        backend
            .dispatch(&program, &inputs, &config)
            .unwrap_or_else(|error| {
                panic!("Fix: CUDA multi-block prefix-scan dispatch failed: {error}")
            })
    });
    // Outputs are returned in declaration order over writeable buffers
    // (RW storage + WriteOnly + is_output marker). Locate "output".
    let out_idx = program
        .buffers()
        .iter()
        .filter(|b| {
            b.is_output()
                || matches!(
                    b.access(),
                    BufferAccess::ReadWrite | BufferAccess::WriteOnly
                )
        })
        .position(|b| b.name() == "output")
        .expect("output buffer present");
    let mut out = bytes_u32(&outputs[out_idx]);
    out.truncate(n as usize);
    out
}

#[test]
fn cuda_mbps_small_inclusive_sum() {
    let input = vec![1u32, 2, 3, 4, 5];
    let cpu = mbps_cpu(&input);
    let gpu = run_mbps(&input);
    assert_eq!(gpu, cpu);
    assert_eq!(gpu, vec![1, 3, 6, 10, 15]);
}

#[test]
fn cuda_mbps_zeros() {
    let input = vec![0u32; 16];
    let cpu = mbps_cpu(&input);
    let gpu = run_mbps(&input);
    assert_eq!(gpu, cpu);
    assert_eq!(gpu, vec![0u32; 16]);
}

#[test]
fn cuda_mbps_one_full_block() {
    // Exactly BLOCK_LANES elements, all ones; inclusive scan = 1..=BLOCK_LANES.
    let input = vec![1u32; BLOCK_LANES as usize];
    let cpu = mbps_cpu(&input);
    let gpu = run_mbps(&input);
    assert_eq!(gpu, cpu);
    assert_eq!(gpu[BLOCK_LANES as usize - 1], BLOCK_LANES);
}
