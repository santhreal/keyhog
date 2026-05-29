//! Parity tests for fixpoint::bitset_fixpoint, visual::packed_rgba_map,
//! and matching::region::dedup_regions_flag_program.

#![cfg(test)]

mod common;

use common::{bytes_u32, u32_bytes, with_live_backend};
use vyre::DispatchConfig;
use vyre_primitives::fixpoint::bitset_fixpoint::bitset_fixpoint;
use vyre_primitives::matching::region::dedup_regions_flag_program;
use vyre_primitives::visual::packed_rgba_map::packed_rgba_map;

// ---------------------------------------------------------------------
// bitset_fixpoint: changed=1 iff current[w] != next[w] for any w.
// ---------------------------------------------------------------------

fn run_fixpoint(current: &[u32], next: &[u32]) -> u32 {
    assert_eq!(current.len(), next.len());
    let words = current.len() as u32;
    let program = bitset_fixpoint("current", "next", "changed", words);
    let inputs: Vec<Vec<u8>> = vec![u32_bytes(current), u32_bytes(next), vec![0u8; 4]];
    let mut config = DispatchConfig::default();
    let workgroup_x = 256u32;
    let grid_x = ((words + workgroup_x - 1) / workgroup_x).max(1);
    config.grid_override = Some([grid_x, 1, 1]);
    let outputs = with_live_backend("bitset fixpoint", |backend| {
        backend
            .dispatch(&program, &inputs, &config)
            .unwrap_or_else(|error| panic!("Fix: CUDA bitset-fixpoint dispatch failed: {error}"))
    });
    bytes_u32(&outputs[0])[0]
}

#[test]
fn cuda_bitset_fixpoint_no_change() {
    let v = vec![0xAAAAu32, 0u32, 0xFFFFu32];
    let gpu = run_fixpoint(&v, &v);
    assert_eq!(gpu, 0);
}

#[test]
fn cuda_bitset_fixpoint_one_word_changed() {
    let current = vec![0xAAAAu32, 0u32, 0xFFFFu32];
    let next = vec![0xAAAAu32, 1u32, 0xFFFFu32];
    let gpu = run_fixpoint(&current, &next);
    assert_eq!(gpu, 1);
}

#[test]
fn cuda_bitset_fixpoint_all_changed() {
    let current = vec![0u32; 8];
    let next = vec![0xFFFF_FFFFu32; 8];
    let gpu = run_fixpoint(&current, &next);
    assert_eq!(gpu, 1);
}

// ---------------------------------------------------------------------
// packed_rgba_map: identity copy.
// ---------------------------------------------------------------------

fn run_rgba_identity(pixels: &[u32]) -> Vec<u32> {
    let count = pixels.len() as u32;
    let program = packed_rgba_map("input", "output", count);
    let inputs: Vec<Vec<u8>> = vec![u32_bytes(pixels), vec![0u8; count as usize * 4]];
    let mut config = DispatchConfig::default();
    let workgroup_x = 256u32;
    let grid_x = ((count + workgroup_x - 1) / workgroup_x).max(1);
    config.grid_override = Some([grid_x, 1, 1]);
    let outputs = with_live_backend("packed RGBA map", |backend| {
        backend
            .dispatch(&program, &inputs, &config)
            .unwrap_or_else(|error| panic!("Fix: CUDA packed-RGBA dispatch failed: {error}"))
    });
    let mut out = bytes_u32(&outputs[0]);
    out.truncate(count as usize);
    out
}

#[test]
fn cuda_packed_rgba_map_identity_basic() {
    let pixels = vec![0xFF00_0000u32, 0xFF00_00FF, 0xFF00_FF00, 0xFFFF_0000];
    let gpu = run_rgba_identity(&pixels);
    assert_eq!(gpu, pixels);
}

#[test]
fn cuda_packed_rgba_map_identity_large() {
    let pixels: Vec<u32> = (0u32..512).map(|i| 0xFF00_0000 | i).collect();
    let gpu = run_rgba_identity(&pixels);
    assert_eq!(gpu, pixels);
}

// ---------------------------------------------------------------------
// dedup_regions_flag_program: per-lane survivor flag.
// ---------------------------------------------------------------------

fn cpu_dedup_flags(pids: &[u32], starts: &[u32], ends: &[u32]) -> Vec<u32> {
    let mut out = vec![0u32; pids.len()];
    for i in 0..pids.len() {
        let flag = if i == 0 {
            1u32
        } else {
            let different_pid = pids[i] != pids[i - 1];
            let no_overlap = starts[i] > ends[i - 1];
            u32::from(different_pid || no_overlap)
        };
        out[i] = flag;
    }
    out
}

fn run_dedup_flag(pids: &[u32], starts: &[u32], ends: &[u32]) -> Vec<u32> {
    assert_eq!(pids.len(), starts.len());
    assert_eq!(pids.len(), ends.len());
    let count = pids.len() as u32;
    let program = dedup_regions_flag_program("pids", "starts", "ends", "survivors", count);
    // survivors is BufferAccess::WriteOnly so it does not consume an
    // input slot.
    let inputs: Vec<Vec<u8>> = vec![u32_bytes(pids), u32_bytes(starts), u32_bytes(ends)];
    let mut config = DispatchConfig::default();
    config.grid_override = Some([1, 1, 1]);
    let outputs = with_live_backend("dedup regions flag", |backend| {
        backend
            .dispatch(&program, &inputs, &config)
            .unwrap_or_else(|error| panic!("Fix: CUDA dedup-regions flag dispatch failed: {error}"))
    });
    let mut out = bytes_u32(&outputs[0]);
    out.truncate(count as usize);
    out
}

#[test]
fn cuda_dedup_regions_flag_distinct_pids() {
    let pids = vec![1u32, 2, 3];
    let starts = vec![0u32, 10, 20];
    let ends = vec![5u32, 15, 25];
    let cpu = cpu_dedup_flags(&pids, &starts, &ends);
    let gpu = run_dedup_flag(&pids, &starts, &ends);
    assert_eq!(gpu, cpu);
    assert_eq!(gpu, vec![1, 1, 1]); // all distinct.
}

#[test]
fn cuda_dedup_regions_flag_overlapping_drops_second() {
    let pids = vec![1u32, 1, 1];
    let starts = vec![0u32, 3, 100];
    let ends = vec![10u32, 12, 110];
    let cpu = cpu_dedup_flags(&pids, &starts, &ends);
    let gpu = run_dedup_flag(&pids, &starts, &ends);
    assert_eq!(gpu, cpu);
    // Index 1 overlaps index 0 (start=3 <= end=10) → drop. Index 2
    // is past the prior end → keep.
    assert_eq!(gpu, vec![1, 0, 1]);
}

#[test]
fn cuda_dedup_regions_flag_pid_change_resets_overlap() {
    let pids = vec![1u32, 2, 2];
    let starts = vec![0u32, 5, 10];
    let ends = vec![20u32, 15, 25];
    let cpu = cpu_dedup_flags(&pids, &starts, &ends);
    let gpu = run_dedup_flag(&pids, &starts, &ends);
    assert_eq!(gpu, cpu);
    // Index 1: pid changed → keep. Index 2: same pid, start=10 <=
    // prev end=15 → drop.
    assert_eq!(gpu, vec![1, 1, 0]);
}
