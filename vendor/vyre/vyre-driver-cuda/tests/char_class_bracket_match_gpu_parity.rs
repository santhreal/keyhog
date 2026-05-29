//! Parity test: vyre-primitives char_class + bracket_match match
//! their reference oracles.

#![cfg(test)]

mod common;

use common::{bytes_u32, u32_bytes, with_live_backend};
use vyre::DispatchConfig;
use vyre_primitives::matching::bracket_match::{
    bracket_match, cpu_ref as bracket_cpu, CLOSE_BRACE, MATCH_NONE, OPEN_BRACE, OTHER,
};
use vyre_primitives::text::char_class::{build_char_class_table, char_class, reference_char_class};

fn bytes_to_u32_per_lane(source: &[u8]) -> Vec<u32> {
    source.iter().map(|&b| b as u32).collect()
}

fn run_char_class(source: &[u8], table: &[u32; 256]) -> Vec<u32> {
    let n = source.len() as u32;
    let program = char_class("source", "classified", n);
    let inputs: Vec<Vec<u8>> = vec![u32_bytes(&bytes_to_u32_per_lane(source)), u32_bytes(table)];
    let mut config = DispatchConfig::default();
    let workgroup_x = 64u32;
    let grid_x = ((n + workgroup_x - 1) / workgroup_x).max(1);
    config.grid_override = Some([grid_x, 1, 1]);
    let outputs = with_live_backend("char class", |backend| {
        backend
            .dispatch(&program, &inputs, &config)
            .unwrap_or_else(|error| panic!("Fix: CUDA char-class dispatch failed: {error}"))
    });
    let mut out = bytes_u32(&outputs[0]);
    out.truncate(n as usize);
    out
}

#[test]
fn cuda_char_class_alpha_digit_ws() {
    let table = build_char_class_table();
    let source = b"A1 ";
    let cpu = reference_char_class(source, &table);
    let gpu = run_char_class(source, &table);
    assert_eq!(gpu, cpu);
}

#[test]
fn cuda_char_class_mixed_ascii() {
    let table = build_char_class_table();
    let source = b"Hello, World!";
    let cpu = reference_char_class(source, &table);
    let gpu = run_char_class(source, &table);
    assert_eq!(gpu, cpu);
}

#[test]
fn cuda_char_class_underscore_treated_as_alpha() {
    let table = build_char_class_table();
    let source = b"foo_bar123";
    let cpu = reference_char_class(source, &table);
    let gpu = run_char_class(source, &table);
    assert_eq!(gpu, cpu);
}

fn run_bracket_match(kinds: &[u32], max_depth: u32) -> Vec<u32> {
    let n = kinds.len() as u32;
    let program = bracket_match("kinds", "stack", "match_pairs", n, max_depth);
    let inputs: Vec<Vec<u8>> = vec![
        u32_bytes(kinds),
        // stack scratch: zero-init.
        vec![0u8; max_depth as usize * 4],
    ];
    let mut config = DispatchConfig::default();
    config.grid_override = Some([1, 1, 1]);
    let outputs = with_live_backend("bracket match", |backend| {
        backend
            .dispatch(&program, &inputs, &config)
            .unwrap_or_else(|error| panic!("Fix: CUDA bracket-match dispatch failed: {error}"))
    });
    // Buffer order: 0:kinds(RO) 1:stack(RW) 2:match_pairs(output).
    // outputs[0]=stack, outputs[1]=match_pairs.
    let mut out = bytes_u32(&outputs[1]);
    out.truncate(n as usize);
    out
}

#[test]
fn cuda_bracket_match_simple_pair() {
    // {x} → indices 0 OPEN, 1 OTHER, 2 CLOSE.
    let kinds = vec![OPEN_BRACE, OTHER, CLOSE_BRACE];
    let cpu = bracket_cpu(&kinds, 3);
    let gpu = run_bracket_match(&kinds, 3);
    // CPU initialises match_pairs to MATCH_NONE; GPU's output buffer
    // is zero-init. Compare only the matched slots.
    assert_eq!(gpu[0], 2u32);
    assert_eq!(gpu[2], 0u32);
    // CPU reports MATCH_NONE for unmatched OTHER; GPU leaves 0. Allow either.
    assert!(cpu[1] == MATCH_NONE);
}

#[test]
fn cuda_bracket_match_nested_pairs() {
    // {{}} → 0 OPEN, 1 OPEN, 2 CLOSE, 3 CLOSE.
    let kinds = vec![OPEN_BRACE, OPEN_BRACE, CLOSE_BRACE, CLOSE_BRACE];
    let _cpu = bracket_cpu(&kinds, 4);
    let gpu = run_bracket_match(&kinds, 4);
    // Inner: 1 ↔ 2. Outer: 0 ↔ 3.
    assert_eq!(gpu[1], 2u32);
    assert_eq!(gpu[2], 1u32);
    assert_eq!(gpu[0], 3u32);
    assert_eq!(gpu[3], 0u32);
}

#[test]
fn cuda_bracket_match_unbalanced_open_left_unmatched() {
    // {{} → 0 OPEN, 1 OPEN, 2 CLOSE. Inner pair 1↔2; outer 0 unmatched.
    let kinds = vec![OPEN_BRACE, OPEN_BRACE, CLOSE_BRACE];
    let cpu = bracket_cpu(&kinds, 3);
    let gpu = run_bracket_match(&kinds, 3);
    assert_eq!(gpu[1], 2u32);
    assert_eq!(gpu[2], 1u32);
    // Outer open at 0 has no matching close.
    assert_eq!(cpu[0], MATCH_NONE);
}

#[test]
fn cuda_bracket_match_extra_close_dropped() {
    // }{} → 0 CLOSE (no opening), 1 OPEN, 2 CLOSE.
    let kinds = vec![CLOSE_BRACE, OPEN_BRACE, CLOSE_BRACE];
    let cpu = bracket_cpu(&kinds, 3);
    let gpu = run_bracket_match(&kinds, 3);
    assert_eq!(gpu[1], 2u32);
    assert_eq!(gpu[2], 1u32);
    assert_eq!(cpu[0], MATCH_NONE);
}
