//! Parity test: vyre-primitives text primitives match reference oracles.
//! Covers line_index (newline-aware line counter) and utf8_validate
//! (per-byte UTF-8 class).

#![cfg(test)]

mod common;

use common::{bytes_u32, u32_bytes, with_live_backend};
use vyre::DispatchConfig;
use vyre_primitives::text::line_index::{line_index, reference_line_index};
use vyre_primitives::text::utf8_validate::{reference_utf8_validate, utf8_validate};

fn bytes_to_u32_per_lane(source: &[u8]) -> Vec<u32> {
    source.iter().map(|&b| b as u32).collect()
}

fn run_line_index(source: &[u8]) -> Vec<u32> {
    let n = source.len() as u32;
    let program = line_index("source", "lines", n);
    let inputs: Vec<Vec<u8>> = vec![u32_bytes(&bytes_to_u32_per_lane(source))];
    let mut config = DispatchConfig::default();
    config.grid_override = Some([1, 1, 1]);
    let outputs = with_live_backend("line index primitive", |backend| {
        backend
            .dispatch(&program, &inputs, &config)
            .unwrap_or_else(|error| panic!("Fix: CUDA line-index dispatch failed: {error}"))
    });
    let mut out = bytes_u32(&outputs[0]);
    out.truncate(n as usize);
    out
}

#[test]
fn cuda_line_index_no_newlines() {
    let s = b"Hello";
    let cpu = reference_line_index(s);
    let gpu = run_line_index(s);
    assert_eq!(gpu, cpu);
    assert_eq!(gpu, vec![0u32; 5]);
}

#[test]
fn cuda_line_index_lf_only() {
    let s = b"ab\ncd";
    let cpu = reference_line_index(s);
    let gpu = run_line_index(s);
    assert_eq!(gpu, cpu);
    assert_eq!(gpu, vec![0, 0, 0, 1, 1]);
}

#[test]
fn cuda_line_index_crlf() {
    let s = b"ab\r\ncd";
    let cpu = reference_line_index(s);
    let gpu = run_line_index(s);
    assert_eq!(gpu, cpu);
    assert_eq!(gpu, vec![0, 0, 0, 0, 1, 1]);
}

#[test]
fn cuda_line_index_lone_cr() {
    let s = b"ab\rcd";
    let cpu = reference_line_index(s);
    let gpu = run_line_index(s);
    assert_eq!(gpu, cpu);
    assert_eq!(gpu, vec![0, 0, 0, 1, 1]);
}

#[test]
fn cuda_line_index_back_to_back_lf() {
    let s = b"a\n\nb";
    let cpu = reference_line_index(s);
    let gpu = run_line_index(s);
    assert_eq!(gpu, cpu);
    assert_eq!(gpu, vec![0, 0, 1, 2]);
}

fn run_utf8_validate(source: &[u8]) -> Vec<u32> {
    let n = source.len() as u32;
    let program = utf8_validate("source", "classes", n);
    let inputs: Vec<Vec<u8>> = vec![u32_bytes(&bytes_to_u32_per_lane(source))];
    let mut config = DispatchConfig::default();
    let workgroup_x = 256u32;
    let grid_x = ((n + workgroup_x - 1) / workgroup_x).max(1);
    config.grid_override = Some([grid_x, 1, 1]);
    let outputs = with_live_backend("UTF-8 validate primitive", |backend| {
        backend
            .dispatch(&program, &inputs, &config)
            .unwrap_or_else(|error| panic!("Fix: CUDA UTF-8 validate dispatch failed: {error}"))
    });
    let mut out = bytes_u32(&outputs[0]);
    out.truncate(n as usize);
    out
}

#[test]
fn cuda_utf8_validate_ascii() {
    let s = b"Hello";
    let cpu = reference_utf8_validate(s);
    let gpu = run_utf8_validate(s);
    assert_eq!(gpu, cpu);
}

#[test]
fn cuda_utf8_validate_two_byte_sequence() {
    // U+00E9 = é = 0xC3 0xA9.
    let s = &[0xC3, 0xA9];
    let cpu = reference_utf8_validate(s);
    let gpu = run_utf8_validate(s);
    assert_eq!(gpu, cpu);
}

#[test]
fn cuda_utf8_validate_four_byte_sequence() {
    // U+1F600 = 😀 = 0xF0 0x9F 0x98 0x80.
    let s = &[0xF0, 0x9F, 0x98, 0x80];
    let cpu = reference_utf8_validate(s);
    let gpu = run_utf8_validate(s);
    assert_eq!(gpu, cpu);
}

#[test]
fn cuda_utf8_validate_invalid_overlong_starts() {
    let s = &[0xC0u8, 0xC1];
    let cpu = reference_utf8_validate(s);
    let gpu = run_utf8_validate(s);
    assert_eq!(gpu, cpu);
}

#[test]
fn cuda_utf8_validate_lone_continuation() {
    let s = &[0x80u8];
    let cpu = reference_utf8_validate(s);
    let gpu = run_utf8_validate(s);
    assert_eq!(gpu, cpu);
}
