//! Smoke test for vyre's new `classic_ac_bounded_ranges_program`
//! end-to-end on the real GPU. Validates that the AC kernel
//! produces the same `(pattern_id, start, end)` triples as the CPU
//! reference oracle on a handful of overlapping-pattern fixtures.
//!
//! Skipped at runtime when no compatible wgpu adapter is available
//! (CI without `--features gpu`, headless containers, software-only
//! adapters). Skip is explicit via `eprintln!` so a no-GPU machine
//! doesn't fake-pass the contract.

use vyre::backend::VyreBackend;
use vyre_libs::matching::classic_ac::{
    build_ac_bounded_ranges_program, classic_ac_bounded_ranges_scan, classic_ac_compile,
};
use vyre_libs::matching::dispatch_io;

fn pack_u32_slice(words: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(words.len() * 4);
    for w in words {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
}

fn run_case(patterns: &[&[u8]], haystack: &[u8]) {
    let pattern_lengths: Vec<u32> = patterns.iter().map(|p| p.len() as u32).collect();
    let ac = classic_ac_compile(patterns);

    // CPU oracle.
    let cpu = classic_ac_bounded_ranges_scan(&ac, &pattern_lengths, haystack);
    let mut cpu_sorted: Vec<(u32, u32, u32)> = cpu;
    cpu_sorted.sort_unstable();

    // GPU dispatch.
    let backend = match vyre_driver_wgpu::WgpuBackend::new() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("SKIP: no wgpu adapter available: {e}");
            return;
        }
    };

    const MAX_MATCHES: u32 = 1024;
    let program = build_ac_bounded_ranges_program(
        &ac.dfa,
        pattern_lengths.len() as u32,
        MAX_MATCHES,
    );

    // Binding order MUST match `classic_ac_bounded_ranges_program`'s
    // BufferDecl indices (0..7). Reordering here would silently
    // mis-wire the GPU kernel.
    let inputs: Vec<Vec<u8>> = vec![
        dispatch_io::pack_haystack_u32(haystack),
        pack_u32_slice(&ac.dfa.transitions),
        pack_u32_slice(&ac.dfa.output_offsets),
        pack_u32_slice(&ac.dfa.output_records),
        pack_u32_slice(&pattern_lengths),
        pack_u32_slice(&[haystack.len() as u32]),
        vec![0u8; 4], // match_count atomic
        // matches: pure output buffer; backend allocates from program's BufferDecl.
    ];

    let config =
        dispatch_io::byte_scan_dispatch_config(haystack.len() as u32, program.workgroup_size[0]);

    let borrowed: Vec<&[u8]> = inputs.iter().map(Vec::as_slice).collect();
    let outputs = match backend.dispatch_borrowed(&program, &borrowed, &config) {
        Ok(o) => o,
        Err(e) => panic!("GPU dispatch failed: {e:?}"),
    };

    // Outputs are returned in the order the kernel WRITES them:
    // `match_count` (binding 6) then `matches` (binding 7).
    assert!(outputs.len() >= 2, "expected 2 output buffers, got {}", outputs.len());
    let count_bytes = &outputs[0];
    let matches_bytes = &outputs[1];
    assert!(
        count_bytes.len() >= 4,
        "match_count buffer truncated to {} bytes",
        count_bytes.len()
    );
    let count = u32::from_le_bytes([count_bytes[0], count_bytes[1], count_bytes[2], count_bytes[3]]);

    let triples = dispatch_io::unpack_match_triples(matches_bytes, count.min(MAX_MATCHES));
    let mut gpu_sorted: Vec<(u32, u32, u32)> = triples
        .iter()
        .map(|m| (m.pattern_id, m.start, m.end))
        .collect();
    gpu_sorted.sort_unstable();

    assert_eq!(
        gpu_sorted, cpu_sorted,
        "GPU AC kernel disagrees with CPU oracle.\n  patterns={:?}\n  haystack={:?}\n  CPU: {:?}\n  GPU: {:?}",
        patterns,
        std::str::from_utf8(haystack).unwrap_or("<bin>"),
        cpu_sorted,
        gpu_sorted
    );
}

#[test]
fn ushers_overlapping_patterns_match_on_gpu() {
    // Canonical AC test: patterns {he, she, his, hers} on "ushers".
    let patterns: [&[u8]; 4] = [b"he", b"she", b"his", b"hers"];
    run_case(&patterns, b"ushers");
}

#[test]
fn nested_suffix_patterns_match_on_gpu() {
    // {a, aa, aaa} on "aaaa". Stress-tests the output_links emit.
    let patterns: [&[u8]; 3] = [b"a", b"aa", b"aaa"];
    run_case(&patterns, b"aaaa");
}

#[test]
fn realistic_secret_prefixes_match_on_gpu() {
    // Mix of typical keyhog literal anchors + a long haystack so the
    // bounded suffix window is meaningfully smaller than the haystack.
    let patterns: [&[u8]; 4] = [b"sk_live_", b"AKIA", b"ghp_", b"sb_"];
    let haystack = b"prefix garbage sk_live_4eC39HqLyjWDarjtT1zdp7dc more text AKIAQYLPMN5HFIQR7XYA tail ghp_aBcD1234EFgh5678ijkl";
    run_case(&patterns, haystack);
}

#[test]
fn empty_haystack_emits_nothing() {
    // Degenerate but legal: empty haystack means no invocations,
    // match buffer stays at count=0.
    let patterns: [&[u8]; 1] = [b"abc"];
    run_case(&patterns, b"");
}
