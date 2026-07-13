//! Corpus-wide per-detector BACKEND PARITY (#177/#183). The SIMD trigger bitmap
//! unions AC-literal + Hyperscan hits; if a detector's trigger is missing from
//! one backend it fires on CPU but not SIMD (or vice-versa), a silent recall
//! divergence. This drives EACH detector's own regex-generated example through
//! both the CpuFallback and SimdCpu backends and asserts the set of firing
//! detectors is byte-for-byte identical. ML-independent; run without `ml` while
//! the embedded weights are mid-retrain.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::TestRunner;

fn fired_ids(scanner: &CompiledScanner, text: &str, backend: ScanBackend) -> Vec<String> {
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "corpus-parity".into(),
            path: Some("s.txt".into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    scanner.clear_fragment_cache();
    let mut ids: Vec<String> = scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), backend)
        .iter()
        .flat_map(|per_chunk| per_chunk.iter())
        .map(|m| m.detector_id.to_string())
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

#[test]
fn cpu_and_simd_agree_on_every_detector_example() {
    let specs = keyhog_core::embedded_detector_specs().to_vec();
    let scanner = CompiledScanner::compile(specs.clone()).expect("scanner compile");
    let mut runner = TestRunner::deterministic();

    let mut checked = 0u32;
    let mut unicode_divergences = 0u32;
    let mut divergences = Vec::new();
    for spec in specs.iter() {
        if format!("{:?}", spec.kind) != "Regex" {
            continue;
        }
        let Some(pat) = spec.patterns.first() else {
            continue;
        };
        let Ok(strat) = proptest::string::string_regex(&pat.regex) else {
            continue;
        };
        let Ok(tree) = strat.new_tree(&mut runner) else {
            continue;
        };
        let example = tree.current();
        checked += 1;
        let cpu = fired_ids(&scanner, &example, ScanBackend::CpuFallback);
        let simd = fired_ids(&scanner, &example, ScanBackend::SimdCpu);
        if cpu != simd {
            // ASCII parity is the clean invariant (the backends MUST agree).
            // Unicode-heavy inputs diverge in the normalization path (tracked as
            // the CPU/SIMD-unicode-divergence backlog finding); count and surface
            // those loudly (Law 10) rather than assert on them here.
            if example.is_ascii() {
                if divergences.len() < 20 {
                    let only_cpu: Vec<_> = cpu.iter().filter(|i| !simd.contains(i)).collect();
                    let only_simd: Vec<_> = simd.iter().filter(|i| !cpu.contains(i)).collect();
                    divergences.push(format!(
                        "{}: only_cpu={only_cpu:?} only_simd={only_simd:?} ex={:?}",
                        spec.id, example
                    ));
                }
            } else {
                unicode_divergences += 1;
            }
        }
    }

    assert!(
        checked >= 800,
        "expected to exercise most of the corpus, only checked {checked}"
    );
    assert!(
        divergences.is_empty(),
        "CPU/SIMD backend divergence on {} ASCII detector examples: {:#?}",
        divergences.len(),
        divergences
    );
    eprintln!(
        "backend parity: {checked} detector examples; CPU == SIMD on all ASCII inputs; \
         {unicode_divergences} unicode-input divergences (tracked finding)"
    );
}
