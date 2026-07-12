//! Differential fuzz: the CPU and SIMD backends must recover IDENTICAL findings
//! for any input (#177/#183). The SIMD trigger bitmap unions AC-literal +
//! Hyperscan hits; a divergence here is a recall regression (some detectors fire
//! only via one path). This fuzzes that parity over random secret-shaped text.
//! ML-independent; run without `ml` while the embedded weights are mid-retrain.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use proptest::prelude::*;
use std::sync::LazyLock;

static SCANNER: LazyLock<CompiledScanner> = LazyLock::new(|| {
    CompiledScanner::compile(keyhog_core::embedded_detector_specs().to_vec())
        .expect("scanner compile")
});

fn scan_sorted(text: &str, backend: ScanBackend) -> Vec<String> {
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "parity-fuzz".into(),
            path: Some("s.txt".into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    SCANNER.clear_fragment_cache();
    let mut creds: Vec<String> = SCANNER
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), backend)
        .iter()
        .flat_map(|per_chunk| per_chunk.iter())
        .map(|m| {
            format!(
                "{}|{}|{}",
                m.detector_id,
                m.location.offset,
                m.credential.as_ref()
            )
        })
        .collect();
    creds.sort();
    creds
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3000))]

    #[test]
    fn cpu_and_simd_backends_agree_on_arbitrary_input(
        s in "[A-Za-z0-9+/=_\\-.:@ \t\n]{0,300}"
    ) {
        let cpu = scan_sorted(&s, ScanBackend::CpuFallback);
        let simd = scan_sorted(&s, ScanBackend::SimdCpu);
        prop_assert_eq!(&cpu, &simd, "CPU vs SIMD divergence on {:?}", s);
    }

    /// Planted real secrets must be found identically by both backends.
    #[test]
    fn cpu_and_simd_agree_with_planted_secrets(
        noise in "[ -~]{0,60}"
    ) {
        let text = format!(
            "{noise} AKIAQYLPMN5HFIQR7BBB {noise} glpat-ABCDEF1234567890abcd",
        );
        let cpu = scan_sorted(&text, ScanBackend::CpuFallback);
        let simd = scan_sorted(&text, ScanBackend::SimdCpu);
        prop_assert_eq!(&cpu, &simd, "backend divergence with planted secrets in {:?}", text);
    }
}
