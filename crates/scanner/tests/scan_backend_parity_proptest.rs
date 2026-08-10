//! Differential fuzz: the CPU and SIMD backends must recover IDENTICAL findings
//! for any input (#177/#183). The SIMD trigger bitmap unions AC-literal +
//! Hyperscan hits; a divergence here is a recall regression (some detectors fire
//! only via one path). This fuzzes that parity over random secret-shaped text.
//! ML-independent; run without `ml` while the embedded weights are mid-retrain.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use proptest::prelude::*;
use std::sync::LazyLock;

static DETECTORS: LazyLock<Vec<keyhog_core::DetectorSpec>> =
    LazyLock::new(|| keyhog_core::embedded_detector_specs().to_vec());
static CPU_SCANNER: LazyLock<CompiledScanner> = LazyLock::new(|| {
    CompiledScanner::compile_for_backend(DETECTORS.clone(), ScanBackend::CpuFallback)
        .expect("compile exact CPU scanner")
});
static SIMD_SCANNER: LazyLock<CompiledScanner> = LazyLock::new(|| {
    CompiledScanner::compile_for_backend(DETECTORS.clone(), ScanBackend::SimdCpu)
        .expect("compile exact SIMD scanner")
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
    let scanner = match backend {
        ScanBackend::CpuFallback => &*CPU_SCANNER,
        ScanBackend::SimdCpu => &*SIMD_SCANNER,
        _ => panic!("parity property accepts only CPU and SIMD backends"),
    };
    scanner.clear_fragment_cache();
    let mut creds: Vec<String> = scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), backend)
        .expect("selected backend scan succeeds")
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
