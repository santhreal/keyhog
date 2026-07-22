//! Helpers for live GPU-backend ↔ CPU parity adversarial samples.

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::path::PathBuf;
use std::sync::OnceLock;

pub fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

pub fn production_scanner() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
        CompiledScanner::compile(detectors).expect("compile scanner")
    })
}

pub fn chunk(text: &str, path: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "adversarial".into(),
            path: Some(path.into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

pub fn credential_keys(results: &[Vec<RawMatch>]) -> std::collections::BTreeSet<(String, String)> {
    results
        .iter()
        .flatten()
        .map(|m| {
            (
                m.detector_id.as_ref().to_string(),
                m.credential.as_ref().to_string(),
            )
        })
        .collect()
}

pub fn assert_cpu_gpu_backend_parity(text: &str, path: &str, label: &str) {
    let scanner = production_scanner();
    let chunks = [chunk(text, path)];

    let cpu = credential_keys(&scanner.scan_chunks_with_backend(&chunks, ScanBackend::CpuFallback));
    assert!(
        !cpu.is_empty(),
        "{label}: CPU baseline must fire on adversarial sample (recall oracle)"
    );

    if !scanner.warm_backend(ScanBackend::GpuWgpu) {
        eprintln!("{label}: GPU backend parity not run because the WGPU scan stack is unavailable");
        return;
    }

    let gpu = scanner
        .try_scan_coalesced_with_backend_and_admission(&chunks, ScanBackend::GpuWgpu, None)
        .unwrap_or_else(|error| panic!("{label}: WGPU dispatch failed after warmup: {error}"));
    let gpu = credential_keys(&gpu);

    assert_eq!(
        cpu,
        gpu,
        "{label}: GPU backend findings must match CPU fallback; cpu_only={:?} gpu_only={:?}",
        cpu.difference(&gpu).collect::<Vec<_>>(),
        gpu.difference(&cpu).collect::<Vec<_>>()
    );
}
