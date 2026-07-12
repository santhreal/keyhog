//! KH-GAP-002: forced GPU backend must not silently scan with CPU without signal.
//!
//! GPU-feature-gated: this asserts `warm_backend(Gpu)` succeeds, which is only
//! possible on a build that compiled the GPU stack (`--features gpu`, exercised
//! by the runners-nightly lane on real GPU hosts). Under the GPU-less `ci-lean`
//! aggregator it would fail because there is no usable adapter. Gating keeps it
//! on the lane that can run it.
#![cfg(feature = "gpu")]

#[path = "../support/mod.rs"]
mod support;

use crate::support::paths::detector_dir;
use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn chunk(text: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "test".into(),
            path: Some("fixture.rs".into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

#[test]
fn gpu_backend_warm_reports_availability() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let gpu_ready = scanner.warm_backend(ScanBackend::Gpu);

    if !gpu_ready {
        panic!(
            "KH-GAP-002: selected GPU backend but warm_backend(Gpu) returned false - \
             silent CPU fallback is forbidden without explicit error"
        );
    }

    let results = scanner.scan_chunks_with_backend(
        &[chunk("const K = \"AKIAQYLPMN5HFIQR7XYA\";")],
        ScanBackend::Gpu,
    );
    let count: usize = results.iter().map(|c| c.len()).sum();
    assert!(
        count > 0,
        "GPU-warmed scanner must find canonical AWS key on fixture, got {count} matches"
    );
}
