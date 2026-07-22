//! KH-GAP-002: a selected GPU backend must execute through the GPU route or
//! terminate the scan with a visible failure.
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
fn selected_gpu_backend_executes_or_fails() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    if !scanner.warm_backend(ScanBackend::GpuWgpu) {
        if keyhog_scanner::gpu::gpu_required_by_policy() {
            panic!(
                "KH-GAP-002: selected GPU backend but warm_backend(Gpu) returned false - \
                 CPU substitution is forbidden; report the unavailable GPU stack"
            );
        }
        eprintln!("KH-GAP-002: WGPU execution not run because the scan stack is unavailable");
        return;
    }

    let results = scanner
        .try_scan_coalesced_with_backend_and_admission(
            &[chunk("const K = \"AKIAQYLPMN5HFIQR7XYA\";")],
            ScanBackend::GpuWgpu,
            None,
        )
        .expect("the warmed WGPU route must execute without CPU substitution");
    let count: usize = results.iter().map(|chunk| chunk.len()).sum();
    assert_eq!(
        count, 1,
        "the selected GPU route must return exactly the canonical AWS finding"
    );
}
