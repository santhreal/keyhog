//! KH-GAP-002: forced GPU backend must not silently scan with CPU without signal.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn detector_dir() -> std::path::PathBuf {
    let mut d = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

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
    unsafe { std::env::set_var("KEYHOG_BACKEND", "gpu") };
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let gpu_ready = scanner.warm_backend(ScanBackend::Gpu);
    unsafe { std::env::remove_var("KEYHOG_BACKEND") };

    if !gpu_ready {
        panic!(
            "KH-GAP-002: KEYHOG_BACKEND=gpu set but warm_backend(Gpu) returned false — \
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
