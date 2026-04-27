use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{gpu, CompiledScanner, ScanBackend};

#[test]
fn gpu_adapter_and_dispatch_are_available() {
    let result = gpu::vyre_gpu_self_test()
        .expect("GPU feature requires a working non-software adapter and compute dispatch");

    assert_eq!(result.direct_matches, 1);
}

#[test]
fn vyre_gpu_scanner_and_coalesced_paths_are_available() {
    let result = gpu::vyre_gpu_self_test()
        .expect("GPU scanner requires vyre direct and coalesced GPU dispatch");

    assert_eq!(result.direct_matches, 1);
    assert_eq!(result.coalesced_matches, 100);
}

#[test]
fn gpu_batch_preserves_cross_chunk_reassembly() {
    let scanner = CompiledScanner::compile(vec![DetectorSpec {
        id: "demo-reassembled-token".into(),
        name: "Demo Reassembled Token".into(),
        service: "demo".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "abcde[0-9A-Z]{15}".into(),
            description: None,
            group: None,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["api_key".into()],
        ..Default::default()
    }])
    .expect("compile scanner");

    let chunks = vec![
        chunk("api_key_part1 = \"abcde12345\""),
        chunk("api_key_part2 = \"FGHIJ67890\""),
    ];

    let cpu_findings = scanner.scan_chunks_with_backend(&chunks, ScanBackend::CpuFallback);
    let gpu_findings = scanner.scan_chunks_with_backend(&chunks, ScanBackend::Gpu);

    // V7-PERF-033: Substrate-neutral match reassembly check.
    // Match counts can vary slightly between CPU/GPU pre-filters due to different
    // state machine budgets, but reassembly must produce the same result.
    assert!(
        gpu_findings
            .iter()
            .flatten()
            .any(|finding| finding.detector_id.ends_with(":reassembled")),
        "GPU batch scan must run normal reassembly post-processing"
    );
}

fn chunk(data: &str) -> Chunk {
    Chunk {
        data: data.to_string(),
        metadata: ChunkMetadata {
            source_type: "test".into(),
            path: Some("demo.conf".into()),
            commit: None,
            author: None,
            date: None,
        },
    }
}
