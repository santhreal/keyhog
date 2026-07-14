#![cfg(feature = "gpu")]

use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn canonical(matches: &[keyhog_core::RawMatch]) -> Vec<(String, Option<usize>, usize, String)> {
    let mut rows: Vec<_> = matches
        .iter()
        .map(|finding| {
            (
                finding.detector_id.to_string(),
                finding.location.line,
                finding.location.offset,
                finding.credential.as_ref().to_string(),
            )
        })
        .collect();
    rows.sort_unstable();
    rows
}

#[test]
fn every_acquired_gpu_peer_matches_the_cpu_reference() {
    let detector = DetectorSpec {
        id: "gpu-peer-parity".into(),
        name: "GPU peer parity".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "KHGPUPEER_[A-Za-z0-9]{20}".into(),
            description: None,
            group: None,
            client_safe: false,
        }],
        keywords: vec!["KHGPUPEER".into()],
        ..DetectorSpec::default()
    };
    let scanner = CompiledScanner::compile(vec![detector]).expect("compile parity scanner");
    let chunk = Chunk {
        data: "first=KHGPUPEER_A1b2C3d4E5f6G7h8I9j0\nsecond=KHGPUPEER_Z9y8X7w6V5u4T3s2R1q0".into(),
        metadata: ChunkMetadata {
            path: Some("gpu-peer.txt".into()),
            ..ChunkMetadata::default()
        },
    };
    let reference = canonical(
        &scanner.scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
            [0],
    );
    assert_eq!(
        reference.len(),
        2,
        "parity fixture must produce two findings"
    );

    let candidates = scanner.gpu_backend_candidates();
    for expected in [ScanBackend::GpuCuda, ScanBackend::GpuWgpu] {
        let status = candidates
            .iter()
            .find(|candidate| candidate.backend == expected)
            .expect("scanner must report every compiled GPU peer");
        if !status.acquired {
            assert!(
                status
                    .acquisition_error
                    .as_deref()
                    .is_some_and(|error| !error.is_empty()),
                "{} acquisition failure must include a diagnostic",
                expected.label()
            );
        }
    }
    let acquired: Vec<_> = candidates
        .into_iter()
        .filter(|candidate| candidate.acquired)
        .collect();
    assert!(
        !keyhog_scanner::hw_probe::probe_hardware().gpu_available || !acquired.is_empty(),
        "physical GPU probe succeeded but no compiled peer was acquired"
    );
    for candidate in acquired {
        assert!(candidate.backend.is_gpu());
        let findings =
            scanner.scan_chunks_with_backend(std::slice::from_ref(&chunk), candidate.backend);
        assert_eq!(
            canonical(&findings[0]),
            reference,
            "{} findings diverged from CPU",
            candidate.backend.label()
        );
    }
}

#[test]
fn production_self_test_reports_each_acquired_peer_identity() {
    match keyhog_scanner::gpu::gpu_region_presence_self_test() {
        Ok(report) => {
            assert!(!report.peers.is_empty());
            for peer in &report.peers {
                assert!(peer.backend.is_gpu());
                assert!(!peer.backend_id.is_empty());
                assert_eq!(peer.matches, 1);
            }
        }
        Err(error) => {
            assert!(
                !keyhog_scanner::hw_probe::probe_hardware().gpu_available,
                "physical GPU host cannot pass by treating every peer as absent: {error}"
            );
            assert!(error.acquired_backends.is_empty());
            assert!(error
                .message
                .contains("no GPU region-presence peer was acquired"));
        }
    }
}
