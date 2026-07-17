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
            required_literals: Vec::new(),
            client_safe: false,
            weak_anchor: false,
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
fn detector_required_literals_preserve_every_backend_finding() {
    let detectors = vec![
        DetectorSpec {
            id: "required-infix-fx".into(),
            name: "Required infix fx".into(),
            service: "test".into(),
            severity: Severity::High,
            patterns: vec![PatternSpec {
                regex: r"([a-f0-9]{8}:fx)".into(),
                group: Some(1),
                required_literals: vec![":fx".into()],
                ..PatternSpec::default()
            }],
            ..DetectorSpec::default()
        },
        DetectorSpec {
            id: "required-infix-url".into(),
            name: "Required infix URL".into(),
            service: "test".into(),
            severity: Severity::High,
            patterns: vec![PatternSpec {
                regex: r"(?i)[a-z][a-z0-9+.-]*://[^/@\s:]*:([^/@\s<>]{6,128})@[a-z0-9._-]".into(),
                group: Some(1),
                required_literals: vec!["://".into()],
                ..PatternSpec::default()
            }],
            ..DetectorSpec::default()
        },
    ];
    let scanner = CompiledScanner::compile(detectors).expect("compile required-literal scanner");
    let chunks = [Chunk {
        data: "deepl=0123abcd:fx\nproxy=https://deploy:Qw9KmPq2@host.example/".into(),
        metadata: ChunkMetadata {
            path: Some("required-literals.txt".into()),
            ..ChunkMetadata::default()
        },
    }];
    let reference =
        canonical(&scanner.scan_coalesced_with_backend(&chunks, ScanBackend::CpuFallback)[0]);
    assert_eq!(
        reference
            .iter()
            .map(|row| (row.0.as_str(), row.3.as_str()))
            .collect::<Vec<_>>(),
        [
            ("required-infix-fx", "0123abcd:fx"),
            ("required-infix-url", "Qw9KmPq2"),
        ]
    );

    let mut backends = vec![ScanBackend::SimdCpu];
    backends.extend(
        scanner
            .gpu_backend_candidates()
            .into_iter()
            .filter(|candidate| candidate.acquired)
            .map(|candidate| candidate.backend),
    );
    for backend in backends {
        let findings = scanner.scan_coalesced_with_backend(&chunks, backend);
        assert_eq!(
            canonical(&findings[0]),
            reference,
            "{} diverged for detector-owned required literals",
            backend.label()
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
