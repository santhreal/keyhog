#![cfg(feature = "gpu")]

mod support;

use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use support::paths::detector_dir;

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

fn canonical_chunks(
    matches: &[Vec<keyhog_core::RawMatch>],
) -> Vec<(String, Option<usize>, usize, String)> {
    canonical(&matches.iter().flatten().cloned().collect::<Vec<_>>())
}

fn production_detectors(ids: &[&str]) -> Vec<DetectorSpec> {
    let mut detectors = keyhog_core::load_detectors(&detector_dir())
        .expect("load production detector TOMLs")
        .into_iter()
        .filter(|detector| ids.contains(&detector.id.as_str()))
        .collect::<Vec<_>>();
    detectors.sort_unstable_by(|left, right| left.id.cmp(&right.id));
    assert_eq!(
        detectors.len(),
        ids.len(),
        "every requested detector must load"
    );
    detectors
}

#[test]
fn every_available_gpu_peer_matches_the_cpu_reference() {
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
        if !status.available {
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
    let available: Vec<_> = candidates
        .into_iter()
        .filter(|candidate| candidate.available)
        .collect();
    assert!(
        !keyhog_scanner::hw_probe::probe_hardware().gpu_available || !available.is_empty(),
        "physical GPU probe succeeded but no compiled peer was available"
    );
    for candidate in available {
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
fn compilation_censuses_gpu_peers_without_materializing_execution_backends() {
    let detector = DetectorSpec {
        id: "gpu-lazy-peer".into(),
        name: "GPU lazy peer".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "KHGPULAZY_[A-Za-z0-9]{20}".into(),
            description: None,
            group: None,
            required_literals: Vec::new(),
            client_safe: false,
            weak_anchor: false,
        }],
        keywords: vec!["KHGPULAZY".into()],
        ..DetectorSpec::default()
    };
    let scanner = CompiledScanner::compile(vec![detector]).expect("compile lazy-peer scanner");
    let before = scanner.gpu_backend_candidates();
    let selected = before
        .iter()
        .find(|candidate| candidate.is_eligible())
        .expect("GPU release host must expose an eligible peer")
        .backend;
    assert!(
        before.iter().all(|candidate| !candidate.acquired),
        "scanner compilation must not materialize an execution peer: {before:?}"
    );

    assert!(
        scanner.warm_backend(selected),
        "selected peer must initialize"
    );
    let after = scanner.gpu_backend_candidates();
    assert!(
        after
            .iter()
            .find(|candidate| candidate.backend == selected)
            .is_some_and(|candidate| candidate.acquired),
        "warming the selected peer must publish its initialized state: {after:?}"
    );
    assert!(
        after
            .iter()
            .filter(|candidate| candidate.backend != selected)
            .all(|candidate| !candidate.acquired),
        "warming one route must not initialize an unused peer: {after:?}"
    );
}

#[test]
fn detector_required_literals_preserve_every_backend_finding() {
    let mut detectors = keyhog_core::load_detectors(&detector_dir())
        .expect("load production detector TOMLs")
        .into_iter()
        .filter(|detector| matches!(detector.id.as_str(), "deepl-api-key" | "url-credentials"))
        .collect::<Vec<_>>();
    detectors.sort_unstable_by(|left, right| left.id.cmp(&right.id));
    assert_eq!(
        detectors
            .iter()
            .map(|detector| detector.id.as_str())
            .collect::<Vec<_>>(),
        ["deepl-api-key", "url-credentials"],
        "the backend parity contract must execute both shipped TOML owners"
    );
    let scanner = CompiledScanner::compile(detectors).expect("compile required-literal scanner");
    let chunks = [
        Chunk {
            data: "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d:fx".into(),
            metadata: ChunkMetadata {
                path: Some("bare-deepl.txt".into()),
                ..ChunkMetadata::default()
            },
        },
        Chunk {
            data: "proxy=https://deploy:Qw9KmPq2@host.example/".into(),
            metadata: ChunkMetadata {
                path: Some("url-userinfo.txt".into()),
                ..ChunkMetadata::default()
            },
        },
        Chunk {
            data: "near misses: 7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d and https://username:password@repo.example.org".into(),
            metadata: ChunkMetadata {
                path: Some("negative-boundaries.txt".into()),
                ..ChunkMetadata::default()
            },
        },
    ];
    let reference =
        canonical_chunks(&scanner.scan_coalesced_with_backend(&chunks, ScanBackend::CpuFallback));
    assert_eq!(
        reference
            .iter()
            .map(|row| (row.0.as_str(), row.3.as_str()))
            .collect::<Vec<_>>(),
        [
            ("deepl-api-key", "7b3e5d8c-1a9f-4e2b-6c8d-3a5e9f1b7c4d:fx"),
            ("url-credentials", "Qw9KmPq2"),
        ]
    );

    let candidates = scanner.gpu_backend_candidates();
    for expected in [ScanBackend::GpuCuda, ScanBackend::GpuWgpu] {
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.backend == expected),
            "scanner omitted the compiled {} peer",
            expected.label()
        );
    }
    let acquired = candidates
        .into_iter()
        .filter(|candidate| candidate.available)
        .map(|candidate| candidate.backend)
        .collect::<Vec<_>>();
    assert!(
        !keyhog_scanner::hw_probe::probe_hardware().gpu_available || !acquired.is_empty(),
        "physical GPU probe succeeded but neither GPU peer was acquired"
    );
    let mut backends = vec![ScanBackend::SimdCpu];
    backends.extend(acquired);
    for backend in backends {
        let findings = scanner.scan_coalesced_with_backend(&chunks, backend);
        assert_eq!(
            canonical_chunks(&findings),
            reference,
            "{} diverged for detector-owned required literals",
            backend.label()
        );
    }
}

#[test]
fn service_scoped_api_headers_match_on_every_acquired_backend() {
    let ids = [
        "8x8-api-credentials",
        "moosend-api-key",
        "omnisend-api-key",
        "opensea-api-key",
        "passbase-api-key",
        "skyscanner-api-key",
        "x2y2-api-key",
    ];
    let scanner = CompiledScanner::compile(production_detectors(&ids))
        .expect("compile service-scoped API header detectors");
    let positives = [
        (
            "8x8-api-credentials",
            "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
            "https://api.8x8.com/stats\nX-Api-Key: Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        ),
        (
            "x2y2-api-key",
            "JSuKxKWNfd898GujYX9p66-_M1knu3xIPTZfsus5cByqlnilvi7",
            "X-API-KEY: JSuKxKWNfd898GujYX9p66-_M1knu3xIPTZfsus5cByqlnilvi7\nhttps://api.x2y2.org/orders",
        ),
        (
            "opensea-api-key",
            "2sIuLPADN-nQyiY2sVUsxowxpKZUoKKW",
            "https://api.opensea.io/api/v2/collections\nX-API-KEY: 2sIuLPADN-nQyiY2sVUsxowxpKZUoKKW",
        ),
        (
            "omnisend-api-key",
            "614030930ca9626eedd2b6b73c763ac9",
            "X-API-Key: 614030930ca9626eedd2b6b73c763ac9\nhttps://api.omnisend.com/v3/account",
        ),
        (
            "passbase-api-key",
            "7VVpvY_rJEc_G33gXrRw",
            "PASSBASE_API_KEY=7VVpvY_rJEc_G33gXrRw",
        ),
        (
            "skyscanner-api-key",
            "JEA8DfgFxzo9YbHh99eKuvHZUH62tIOeNPCQWBgg",
            "https://partners.api.skyscanner.net/apiservices/v3/cultures\nx-api-key: JEA8DfgFxzo9YbHh99eKuvHZUH62tIOeNPCQWBgg",
        ),
        (
            "moosend-api-key",
            "a4f4f-7a6c28--633f18a1a2b0ff571464fc",
            "X-Api-Key: a4f4f-7a6c28--633f18a1a2b0ff571464fc\nhttps://api.moosend.com/v3/subscribers.json",
        ),
    ];
    let positive_chunks = positives
        .iter()
        .enumerate()
        .map(|(index, (_, _, text))| Chunk {
            data: (*text).into(),
            metadata: ChunkMetadata {
                path: Some(format!("positive-{index}.txt").into()),
                ..ChunkMetadata::default()
            },
        })
        .collect::<Vec<_>>();
    let negative_chunks = positives
        .iter()
        .enumerate()
        .filter_map(|(index, (detector, credential, _))| {
            (*detector != "passbase-api-key").then(|| Chunk {
                data: format!("X-API-KEY: {credential}").into(),
                metadata: ChunkMetadata {
                    path: Some(format!("negative-{index}.txt").into()),
                    ..ChunkMetadata::default()
                },
            })
        })
        .chain(std::iter::once(Chunk {
            data: "X-API-KEY: 7VVpvY_rJEc_G33gXrRw".into(),
            metadata: ChunkMetadata {
                path: Some("negative-passbase.txt".into()),
                ..ChunkMetadata::default()
            },
        }))
        .collect::<Vec<_>>();

    let reference = canonical_chunks(
        &scanner.scan_coalesced_with_backend(&positive_chunks, ScanBackend::CpuFallback),
    );
    assert_eq!(
        reference.len(),
        positives.len(),
        "one exact finding per positive"
    );
    for (detector, credential, _) in positives {
        assert!(
            reference
                .iter()
                .any(|row| row.0 == detector && row.3 == credential),
            "CPU oracle missed {detector}/{credential}: {reference:?}"
        );
    }
    assert!(
        canonical_chunks(
            &scanner.scan_coalesced_with_backend(&negative_chunks, ScanBackend::CpuFallback)
        )
        .is_empty(),
        "bare generic API headers must not be assigned to a service"
    );

    let mut backends = vec![ScanBackend::SimdCpu];
    backends.extend(
        scanner
            .gpu_backend_candidates()
            .into_iter()
            .filter(|candidate| candidate.available)
            .map(|candidate| candidate.backend),
    );
    for backend in backends {
        assert_eq!(
            canonical_chunks(&scanner.scan_coalesced_with_backend(&positive_chunks, backend)),
            reference,
            "{} diverged on service-scoped positives",
            backend.label()
        );
        assert!(
            canonical_chunks(&scanner.scan_coalesced_with_backend(&negative_chunks, backend))
                .is_empty(),
            "{} assigned a bare generic header",
            backend.label()
        );
        eprintln!(
            "service-scoped API header parity passed on {}",
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
