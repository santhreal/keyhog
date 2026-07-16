#![cfg(feature = "gpu")]

use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn canonical(matches: &[keyhog_core::RawMatch]) -> Vec<(usize, String)> {
    let mut rows: Vec<_> = matches
        .iter()
        .map(|finding| {
            (
                finding.location.offset,
                finding.credential.as_ref().to_string(),
            )
        })
        .collect();
    rows.sort_unstable();
    rows
}

#[test]
fn resident_gpu_readback_reuse_preserves_owned_results_and_parity() {
    let detector = DetectorSpec {
        id: "gpu-resident-output-ownership".into(),
        name: "GPU resident output ownership".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "KHRESIDENT_[A-Za-z0-9]{20}".into(),
            description: None,
            group: None,
            client_safe: false,
            weak_anchor: false,
        }],
        keywords: vec!["KHRESIDENT".into()],
        ..DetectorSpec::default()
    };
    let scanner = CompiledScanner::compile(vec![detector]).expect("compile resident scanner");
    let chunks = [
        Chunk {
            data: "first=KHRESIDENT_A1b2C3d4E5f6G7h8I9j0".into(),
            metadata: ChunkMetadata {
                path: Some("resident-first.txt".into()),
                ..ChunkMetadata::default()
            },
        },
        Chunk {
            data: "none here\nsecond=KHRESIDENT_Z9y8X7w6V5u4T3s2R1q0".into(),
            metadata: ChunkMetadata {
                path: Some("resident-second.txt".into()),
                ..ChunkMetadata::default()
            },
        },
    ];
    let reference: Vec<_> = scanner
        .scan_chunks_with_backend(&chunks, ScanBackend::CpuFallback)
        .iter()
        .map(|matches| canonical(matches))
        .collect();
    assert_eq!(reference.iter().map(Vec::len).sum::<usize>(), 2);

    let candidates = scanner.gpu_backend_candidates();
    let acquired: Vec<_> = candidates
        .into_iter()
        .filter(|candidate| candidate.acquired)
        .collect();
    assert!(
        !keyhog_scanner::hw_probe::probe_hardware().gpu_available || !acquired.is_empty(),
        "physical GPU probe succeeded but no resident peer was acquired"
    );

    for candidate in acquired {
        let first = scanner.scan_chunks_with_backend(&chunks, candidate.backend);
        let first_owned: Vec<_> = first.iter().map(|matches| canonical(matches)).collect();
        assert_eq!(
            first_owned,
            reference,
            "first {} scan",
            candidate.backend.label()
        );

        for reuse in 1..=8 {
            let next = scanner.scan_chunks_with_backend(&chunks, candidate.backend);
            let next_owned: Vec<_> = next.iter().map(|matches| canonical(matches)).collect();
            assert_eq!(
                next_owned,
                reference,
                "{} scan after reuse {reuse}",
                candidate.backend.label()
            );
            assert_eq!(
                first_owned, reference,
                "owned first result changed after reuse {reuse}"
            );
        }
    }
}
