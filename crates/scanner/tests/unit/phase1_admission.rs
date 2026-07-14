use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn scanner() -> CompiledScanner {
    CompiledScanner::compile(vec![DetectorSpec {
        tests: Vec::new(),
        id: "phase1-admission-token".into(),
        name: "Phase 1 admission token".into(),
        service: "unit".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: r"ghp_[A-Za-z0-9]{8}".into(),
            description: None,
            group: None,
            client_safe: false,
        }],
        keywords: vec!["ghp_".into()],
        min_confidence: Some(0.0),
        ..Default::default()
    }])
    .expect("phase-1 admission scanner compiles")
}

fn chunk(data: String) -> Chunk {
    Chunk {
        data: data.into(),
        metadata: ChunkMetadata::default(),
    }
}

fn repeated_to_len(seed: &str, len: usize) -> String {
    let mut value = seed.repeat(len.div_ceil(seed.len()));
    value.truncate(len);
    value
}

fn canonical(findings: &[Vec<keyhog_core::RawMatch>]) -> Vec<(usize, String, usize, String)> {
    let mut rows = findings
        .iter()
        .enumerate()
        .flat_map(|(chunk_index, chunk_findings)| {
            chunk_findings.iter().map(move |finding| {
                (
                    chunk_index,
                    finding.detector_id.to_string(),
                    finding.location.offset,
                    finding.credential.as_ref().to_string(),
                )
            })
        })
        .collect::<Vec<_>>();
    rows.sort_unstable();
    rows
}

#[test]
fn phase1_summary_distinguishes_equal_size_admission_classes() {
    const BYTES: usize = 192;
    let scanner = scanner();
    let alphabet_rejected = chunk("~".repeat(BYTES));
    let bigram_rejected = chunk("g".repeat(BYTES));
    let admitted = chunk("gh ".repeat(BYTES / 3));
    let batch = vec![
        alphabet_rejected.clone(),
        bigram_rejected.clone(),
        admitted.clone(),
    ];

    let summary = scanner.phase1_admission_summary(&batch);
    assert_eq!(summary.alphabet_rejected_chunks, 1);
    assert_eq!(summary.alphabet_rejected_bytes, BYTES as u64);
    assert_eq!(summary.bigram_rejected_chunks, 1);
    assert_eq!(summary.bigram_rejected_bytes, BYTES as u64);
    assert_eq!(summary.admitted_chunks, 1);
    assert_eq!(summary.admitted_bytes, BYTES as u64);
    assert_eq!(
        summary.alphabet_rejected_bytes + summary.bigram_rejected_bytes + summary.admitted_bytes,
        batch
            .iter()
            .map(|chunk| chunk.data.len() as u64)
            .sum::<u64>()
    );

    let reversed =
        scanner.phase1_admission_summary(&[admitted, bigram_rejected, alphabet_rejected]);
    assert_eq!(reversed, summary, "summary must not depend on chunk order");
}

#[test]
fn phase1_admission_classes_preserve_backend_findings_at_eight_mib() {
    const BYTES: usize = 8 * 1024 * 1024;
    const REGION_BYTES: usize = BYTES / 2;
    const CREDENTIAL: &str = "ghp_A1b2C3d4";
    let scanner = scanner();
    let mut admitted_tail = repeated_to_len("gh ", REGION_BYTES);
    admitted_tail.replace_range(REGION_BYTES - CREDENTIAL.len().., CREDENTIAL);
    // Two source regions per class preserve each exact 8 MiB workload while
    // keeping every portable WGPU dispatch below its one-dimensional grid cap.
    let batch = vec![
        chunk("~".repeat(REGION_BYTES)),
        chunk("~".repeat(REGION_BYTES)),
        chunk("g".repeat(REGION_BYTES)),
        chunk("g".repeat(REGION_BYTES)),
        chunk(repeated_to_len("gh ", REGION_BYTES)),
        chunk(admitted_tail),
    ];

    let reference =
        canonical(&scanner.scan_coalesced_with_backend(&batch, ScanBackend::CpuFallback));
    assert_eq!(
        reference,
        vec![(
            5,
            "phase1-admission-token".to_string(),
            REGION_BYTES - CREDENTIAL.len(),
            CREDENTIAL.to_string(),
        )],
        "the fixture must prove one exact finding after two rejected phase-one classes"
    );
    assert_eq!(
        canonical(&scanner.scan_coalesced_with_backend(&batch, ScanBackend::SimdCpu)),
        reference,
        "Hyperscan/SIMD must preserve scalar findings across phase-one admission classes"
    );

    #[cfg(feature = "gpu")]
    {
        let candidates = scanner.gpu_backend_candidates();
        let acquired = candidates
            .iter()
            .filter(|candidate| candidate.acquired)
            .collect::<Vec<_>>();
        assert!(
            !keyhog_scanner::hw_probe::probe_hardware().gpu_available || !acquired.is_empty(),
            "a physical GPU was detected but neither compiled GPU peer was acquired: {candidates:?}"
        );
        for candidate in acquired {
            assert_eq!(
                canonical(&scanner.scan_coalesced_with_backend(&batch, candidate.backend)),
                reference,
                "{} must preserve scalar findings across phase-one admission classes",
                candidate.backend.label()
            );
        }
    }
}
