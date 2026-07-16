use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{CompiledScanner, ScanBackend, ScannerConfig};

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
            weak_anchor: false,
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

    let planned = vec![
        chunk("~".repeat(BYTES)),
        chunk("g".repeat(BYTES)),
        chunk("gh ".repeat(BYTES / 3)),
    ];
    let plan = scanner.phase1_admission_plan(&planned);
    assert_eq!(
        canonical(&scanner.scan_coalesced_with_backend_and_admission(
            &planned,
            ScanBackend::CpuFallback,
            Some(&plan),
        )),
        canonical(&scanner.scan_coalesced_with_backend(&planned, ScanBackend::CpuFallback)),
        "reusing the route admission plan must preserve scalar findings"
    );
}

#[test]
fn phase1_summary_parallel_fold_preserves_admission_totals() {
    const BYTES: usize = 16 * 1024;
    let scanner = scanner();
    let batch = vec![
        chunk("~".repeat(BYTES)),
        chunk("g".repeat(BYTES)),
        chunk("gh ".repeat(BYTES / 3)),
        chunk("gh ".repeat(BYTES / 3)),
    ];

    let summary = scanner.phase1_admission_summary(&batch);
    assert_eq!(summary.alphabet_rejected_chunks, 1);
    assert_eq!(summary.bigram_rejected_chunks, 1);
    assert_eq!(summary.admitted_chunks, 2);
    assert_eq!(
        summary.alphabet_rejected_bytes + summary.bigram_rejected_bytes + summary.admitted_bytes,
        batch
            .iter()
            .map(|chunk| chunk.data.len() as u64)
            .sum::<u64>()
    );
}

#[test]
fn phase1_admission_classes_preserve_backend_findings_at_eight_mib() {
    const BYTES: usize = 8 * 1024 * 1024;
    const WGPU_GRID_BYTES: usize = 8_388_480;
    const SEAM_CREDENTIAL: &str = "ghp_A1b2C3d4";
    const TAIL_CREDENTIAL: &str = "ghp_Z9y8X7w6";
    let scanner = scanner();
    let mut admitted = repeated_to_len("gh ", BYTES);
    let seam_start = WGPU_GRID_BYTES - 2;
    admitted.replace_range(
        seam_start..seam_start + SEAM_CREDENTIAL.len(),
        SEAM_CREDENTIAL,
    );
    admitted.replace_range(
        seam_start + SEAM_CREDENTIAL.len()..seam_start + SEAM_CREDENTIAL.len() + 1,
        "!",
    );
    admitted.replace_range(BYTES - TAIL_CREDENTIAL.len().., TAIL_CREDENTIAL);
    let batch = vec![
        chunk("~".repeat(BYTES)),
        chunk("g".repeat(BYTES)),
        chunk(admitted),
    ];

    let reference =
        canonical(&scanner.scan_coalesced_with_backend(&batch, ScanBackend::CpuFallback));
    assert_eq!(
        reference,
        vec![
            (
                2,
                "phase1-admission-token".to_string(),
                seam_start,
                SEAM_CREDENTIAL.to_string(),
            ),
            (
                2,
                "phase1-admission-token".to_string(),
                BYTES - TAIL_CREDENTIAL.len(),
                TAIL_CREDENTIAL.to_string(),
            ),
        ],
        "the fixture must prove exact seam and tail findings after two rejected phase-one classes"
    );
    assert_eq!(
        canonical(&scanner.scan_coalesced_with_backend(&batch, ScanBackend::SimdCpu)),
        reference,
        "Hyperscan/SIMD must preserve scalar findings across phase-one admission classes"
    );
    let direct_reference =
        canonical(&[scanner.scan_with_backend(&batch[2], ScanBackend::CpuFallback)]);

    #[cfg(feature = "gpu")]
    {
        let candidates = scanner.gpu_backend_candidates();
        let hardware = keyhog_scanner::hw_probe::probe_hardware();
        let wgpu_acquired = candidates
            .iter()
            .find(|candidate| candidate.backend == ScanBackend::GpuWgpu)
            .is_some_and(|candidate| candidate.acquired);
        assert!(
            !hardware.gpu_available || wgpu_acquired,
            "a physical GPU was detected but the WGPU peer needed to prove the 8 MiB dispatch seam was not acquired: {candidates:?}"
        );
        let acquired = candidates
            .iter()
            .filter(|candidate| candidate.acquired)
            .collect::<Vec<_>>();
        assert!(
            !hardware.gpu_available || !acquired.is_empty(),
            "a physical GPU was detected but neither compiled GPU peer was acquired: {candidates:?}"
        );
        for candidate in acquired {
            assert_eq!(
                canonical(&scanner.scan_coalesced_with_backend(&batch, candidate.backend)),
                reference,
                "{} must preserve scalar findings across phase-one admission classes",
                candidate.backend.label()
            );
            assert_eq!(
                canonical(&[scanner.scan_with_backend(&batch[2], candidate.backend)]),
                direct_reference,
                "{} per-chunk API must preserve seam and tail findings",
                candidate.backend.label()
            );
        }
    }
}

#[test]
fn oversized_window_reduction_preserves_mixed_logical_rows() {
    const BYTES: usize = 8 * 1024 * 1024;
    const WGPU_GRID_BYTES: usize = 8_388_480;
    const SEAM_CREDENTIAL: &str = "ghp_M3n4B5v6";
    let scanner = scanner();
    let mut oversized = repeated_to_len("gh ", BYTES);
    let seam_start = WGPU_GRID_BYTES - 2;
    oversized.replace_range(
        seam_start..seam_start + SEAM_CREDENTIAL.len(),
        SEAM_CREDENTIAL,
    );
    oversized.replace_range(
        seam_start + SEAM_CREDENTIAL.len()..seam_start + SEAM_CREDENTIAL.len() + 1,
        "!",
    );
    let batch = vec![
        chunk("ghp_A1b2C3d4!".into()),
        chunk(oversized),
        chunk("ghp_Z9y8X7w6!".into()),
    ];
    let reference =
        canonical(&scanner.scan_coalesced_with_backend(&batch, ScanBackend::CpuFallback));
    assert_eq!(
        reference.len(),
        3,
        "fixture must produce one finding per logical row"
    );
    assert_eq!(
        reference.iter().map(|row| row.0).collect::<Vec<_>>(),
        [0, 1, 2]
    );
    assert_eq!(reference[1].2, seam_start);
    assert_eq!(
        canonical(&scanner.scan_coalesced_with_backend(&batch, ScanBackend::SimdCpu)),
        reference
    );

    #[cfg(feature = "gpu")]
    for candidate in scanner
        .gpu_backend_candidates()
        .into_iter()
        .filter(|candidate| candidate.acquired)
    {
        assert_eq!(
            canonical(&scanner.scan_coalesced_with_backend(&batch, candidate.backend)),
            reference,
            "{} changed logical row order or findings",
            candidate.backend.label()
        );
    }
}

#[test]
fn oversized_prefixless_phase2_row_keeps_cpu_admission_authoritative() {
    const BYTES: usize = 8 * 1024 * 1024;
    const TOKEN: &str = "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn";
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    let scanner = scanner().with_config(config);
    let mut data = "x".repeat(BYTES);
    let assignment = format!("secretKey=\"{TOKEN}\"\n");
    data.replace_range(BYTES - assignment.len().., &assignment);
    assert!(
        scanner
            .collect_triggered_patterns_cpu(&data)
            .iter()
            .all(|&word| word == 0),
        "fixture must enter the prefixless phase-two no-hit lane"
    );
    let batch = vec![chunk(data)];
    let reference =
        canonical(&scanner.scan_coalesced_with_backend(&batch, ScanBackend::CpuFallback));
    assert!(
        reference.iter().any(|row| row.3 == TOKEN),
        "CPU no-hit admission must find the tail token: {reference:?}"
    );

    #[cfg(feature = "gpu")]
    for candidate in scanner
        .gpu_backend_candidates()
        .into_iter()
        .filter(|candidate| candidate.acquired)
    {
        assert_eq!(
            canonical(&scanner.scan_coalesced_with_backend(&batch, candidate.backend)),
            reference,
            "{} lost the oversized prefixless phase-two row",
            candidate.backend.label()
        );
    }
}
