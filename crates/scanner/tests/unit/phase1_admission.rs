use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{CompiledScanner, ScanBackend, ScannerConfig};

fn try_scanner_for_backend(backend: ScanBackend) -> keyhog_scanner::Result<CompiledScanner> {
    CompiledScanner::compile_for_backend(
        vec![DetectorSpec {
            tests: Vec::new(),
            id: "phase1-admission-token".into(),
            name: "Phase 1 admission token".into(),
            service: "unit".into(),
            severity: Severity::High,
            patterns: vec![PatternSpec {
                regex: r"ghp_[A-Za-z0-9]{8}".into(),
                description: None,
                group: None,
                required_literals: Vec::new(),
                client_safe: false,
                weak_anchor: false,
                structural_password_slot: false,
            }],
            keywords: vec!["ghp_".into()],
            min_confidence: Some(0.0),
            match_confidence: keyhog_core::detector_spec_by_id("github-classic-pat")
                .and_then(|detector| detector.match_confidence),
            ..Default::default()
        }],
        backend,
    )
}

fn scanner_for_backend(backend: ScanBackend) -> CompiledScanner {
    try_scanner_for_backend(backend).expect("phase-1 admission scanner compiles")
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

fn canonical_result(
    findings: keyhog_scanner::Result<Vec<Vec<keyhog_core::RawMatch>>>,
) -> Vec<(usize, String, usize, String)> {
    canonical(&findings.expect("phase-one admission scan succeeds"))
}

#[test]
fn phase1_summary_distinguishes_equal_size_admission_classes() {
    const BYTES: usize = 192;
    let scanner = scanner_for_backend(ScanBackend::CpuFallback);
    let alphabet_rejected = chunk("~".repeat(BYTES));
    let bigram_rejected = chunk("g".repeat(BYTES));
    let admitted = chunk("ghp_".repeat(BYTES / 4));
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
        chunk("ghp_".repeat(BYTES / 4)),
    ];
    let plan = scanner.phase1_admission_plan(&planned);
    assert_eq!(
        canonical_result(scanner.scan_coalesced_with_backend_and_admission(
            &planned,
            ScanBackend::CpuFallback,
            Some(&plan),
        )),
        canonical_result(scanner.scan_coalesced_with_backend(&planned, ScanBackend::CpuFallback),),
        "reusing the route admission plan must preserve scalar findings"
    );
}

#[test]
fn phase1_summary_parallel_fold_preserves_admission_totals() {
    const BYTES: usize = 16 * 1024;
    let scanner = scanner_for_backend(ScanBackend::CpuFallback);
    let batch = vec![
        chunk("~".repeat(BYTES)),
        chunk("g".repeat(BYTES)),
        chunk("ghp_".repeat(BYTES / 4)),
        chunk("ghp_".repeat(BYTES / 4)),
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

/// Proves every acquired backend preserves seam and tail findings for all
/// phase-one admission classes without concurrent adapter interference.
#[test]
fn phase1_admission_classes_preserve_backend_findings_at_eight_mib() {
    let _gpu_test_guard = crate::testing::gpu_test_lock();
    const BYTES: usize = 8 * 1024 * 1024;
    const WGPU_GRID_BYTES: usize = 8_388_480;
    const SEAM_CREDENTIAL: &str = "ghp_A1b2C3d4";
    const TAIL_CREDENTIAL: &str = "ghp_Z9y8X7w6";
    let scanner = scanner_for_backend(ScanBackend::CpuFallback);
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
        canonical_result(scanner.scan_coalesced_with_backend(&batch, ScanBackend::CpuFallback));
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
    let simd_scanner = scanner_for_backend(ScanBackend::SimdCpu);
    assert_eq!(
        canonical_result(simd_scanner.scan_coalesced_with_backend(&batch, ScanBackend::SimdCpu)),
        reference,
        "Hyperscan/SIMD must preserve scalar findings across phase-one admission classes"
    );
    #[cfg(feature = "gpu")]
    {
        let direct_reference = canonical(&[scanner
            .scan_with_backend(&batch[2], ScanBackend::CpuFallback)
            .expect("selected backend scan succeeds")]);
        let gpu_scanners: Vec<_> = [
            ScanBackend::GpuCuda,
            ScanBackend::GpuMetal,
            ScanBackend::GpuWgpu,
        ]
        .into_iter()
        .filter_map(|backend| {
            let scanner = try_scanner_for_backend(backend).ok()?;
            scanner
                .gpu_backend_candidates()
                .iter()
                .any(|candidate| candidate.backend == backend && candidate.available)
                .then_some((backend, scanner))
        })
        .collect();
        let acquired_backends = gpu_scanners
            .iter()
            .map(|(backend, _)| *backend)
            .collect::<Vec<_>>();
        let hardware = keyhog_scanner::hw_probe::probe_hardware();
        assert!(
            !hardware.gpu_available || acquired_backends.contains(&ScanBackend::GpuWgpu),
            "a physical GPU was detected but the exact WGPU peer needed to prove the 8 MiB dispatch seam was not acquired: {acquired_backends:?}"
        );
        assert!(
            !hardware.gpu_available || !gpu_scanners.is_empty(),
            "a physical GPU was detected but no exact GPU peer was acquired"
        );
        for (backend, gpu_scanner) in gpu_scanners {
            assert_eq!(
                canonical_result(gpu_scanner.scan_coalesced_with_backend(&batch, backend)),
                reference,
                "{} must preserve scalar findings across phase-one admission classes",
                backend.label()
            );
            assert_eq!(
                canonical(&[gpu_scanner
                    .scan_with_backend(&batch[2], backend)
                    .expect("selected GPU per-chunk scan succeeds")]),
                direct_reference,
                "{} per-chunk API must preserve seam and tail findings",
                backend.label()
            );
        }
    }
}

/// Proves oversized mixed rows retain their logical order and exact findings
/// on every acquired backend while GPU fixtures are serialized.
#[test]
fn oversized_window_reduction_preserves_mixed_logical_rows() {
    let _gpu_test_guard = crate::testing::gpu_test_lock();
    const BYTES: usize = 8 * 1024 * 1024;
    const WGPU_GRID_BYTES: usize = 8_388_480;
    const SEAM_CREDENTIAL: &str = "ghp_M3n4B5v6";
    let scanner = scanner_for_backend(ScanBackend::CpuFallback);
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
        canonical_result(scanner.scan_coalesced_with_backend(&batch, ScanBackend::CpuFallback));
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
    let simd_scanner = scanner_for_backend(ScanBackend::SimdCpu);
    assert_eq!(
        canonical_result(simd_scanner.scan_coalesced_with_backend(&batch, ScanBackend::SimdCpu)),
        reference
    );

    #[cfg(feature = "gpu")]
    for (backend, gpu_scanner) in [
        ScanBackend::GpuCuda,
        ScanBackend::GpuMetal,
        ScanBackend::GpuWgpu,
    ]
    .into_iter()
    .filter_map(|backend| {
        let scanner = try_scanner_for_backend(backend).ok()?;
        scanner
            .gpu_backend_candidates()
            .iter()
            .any(|candidate| candidate.backend == backend && candidate.available)
            .then_some((backend, scanner))
    }) {
        assert_eq!(
            canonical_result(gpu_scanner.scan_coalesced_with_backend(&batch, backend)),
            reference,
            "{} changed logical row order or findings",
            backend.label()
        );
    }
}

/// Proves prefixless phase-two admission remains CPU-authoritative and exact
/// across acquired GPU peers without shared-adapter test races.
#[test]
fn oversized_prefixless_phase2_row_keeps_cpu_admission_authoritative() {
    let _gpu_test_guard = crate::testing::gpu_test_lock();
    const BYTES: usize = 8 * 1024 * 1024;
    const TOKEN: &str = "Kp4Qx7Rm2Sn5Tb8Vw3YzH6Lc9Df1Gj4N";
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    let mut generic = keyhog_core::detector_spec_by_id("generic-secret")
        .expect("embedded generic assignment detector")
        .clone();
    // Isolate phase-two admission from the separate confidence-scoring route.
    generic.ml.match_mode = keyhog_core::DetectorMlMode::Disabled;
    let scanner =
        CompiledScanner::compile_for_backend(vec![generic.clone()], ScanBackend::CpuFallback)
            .expect("compile detector-owned generic scalar plan")
            .with_config(config.clone());
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
        canonical_result(scanner.scan_coalesced_with_backend(&batch, ScanBackend::CpuFallback));
    assert!(
        reference.iter().any(|row| row.3 == TOKEN),
        "CPU no-hit admission must find the tail token: {reference:?}"
    );

    #[cfg(feature = "gpu")]
    for (backend, gpu_scanner) in [
        ScanBackend::GpuCuda,
        ScanBackend::GpuMetal,
        ScanBackend::GpuWgpu,
    ]
    .into_iter()
    .filter_map(|backend| {
        let scanner = CompiledScanner::compile_for_backend(vec![generic.clone()], backend).ok()?;
        let scanner = scanner.with_config(config.clone());
        scanner
            .gpu_backend_candidates()
            .iter()
            .any(|candidate| candidate.backend == backend && candidate.available)
            .then_some((backend, scanner))
    }) {
        assert_eq!(
            canonical_result(gpu_scanner.scan_coalesced_with_backend(&batch, backend)),
            reference,
            "{} lost the oversized prefixless phase-two row",
            backend.label()
        );
    }
}
