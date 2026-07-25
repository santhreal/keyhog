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
    }])
    .expect("phase-1 admission scanner compiles")
}

fn chunk(data: String) -> Chunk {
    Chunk {
        data: data.into(),
        metadata: ChunkMetadata::default(),
    }
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

/// Regression for KH-1289/KH-1409: a plan for a different allocation must
/// produce one exact recovery receipt while retaining the safe rescan finding.
#[test]
fn mismatched_plan_returns_exact_recovery_receipt_and_preserves_findings() {
    const TOKEN: &str = "ghp_A1b2C3d4";
    let scanner = scanner();
    let planned = vec![chunk(format!("{TOKEN}!"))];
    let plan = scanner.phase1_admission_plan(&planned);
    let live = vec![chunk(format!("{TOKEN}!"))];

    let outcome = scanner.scan_coalesced_with_backend_admission_route_and_recovery(&live,
    ScanBackend::CpuFallback,
    Some(&plan),
    scanner.execution_route_for_backend(ScanBackend::CpuFallback),
    false,)
        .expect("mismatched plan recovers through exact admission");

    assert_eq!(
        canonical(&outcome.matches),
        vec![(
            0,
            "phase1-admission-token".to_string(),
            0,
            TOKEN.to_string(),
        )],
        "discarding the untrusted plan must not discard its safe finding"
    );
    let receipt = outcome
        .recovery
        .expect("identity mismatch must be returned as a recovery receipt");
    assert!(receipt.is_phase1_admission_recovery());
    assert_eq!(receipt.failed_backend, ScanBackend::CpuFallback);
    assert_eq!(receipt.recovery_backend, ScanBackend::CpuFallback);
    assert_eq!(receipt.ranges.len(), 1);
    assert_eq!(receipt.ranges[0].chunk_index, 0);
    assert_eq!(receipt.ranges[0].byte_start, 0);
    assert_eq!(receipt.ranges[0].byte_end, live[0].data.len());
    assert_eq!(receipt.recovered_chunks(), 1);
    assert_eq!(receipt.recovered_bytes(), live[0].data.len() as u64);
    assert_eq!(
        receipt.reason,
        "phase-one admission plan identity mismatch; discarded the untrusted plan and recomputed exact admission"
    );
}

/// Regression for KH-1409: matching plan identity must remain the allocation-
/// free fast path and must not falsely mark a successful scan as recovered.
#[test]
fn matching_plan_has_no_recovery_receipt() {
    const TOKEN: &str = "ghp_Z9y8X7w6";
    let scanner = scanner();
    let live = vec![chunk(format!("{TOKEN}!"))];
    let plan = scanner.phase1_admission_plan(&live);

    let outcome = scanner.scan_coalesced_with_backend_admission_route_and_recovery(&live,
    ScanBackend::CpuFallback,
    Some(&plan),
    scanner.execution_route_for_backend(ScanBackend::CpuFallback),
    false,)
        .expect("matching admission identity scans normally");

    assert!(outcome.recovery.is_none());
    assert_eq!(
        canonical(&outcome.matches),
        vec![(
            0,
            "phase1-admission-token".to_string(),
            0,
            TOKEN.to_string(),
        )]
    );
}

/// Regression for KH-1409: reusing the same wrong plan on separate requests
/// must return one complete receipt per request rather than warn only once.
#[test]
fn repeated_mismatch_returns_repeated_complete_receipts() {
    let scanner = scanner();
    let planned = vec![chunk("ghp_A1b2C3d4!".into())];
    let plan = scanner.phase1_admission_plan(&planned);
    let live = vec![chunk("ghp_M3n4B5v6!".into())];

    for attempt in 0..2 {
        let outcome = scanner.scan_coalesced_with_backend_admission_route_and_recovery(&live,
        ScanBackend::CpuFallback,
        Some(&plan),
        scanner.execution_route_for_backend(ScanBackend::CpuFallback),
        false,)
            .expect("every mismatched request recovers");
        assert_eq!(
            canonical(&outcome.matches)[0].3,
            "ghp_M3n4B5v6",
            "attempt {attempt} lost the exact safe finding"
        );
        let receipt = outcome
            .recovery
            .expect("every mismatch needs its own counted receipt");
        assert!(receipt.is_phase1_admission_recovery());
        assert_eq!(receipt.ranges.len(), 1);
        assert_eq!(receipt.recovered_chunks(), 1);
        assert_eq!(receipt.recovered_bytes(), live[0].data.len() as u64);
    }
}

/// Regression for KH-1409: a plan identity with the wrong chunk cardinality is
/// malformed for the request, so every live byte must be exactly recomputed and
/// represented in the receipt rather than partially zipping the plan.
#[test]
fn malformed_plan_cardinality_recovers_every_live_chunk() {
    let scanner = scanner();
    let planned = vec![chunk("ghp_A1b2C3d4!".into())];
    let plan = scanner.phase1_admission_plan(&planned);
    let live = vec![
        chunk("ghp_M3n4B5v6!".into()),
        chunk("ghp_Z9y8X7w6!".into()),
    ];

    let outcome = scanner.scan_coalesced_with_backend_admission_route_and_recovery(&live,
    ScanBackend::CpuFallback,
    Some(&plan),
    scanner.execution_route_for_backend(ScanBackend::CpuFallback),
    false,)
        .expect("malformed plan identity recovers through exact admission");
    assert_eq!(
        canonical(&outcome.matches)
            .into_iter()
            .map(|row| row.3)
            .collect::<Vec<_>>(),
        vec![
            "ghp_M3n4B5v6".to_string(),
            "ghp_Z9y8X7w6".to_string(),
        ],
        "malformed identity recovery must preserve every safe finding"
    );
    let receipt = outcome
        .recovery
        .expect("malformed identity must return a recovery receipt");
    assert_eq!(receipt.ranges.len(), 2);
    assert_eq!(receipt.recovered_chunks(), 2);
    assert_eq!(
        receipt.recovered_bytes(),
        live.iter()
            .map(|chunk| chunk.data.len() as u64)
            .sum::<u64>()
    );
    assert_eq!(
        receipt.reason,
        "malformed phase-one admission plan identity; discarded the untrusted plan and recomputed exact admission"
    );
}

/// Regression for KH-1409: the legacy fallible API cannot represent recovery
/// metadata, so it must return the typed identity error instead of discarding a
/// completed receipt and presenting recovered findings as an ordinary success.
#[test]
fn receipt_blind_fallible_api_rejects_mismatched_identity() {
    let scanner = scanner();
    let planned = vec![chunk("ghp_A1b2C3d4!".into())];
    let plan = scanner.phase1_admission_plan(&planned);
    let live = vec![chunk("ghp_M3n4B5v6!".into())];

    let error = scanner.scan_coalesced_with_backend_and_admission(&live,
    ScanBackend::CpuFallback,
    Some(&plan),)
        .expect_err("receipt-blind API must fail closed on identity recovery");
    assert!(matches!(
        error,
        keyhog_scanner::ScanError::AdmissionPlanIdentity(reason)
            if reason == "phase-one admission plan identity mismatch; discarded the untrusted plan and recomputed exact admission"
    ));
}
