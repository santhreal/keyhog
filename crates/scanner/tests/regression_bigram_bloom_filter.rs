//! Scanner-level health, gating, and differential coverage for KH-1237.

use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::testing::{production_bigram_prefilter_status, BigramBloom};
use keyhog_scanner::{BigramPrefilterState, CompiledScanner, ScanBackend};

const SATURATION_FLOOR: u32 = 39_322;

fn bloom(literals: &[&str]) -> BigramBloom {
    BigramBloom::from_literal_prefixes(
        &literals
            .iter()
            .map(|literal| (*literal).to_owned())
            .collect::<Vec<_>>(),
    )
}

fn detector(patterns: Vec<PatternSpec>) -> DetectorSpec {
    DetectorSpec {
        tests: Vec::new(),
        id: "kh-1237-selective-filter".into(),
        name: "KH-1237 selective filter".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns,
        companions: Vec::new(),
        verify: None,
        keywords: Vec::new(),
        min_confidence: Some(0.0),
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    }
}

fn chunk(path: &str, data: String) -> Chunk {
    Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            source_type: "kh-1237".into(),
            path: Some(path.into()),
            ..ChunkMetadata::default()
        },
    }
}

#[test]
fn production_detector_set_is_healthy_and_materially_populated() {
    let status = production_bigram_prefilter_status();
    eprintln!(
        "production selective bloom: popcount={} of {} ({:.2}% full)",
        status.populated_slots,
        status.total_slots,
        status.density_basis_points as f64 / 100.0
    );
    assert_eq!(status.state, BigramPrefilterState::Healthy);
    assert!(status.populated_slots > 256);
    assert!(status.populated_slots < SATURATION_FLOOR);
    assert_eq!(status.total_slots, 65_536);
    assert_eq!(status.saturation_threshold_slots, SATURATION_FLOOR);
}

#[test]
fn diagnostics_report_exact_density_and_named_corpus_rejection() {
    let filter = bloom(&["AB"]);
    let status = filter.status();
    assert_eq!(
        status.populated_slots, 0,
        "short anchors use the exact owner"
    );
    assert_eq!(status.total_slots, 65_536);
    assert_eq!(status.density_basis_points, 0);
    assert_eq!(status.state, BigramPrefilterState::Healthy);

    let inputs = [&b"AB"[..], &b"AC"[..], &b"CA"[..]];
    let corpus = filter.corpus_status("kh-1237-ordinary", inputs);
    assert_eq!(corpus.corpus_name, "kh-1237-ordinary");
    assert_eq!(corpus.input_count, 3);
    assert_eq!(corpus.eligible_inputs, 3);
    assert_eq!(corpus.rejected_inputs, 2);
    assert_eq!(corpus.rejection_basis_points, 6_666);
}

#[test]
fn saturation_boundary_is_exact_and_fail_open() {
    let below = BigramBloom::with_population_for_test(SATURATION_FLOOR - 1);
    let at = BigramBloom::with_population_for_test(SATURATION_FLOOR);
    assert_eq!(below.status().state, BigramPrefilterState::Healthy);
    assert_eq!(at.status().state, BigramPrefilterState::Saturated);
    assert!(at.maybe_overlaps(b"unset anchor must fail open"));
}

#[test]
fn invalid_filter_is_visible_and_fail_open() {
    let invalid = BigramBloom::invalid_for_test();
    assert_eq!(invalid.status().state, BigramPrefilterState::Invalid);
    assert!(invalid.maybe_overlaps(b"candidate"));
    let inputs = [&b"candidate"[..], &b"ordinary source"[..]];
    let status = invalid.corpus_status("invalid", inputs);
    assert_eq!(status.rejected_inputs, 0);
}

#[test]
fn production_corpus_measurement_obeys_sixty_four_byte_boundary() {
    let filter = bloom(&["ANCHOR_1234"]);
    let below = [b'z'; 63];
    let at = [b'z'; 64];
    let status = filter.production_corpus_status("boundary", [&below[..], &at[..]]);
    assert_eq!(status.input_count, 2);
    assert_eq!(status.eligible_inputs, 1);
    assert_eq!(status.rejected_inputs, 1);
    assert_eq!(status.rejection_basis_points, 5_000);
}

#[test]
fn direct_literal_enabled_and_bypass_findings_are_identical() {
    let scanner = CompiledScanner::compile(vec![detector(vec![PatternSpec {
        regex: r"TOKEN_[A-Za-z0-9]{24}".into(),
        ..Default::default()
    }])])
    .expect("compile direct detector");
    let chunks = vec![
        chunk("negative.txt", "T_O_K_E_N".repeat(12)),
        chunk(
            "positive.txt",
            format!(
                "{}TOKEN_abcdefghijklmnopqrstuvwx{}",
                "!".repeat(40),
                "~".repeat(40)
            ),
        ),
    ];
    let admission = scanner.phase1_admission_plan(&chunks);
    assert_eq!(admission.summary().bigram_rejected_chunks, 1);

    scanner.clear_fragment_cache();
    let enabled = scanner
        .scan_chunks_with_backend(&chunks, ScanBackend::CpuFallback)
        .expect("enabled scan");
    scanner.clear_fragment_cache();
    let bypass = scanner
        .scan_chunks_with_backend_bypassing_bigram_for_diagnostics(
            &chunks,
            ScanBackend::CpuFallback,
        )
        .expect("bypass scan");
    assert_eq!(enabled, bypass);
    assert!(enabled[0].is_empty());
    assert_eq!(enabled[1].len(), 1);
}

/// WHY: repeated payloads must share route classification work without letting a
/// sampled-fingerprint collision reuse another payload's admission decision.
#[test]
fn phase1_plan_classifies_each_distinct_payload_once() {
    const BYTES: usize = 100 * 1024;
    const CREDENTIAL: &str = "TOKEN_abcdefghijklmnopqrstuvwx";
    let scanner = CompiledScanner::compile(vec![detector(vec![PatternSpec {
        regex: r"TOKEN_[A-Za-z0-9]{24}".into(),
        ..Default::default()
    }])])
    .expect("compile direct detector");
    let repeated = "T_O_K_E_N".repeat(BYTES.div_ceil(9));
    let mut repeated = repeated[..BYTES].to_owned();
    let mut colliding = repeated.clone();
    colliding.replace_range(BYTES / 2..BYTES / 2 + CREDENTIAL.len(), CREDENTIAL);
    let colliding_repeated = colliding.clone();
    let chunks = vec![
        chunk("repeated-0.txt", repeated.clone()),
        chunk("repeated-1.txt", repeated.clone()),
        chunk("repeated-2.txt", std::mem::take(&mut repeated)),
        chunk("distinct.txt", colliding),
    ];

    let plan = scanner.phase1_admission_plan(&chunks);
    assert_eq!(plan.unique_payloads_for_diagnostics(), 2);
    assert_eq!(plan.summary().bigram_rejected_chunks, 3);
    assert_eq!(plan.summary().admitted_chunks, 1);
    scanner.reset_reusable_phase1_evidence_hits_for_diagnostics();
    let collision_chunks = vec![
        chunk("collision-0.txt", colliding_repeated.clone()),
        chunk("collision-1.txt", colliding_repeated.clone()),
        chunk("collision-2.txt", colliding_repeated),
    ];
    let collision_plan = scanner.phase1_admission_plan(&collision_chunks);
    assert_eq!(
        collision_plan.summary().admitted_chunks,
        3,
        "sampled-fingerprint collisions must classify by full payload bytes"
    );
    assert_eq!(
        scanner.reusable_phase1_evidence_hits_for_diagnostics(),
        0,
        "a sampled-fingerprint collision must not hit the reusable evidence cache"
    );
    scanner.phase1_admission_plan(&collision_chunks);
    assert!(
        scanner.reusable_phase1_evidence_hits_for_diagnostics() > 0,
        "the exact colliding payload must become reusable after independent classification"
    );
    let planned = scanner
        .scan_coalesced_with_backend_and_admission(&chunks, ScanBackend::CpuFallback, Some(&plan))
        .expect("planned scan");
    scanner.clear_fragment_cache();
    let direct = scanner
        .scan_coalesced_with_backend(&chunks, ScanBackend::CpuFallback)
        .expect("direct scan");
    assert_eq!(
        planned, direct,
        "deduplicated admission planning must preserve per-chunk findings"
    );
}

/// WHY: autoroute already scans byte-distinct representatives for phase-two
/// keywords. The production CPU scan must consume those exact hints instead of
/// rescanning every repeated payload, while preserving phase-two-only findings.
#[test]
fn repeated_payloads_share_phase2_keyword_hints() {
    let mut phase2_detector = detector(vec![PatternSpec {
        regex: r"([a-z]{4}[0-9]{4})".into(),
        group: Some(1),
        ..Default::default()
    }]);
    phase2_detector.keywords = vec!["phasekw".into()];
    let scanner =
        CompiledScanner::compile(vec![phase2_detector]).expect("compile phase-two detector");
    let payload = "phasekw = abcd1234\n".repeat(512);
    let chunks = vec![
        chunk("phase2-0.txt", payload.clone()),
        chunk("phase2-1.txt", payload.clone()),
        chunk("phase2-2.txt", payload),
    ];

    let plan = scanner.phase1_admission_plan(&chunks);
    let first = plan
        .phase2_keyword_hints_for_diagnostics(0)
        .expect("first hint row");
    assert!(
        !first.is_empty(),
        "fixture must activate a phase-two keyword"
    );
    assert_eq!(
        plan.phase2_keyword_hints_for_diagnostics(1),
        Some(first),
        "byte-identical payloads must reference the same persisted hint row"
    );
    let total_bytes = chunks
        .iter()
        .map(|chunk| chunk.data.len() as u64)
        .sum::<u64>();
    scanner.reset_phase2_keyword_scanned_bytes_for_diagnostics();

    let planned = scanner
        .scan_coalesced_with_backend_and_admission(&chunks, ScanBackend::CpuFallback, Some(&plan))
        .expect("planned scan");
    assert_eq!(
        scanner.phase2_keyword_scanned_bytes_for_diagnostics(),
        0,
        "planned scan must consume persisted hints without rescanning payload bytes"
    );
    scanner.clear_fragment_cache();
    scanner.reset_phase2_keyword_scanned_bytes_for_diagnostics();
    let direct = scanner
        .scan_coalesced_with_backend(&chunks, ScanBackend::CpuFallback)
        .expect("direct scan");
    assert_eq!(
        scanner.phase2_keyword_scanned_bytes_for_diagnostics(),
        total_bytes,
        "direct scan must establish the diagnostic fallback-byte control"
    );
    assert_eq!(planned, direct);
    assert!(
        planned.iter().all(|matches| !matches.is_empty()),
        "phase-two keyword hints must retain every repeated finding"
    );
}

/// WHY: generic assignment stem localization is payload-only and is already
/// computed while autoroute classifies exact representatives. CPU dispatch must
/// consume those persisted positions without rescanning duplicate chunk bytes.
#[test]
fn repeated_payloads_share_generic_keyword_positions() {
    let mut detector_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    detector_dir.pop();
    detector_dir.pop();
    detector_dir.push("detectors");
    let mut scanner = CompiledScanner::compile(
        keyhog_core::load_detectors(&detector_dir).expect("production detectors"),
    )
    .expect("compile production scanner");
    let payload = "secret = Ab3dEf5hJk7mNp9qRs2uVw4yXz6Bcd8F\n".repeat(128);
    let chunks = vec![
        chunk("generic-0.txt", payload.clone()),
        chunk("generic-1.txt", payload.clone()),
        chunk("generic-2.txt", payload),
    ];

    let plan = scanner.phase1_admission_plan(&chunks);
    assert_eq!(
        plan.entropy_absence_for_diagnostics(0),
        Some(false),
        "repeated credential fixture must not claim entropy absence"
    );
    let first = plan
        .generic_keyword_positions_for_diagnostics(0)
        .expect("first generic position row");
    assert!(!first.is_empty(), "fixture must activate a generic stem");
    assert_eq!(
        plan.generic_keyword_positions_for_diagnostics(1),
        Some(first),
        "byte-identical payloads must reference the same generic position row"
    );

    scanner.reset_generic_keyword_scanned_bytes_for_diagnostics();
    let planned = scanner
        .scan_coalesced_with_backend_and_admission(&chunks, ScanBackend::CpuFallback, Some(&plan))
        .expect("planned scan");
    assert_eq!(
        scanner.generic_keyword_scanned_bytes_for_diagnostics(),
        0,
        "planned scan must consume generic positions without rescanning bytes"
    );

    scanner.clear_fragment_cache();
    scanner.reset_generic_keyword_scanned_bytes_for_diagnostics();
    let direct = scanner
        .scan_coalesced_with_backend(&chunks, ScanBackend::CpuFallback)
        .expect("direct scan");
    assert_eq!(
        scanner.generic_keyword_scanned_bytes_for_diagnostics(),
        chunks
            .iter()
            .map(|chunk| chunk.data.len() as u64)
            .sum::<u64>(),
        "direct scan must establish the generic prefilter byte control"
    );
    assert_eq!(planned, direct);
    assert!(
        planned.iter().all(|matches| !matches.is_empty()),
        "generic position hints must retain every repeated finding"
    );

    let ordinary_payload = "const ordinary_value = 1234567890;\n".repeat(2_925);
    let ordinary_chunks = vec![
        chunk("ordinary-0.txt", ordinary_payload.clone()),
        chunk("ordinary-1.txt", ordinary_payload.clone()),
        chunk("ordinary-2.txt", ordinary_payload),
    ];
    scanner.reset_reusable_phase1_evidence_hits_for_diagnostics();
    let initial_ordinary_plan = scanner.phase1_admission_plan(&ordinary_chunks);
    assert_eq!(
        scanner.reusable_phase1_evidence_hits_for_diagnostics(),
        0,
        "the first exact payload classification must populate rather than hit the cache"
    );
    let ordinary_plan = scanner.phase1_admission_plan(&ordinary_chunks);
    assert_eq!(ordinary_plan.summary(), initial_ordinary_plan.summary());
    assert!(
        scanner.reusable_phase1_evidence_hits_for_diagnostics() > 0,
        "a later batch must reuse exact representative evidence"
    );
    assert_eq!(
        ordinary_plan.phase2_always_active_absence_for_diagnostics(0),
        Some(true),
        "repeated clean fixture must establish complete always-active absence"
    );
    let ordinary_triggers = ordinary_plan
        .cpu_trigger_hints_for_diagnostics(0)
        .expect("repeated clean fixture must persist CPU trigger evidence");
    assert!(
        ordinary_triggers.iter().any(|&word| word != 0),
        "fixture must exercise confirmed-pattern trigger collection"
    );
    assert_eq!(
        ordinary_plan.cpu_trigger_hints_for_diagnostics(1),
        Some(ordinary_triggers),
        "byte-identical payloads must reference the same CPU trigger row"
    );
    assert_eq!(
        ordinary_plan.normalization_passthrough_for_diagnostics(0),
        Some(true),
        "repeated ASCII fixture must establish exact normalization passthrough"
    );
    assert_eq!(
        ordinary_plan.confirmed_patterns_absence_for_diagnostics(0),
        Some(true),
        "repeated clean fixture must establish exact confirmed-pattern absence"
    );
    assert_eq!(
        ordinary_plan.entropy_absence_for_diagnostics(0),
        Some(true),
        "repeated clean fixture must establish path-independent entropy absence"
    );
    assert_eq!(
        ordinary_plan.multiline_absence_for_diagnostics(0),
        Some(true),
        "repeated clean fixture must establish multiline-admission absence"
    );
    assert_eq!(
        ordinary_plan.line_context_index_for_diagnostics(0),
        Some(true),
        "repeated passthrough fixture must persist one reusable line index"
    );

    scanner.clear_fragment_cache();
    scanner.reset_phase2_prefilter_scanned_bytes_for_diagnostics();
    scanner.reset_phase1_trigger_scanned_bytes_for_diagnostics();
    scanner.reset_normalization_scanned_bytes_for_diagnostics();
    scanner.reset_confirmed_pattern_scanned_bytes_for_diagnostics();
    scanner.reset_entropy_scanned_bytes_for_diagnostics();
    scanner.reset_multiline_admission_scanned_bytes_for_diagnostics();
    scanner.reset_line_index_scanned_bytes_for_diagnostics();
    let planned_ordinary = scanner
        .scan_coalesced_with_backend_and_admission(
            &ordinary_chunks,
            ScanBackend::CpuFallback,
            Some(&ordinary_plan),
        )
        .expect("planned ordinary scan");
    assert_eq!(
        scanner.phase2_prefilter_scanned_bytes_for_diagnostics(),
        0,
        "complete representative absence must suppress repeated prefilter scans"
    );
    assert_eq!(
        scanner.phase1_trigger_scanned_bytes_for_diagnostics(),
        0,
        "planned scan must consume CPU trigger hints without rescanning bytes"
    );
    assert_eq!(
        scanner.normalization_scanned_bytes_for_diagnostics(),
        0,
        "planned scan must consume normalization passthrough without rescanning bytes"
    );
    assert_eq!(
        scanner.confirmed_pattern_scanned_bytes_for_diagnostics(),
        0,
        "planned scan must consume confirmed-pattern absence without rescanning bytes"
    );
    assert_eq!(
        scanner.entropy_scanned_bytes_for_diagnostics(),
        0,
        "planned scan must consume entropy absence without rescanning bytes"
    );
    assert_eq!(
        scanner.multiline_admission_scanned_bytes_for_diagnostics(),
        0,
        "planned scan must consume multiline absence without rescanning bytes"
    );
    assert_eq!(
        scanner.line_index_scanned_bytes_for_diagnostics(),
        0,
        "planned scan must consume the shared line index without rebuilding it"
    );

    scanner.clear_fragment_cache();
    scanner.reset_phase2_prefilter_scanned_bytes_for_diagnostics();
    scanner.reset_phase1_trigger_scanned_bytes_for_diagnostics();
    scanner.reset_normalization_scanned_bytes_for_diagnostics();
    scanner.reset_confirmed_pattern_scanned_bytes_for_diagnostics();
    scanner.reset_entropy_scanned_bytes_for_diagnostics();
    scanner.reset_multiline_admission_scanned_bytes_for_diagnostics();
    scanner.reset_line_index_scanned_bytes_for_diagnostics();
    let direct_ordinary = scanner
        .scan_coalesced_with_backend(&ordinary_chunks, ScanBackend::CpuFallback)
        .expect("direct ordinary scan");
    assert!(
        scanner.phase2_prefilter_scanned_bytes_for_diagnostics() > 0,
        "direct scan must establish the always-active prefilter control"
    );
    assert!(
        scanner.phase1_trigger_scanned_bytes_for_diagnostics() > 0,
        "direct scan must establish the phase-one trigger byte control"
    );
    assert!(
        scanner.normalization_scanned_bytes_for_diagnostics() > 0,
        "direct scan must establish the normalization byte control"
    );
    assert!(
        scanner.confirmed_pattern_scanned_bytes_for_diagnostics() > 0,
        "direct scan must establish the confirmed-pattern byte control"
    );
    assert!(
        scanner.entropy_scanned_bytes_for_diagnostics() > 0,
        "direct scan must establish the entropy byte control"
    );
    assert!(
        scanner.multiline_admission_scanned_bytes_for_diagnostics() > 0,
        "direct scan must establish the multiline-admission byte control"
    );
    assert!(
        scanner.line_index_scanned_bytes_for_diagnostics() > 0,
        "direct scan must establish the line-index byte control"
    );
    assert_eq!(planned_ordinary, direct_ordinary);
    assert!(planned_ordinary.iter().all(Vec::is_empty));

    let multiline_payload = "secret = \"alpha\" +\n    \"beta\"\n".repeat(128);
    let multiline_chunks = vec![
        chunk("multiline-0.txt", multiline_payload.clone()),
        chunk("multiline-1.txt", multiline_payload.clone()),
        chunk("multiline-2.txt", multiline_payload),
    ];
    let multiline_plan = scanner.phase1_admission_plan(&multiline_chunks);
    assert_eq!(
        multiline_plan.multiline_absence_for_diagnostics(0),
        Some(false),
        "a concatenated assignment must never claim multiline-admission absence"
    );

    scanner.config.entropy_threshold = (scanner.config.entropy_threshold - 0.01).max(0.0);
    scanner.clear_fragment_cache();
    scanner.reset_entropy_scanned_bytes_for_diagnostics();
    scanner.reset_multiline_admission_scanned_bytes_for_diagnostics();
    scanner
        .scan_coalesced_with_backend_and_admission(
            &ordinary_chunks,
            ScanBackend::CpuFallback,
            Some(&ordinary_plan),
        )
        .expect("config-changed planned scan");
    assert!(
        scanner.multiline_admission_scanned_bytes_for_diagnostics() > 0,
        "a changed evidence policy must invalidate multiline absence"
    );
    assert!(
        scanner.entropy_scanned_bytes_for_diagnostics() > 0,
        "a changed entropy policy must invalidate persisted absence evidence"
    );
}

/// WHY: representative absence is valid only when every triggered confirmed
/// regex is absent. A matching representative must retain full per-chunk
/// extraction so path-sensitive adjudication still runs independently.
#[test]
fn repeated_confirmed_matches_never_claim_absence() {
    let scanner = CompiledScanner::compile(vec![detector(vec![PatternSpec {
        regex: r"ANCHOR_[A-Za-z0-9]{24}".into(),
        ..Default::default()
    }])])
    .expect("compile anchored detector");
    let payload = format!("prefix ANCHOR_{} suffix", "A1b2C3d4E5f6G7h8J9k0LmNo");
    let chunks = vec![
        chunk("confirmed-0.txt", payload.clone()),
        chunk("confirmed-1.txt", payload.clone()),
        chunk("confirmed-2.txt", payload),
    ];
    let plan = scanner.phase1_admission_plan(&chunks);
    assert_eq!(
        plan.confirmed_patterns_absence_for_diagnostics(0),
        Some(false),
        "a matching confirmed regex must invalidate representative absence"
    );

    let planned = scanner
        .scan_coalesced_with_backend_and_admission(&chunks, ScanBackend::CpuFallback, Some(&plan))
        .expect("planned confirmed scan");
    scanner.clear_fragment_cache();
    let direct = scanner
        .scan_coalesced_with_backend(&chunks, ScanBackend::CpuFallback)
        .expect("direct confirmed scan");
    assert_eq!(planned, direct);
    assert!(planned.iter().all(|matches| !matches.is_empty()));
}

#[test]
fn prefixless_dynamic_pattern_stays_in_explicit_always_admit_lane() {
    let scanner = CompiledScanner::compile(vec![detector(vec![
        PatternSpec {
            regex: r"ANCHOR_[A-Za-z0-9]{24}".into(),
            ..Default::default()
        },
        PatternSpec {
            regex: r"([Q]{4}[0-9]{4}[Z]{16})".into(),
            group: Some(1),
            ..Default::default()
        },
    ])])
    .expect("compile mixed anchored/dynamic detector");
    let credential = "QQQQ1234ZZZZZZZZZZZZZZZZ";
    let chunks = vec![chunk(
        "dynamic.txt",
        format!(
            "{}{}{}{}",
            "A_N_C_H_O_R".repeat(8),
            "!".repeat(40),
            credential,
            "~".repeat(40)
        ),
    )];
    let admission = scanner.phase1_admission_plan(&chunks);
    assert_eq!(admission.summary().bigram_rejected_chunks, 1);

    scanner.clear_fragment_cache();
    let enabled = scanner
        .scan_chunks_with_backend(&chunks, ScanBackend::CpuFallback)
        .expect("enabled scan");
    scanner.clear_fragment_cache();
    let bypass = scanner
        .scan_chunks_with_backend_bypassing_bigram_for_diagnostics(
            &chunks,
            ScanBackend::CpuFallback,
        )
        .expect("bypass scan");
    assert_eq!(enabled, bypass);
    assert!(enabled[0]
        .iter()
        .any(|finding| finding.credential.as_ref() == credential));
}
