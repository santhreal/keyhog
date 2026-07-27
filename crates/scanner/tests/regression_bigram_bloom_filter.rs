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
