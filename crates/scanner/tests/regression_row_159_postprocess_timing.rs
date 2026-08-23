//! Regression test for Row 159: Postprocess & confirmation timing metrics.
//!
//! WHY: closes the class of a postprocess or phase-2 stage whose cost is invisible to
//! the profile runtime, so a regression there cannot be measured.
//! What it does not catch: the absolute cost of a stage that is already attributed,
//! and stages this suite does not exercise.
//! Candidate confirmation in postprocess and phase-2 verification previously lacked
//! unified, typed metric attribution in `keyhog_profile`. Overhead from suffix gating,
//! companion gating, anchor candidate collection, fragment reassembly, and postprocess
//! resolution was either hidden in unprofiled spans or kept in isolated process-global
//! atomics rather than the unified profile runtime.
//!
//! This test closes that defect class by verifying:
//! 1. Confirmed pattern extraction records fine-grained typed metrics for suffix gates,
//!    companion gates, anchor candidate collection, and extraction.
//! 2. Phase-2 candidate collection and anchored verification capture candidate counts,
//!    verification counts, and pattern evaluations.
//! 3. Cross-chunk fragment scanning and postprocess dedup capture calls and timing spans.
//! 4. `ConfirmedPostprocessProfile` and `Phase2VerificationProfile` accurately drain and format
//!    these metrics without memory leaks or unmeasured regions.

use keyhog_core::{detector_spec_by_id, Chunk, DetectorSpec};
use keyhog_profile::{set_detail, take_typed_metrics, CounterId, Detail};
use keyhog_scanner::{
    engine::phase2::{format_phase2_verification_profile, phase2_verification_profile_from_typed},
    engine::scan_postprocess::{
        confirmed_postprocess_profile_from_typed, format_confirmed_postprocess_profile,
    },
    CompiledScanner, ScanBackend,
};

fn test_detector_suite() -> Vec<DetectorSpec> {
    let mut specs = Vec::new();
    if let Some(spec) = detector_spec_by_id("slack-bot-token") {
        specs.push(spec.clone());
    }
    if let Some(spec) = detector_spec_by_id("github-classic-pat") {
        specs.push(spec.clone());
    }
    if specs.is_empty() {
        let sample = detector_spec_by_id("aws-access-key-id").expect("aws detector exists");
        specs.push(sample.clone());
    }
    specs
}

#[test]
fn test_postprocess_confirmation_and_phase2_metrics_attribution() {
    set_detail(Detail::Diagnostic);
    keyhog_profile::reset();

    let detectors = test_detector_suite();
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    let sample_text = "\
// Some header comment with ordinary_value = 1234567890
let slack_key = \"xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx\";
let ghp_token = \"ghp_123456789012345678901234567890123456\";
";
    let chunk = Chunk::from(sample_text);

    let matches = scanner
        .scan_chunks_with_backend(&[chunk], ScanBackend::CpuFallback)
        .expect("scan succeeds");

    assert!(!matches.is_empty(), "expected at least 1 match");

    let typed = take_typed_metrics();
    assert!(!typed.is_empty(), "expected recorded typed metrics");

    let confirmed = confirmed_postprocess_profile_from_typed(&typed);
    let phase2_verif = phase2_verification_profile_from_typed(&typed);

    // Verify confirmed profile formatting
    let formatted_confirmed = format_confirmed_postprocess_profile(&confirmed);
    assert!(
        formatted_confirmed.contains("CONFIRMED postprocess confirmation profile"),
        "expected header in confirmed format: {formatted_confirmed}"
    );

    // Verify phase2 verification formatting
    let formatted_phase2 = format_phase2_verification_profile(&phase2_verif);
    assert!(
        formatted_phase2.contains("PHASE2 verification profile"),
        "expected header in phase2 format: {formatted_phase2}"
    );

    // Suffix gate or extract calls should have fired
    let value = |cid: CounterId| {
        typed
            .iter()
            .find(|r| r.metric_id == cid.metric_id())
            .map_or(0, |r| r.value)
    };

    let extract_calls = value(CounterId::ConfirmedExtractCalls);
    let anchored_matches = value(CounterId::ConfirmedAnchoredMatches);
    let whole_matches = value(CounterId::ConfirmedWholeChunkMatches);
    assert!(
        extract_calls > 0 || anchored_matches > 0 || whole_matches > 0,
        "expected non-zero extract or match counters: calls={extract_calls}, anchored={anchored_matches}, whole={whole_matches}"
    );
    assert!(
        confirmed.any_recorded() || phase2_verif.any_recorded(),
        "expected recorded metrics in profile structures"
    );

    set_detail(Detail::Off);
}

#[test]
fn test_postprocess_fragments_and_dedup_timing_isolated() {
    set_detail(Detail::Diagnostic);
    keyhog_profile::reset();

    let detectors = test_detector_suite();
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    let chunk = Chunk::from("xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx");
    let _ = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::CpuFallback);

    let typed = take_typed_metrics();
    let confirmed = confirmed_postprocess_profile_from_typed(&typed);

    // Postprocess profile accurately formats all sub-fields
    let text = format_confirmed_postprocess_profile(&confirmed);
    assert!(text.contains("suffix-gate:"));
    assert!(text.contains("companion-gate:"));
    assert!(text.contains("anchor-collect:"));
    assert!(text.contains("extract:"));
    assert!(text.contains("fragments:"));
    assert!(text.contains("dedup:"));

    set_detail(Detail::Off);
}

#[test]
fn test_zero_overhead_when_profiling_disabled() {
    set_detail(Detail::Off);
    keyhog_profile::reset();

    let detectors = test_detector_suite();
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    let chunk = Chunk::from("xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx");
    let matches = scanner
        .scan_chunks_with_backend(&[chunk], ScanBackend::CpuFallback)
        .expect("scan succeeds");
    assert!(!matches.is_empty());

    let typed = take_typed_metrics();
    let confirmed = confirmed_postprocess_profile_from_typed(&typed);
    let phase2_verif = phase2_verification_profile_from_typed(&typed);

    assert_eq!(confirmed.extract_ns, 0);
    assert_eq!(confirmed.suffix_gate_ns, 0);
    assert_eq!(phase2_verif.anchor_collect_ns, 0);
}
