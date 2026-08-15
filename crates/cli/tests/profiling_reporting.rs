//! Profiling instrumentation contract tests for the CLI reporting slice:
//! reporting.rs (report assembly + per-format encoders + coverage-gap event),
//! baseline.rs, inline_suppression.rs, and action_report.rs.
//!
//! Every test asserts the exact Stage and exact call count recorded under an
//! active `keyhog_profile::Runtime`, and the suite closes with a silence test
//! proving the same paths record nothing without one.

use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::testing::{CliTestApi as _, API};
use keyhog_core::{
    Chunk, ChunkMetadata, MatchLocation, RawMatch, SensitiveString, Severity, VerificationResult,
    VerifiedFinding,
};
use keyhog_profile::{EventId, Stage, StageMeasurement};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// Run `f` under a fresh recording runtime and drain its stage measurements.
///
/// The enter guard MUST stay held across `take_stage_measurements`: the drain
/// reads the runtime current on this thread, so draining after the guard drops
/// would read the (always empty) legacy runtime instead.
fn measure(f: impl FnOnce()) -> Vec<StageMeasurement> {
    keyhog_profile::reset();
    let runtime = keyhog_profile::Runtime::new();
    let guard = runtime.enter();
    f();
    let measurements = keyhog_profile::take_stage_measurements();
    drop(guard);
    keyhog_profile::reset();
    measurements
}

/// Assert the measurement set is exactly one stage with an exact call count.
/// A second instrumented stage sneaking onto the measured path must fail here.
fn assert_only_stage(measurements: &[StageMeasurement], stage: Stage, calls: u64) {
    assert_eq!(
        measurements.len(),
        1,
        "expected exactly one recorded stage, got {measurements:?}"
    );
    assert_eq!(measurements[0].stage, stage);
    assert_eq!(measurements[0].calls, calls);
}

/// Minimal verified finding; `hash_byte` keys baseline identity.
fn verified_finding(hash_byte: u8) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from("demo-detector"),
        detector_name: Arc::from("Demo Detector"),
        service: Arc::from("demo"),
        severity: Severity::High,
        credential_redacted: "demo…redacted".into(),
        credential_hash: [hash_byte; 32].into(),
        companions_redacted: HashMap::new(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from("demo.txt")),
            line: Some(2),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Unverifiable,
        metadata: HashMap::new(),
        additional_locations: Vec::new(),
        entropy: None,
        evidence_score: None,
        evidence: keyhog_core::EvidenceVerdict::review_unattributed(),
    }
}

/// ScanArgs that route report output to a temp file (never the TTY).
fn report_args(dir: &Path, format: &str, file: &str) -> ScanArgs {
    let out = dir.join(file);
    ScanArgs::try_parse_from([
        "scan",
        ".",
        "--format",
        format,
        "--output",
        out.to_str().expect("temp path is UTF-8"),
    ])
    .expect("parse report args")
}

/// Filesystem chunk + raw match fixture for the inline suppression paths;
/// the file carries a `keyhog:ignore` directive above the secret line.
fn inline_fixture(dir: &Path) -> (std::path::PathBuf, Chunk, RawMatch) {
    let path = dir.join("with_ignore.rs");
    let scanned = "// keyhog:ignore\nlet token = \"secret\";\n";
    std::fs::write(&path, scanned).expect("write inline fixture");
    let chunk = Chunk {
        data: SensitiveString::from(scanned),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some(path.to_string_lossy().into_owned().into()),
            ..Default::default()
        },
    };
    let m = RawMatch {
        detector_id: Arc::from("demo"),
        detector_name: Arc::from("Demo"),
        service: Arc::from("demo"),
        severity: Severity::Low,
        credential: SensitiveString::from("secret"),
        credential_hash: [9u8; 32].into(),
        companions: HashMap::new(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from(path.to_string_lossy().as_ref())),
            line: Some(2),
            offset: scanned.find("secret").expect("fixture contains credential"),
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: None,
        evidence: keyhog_core::EvidenceVerdict::review_unattributed(),
    };
    (path, chunk, m)
}

/// One Action receipt argument set plus a pre-written report file to digest.
fn receipt_fixture(dir: &Path) -> (ScanArgs, std::path::PathBuf) {
    let report = dir.join("report.json");
    std::fs::write(&report, "{}\n").expect("write report fixture");
    let receipt = dir.join("receipt.txt");
    let args = ScanArgs::try_parse_from([
        "scan",
        ".",
        "--format",
        "json",
        "--output",
        report.to_str().expect("UTF-8"),
        "--action-receipt",
        receipt.to_str().expect("UTF-8"),
    ])
    .expect("parse receipt args");
    (args, receipt)
}

/// WHY: report finalization must attribute ScanReport assembly AND the JSON
/// encoder write+flush to Stage::Reporting (2 calls total). A regression that
/// drops either span, or double-wraps one, changes this exact count.
#[test]
fn report_json_records_assembly_and_encoder_spans() {
    let dir = tempfile::tempdir().expect("tempdir");
    let guard = API.scan_runtime_guard_for_test();
    let args = report_args(dir.path(), "json", "report.json");
    let measurements = measure(|| {
        API.report_findings(&[], &args, &guard)
            .expect("JSON report");
    });
    assert_only_stage(&measurements, Stage::Reporting, 2);
}

/// WHY: the coverage-gap detection seam in reporting must emit exactly one
/// EventId::CoverageGap per detection pass that finds gaps, alongside the two
/// Reporting spans (assembly + CSV encoder). Locks the KH-law-10 structured
/// gap surface to its telemetry contract.
#[test]
fn report_csv_with_coverage_gap_records_event_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let guard = API.scan_runtime_guard_for_test();
    keyhog_sources::merge_skip_count_deltas(&keyhog_sources::SkipCounts {
        over_max_size: 2,
        ..Default::default()
    });
    keyhog_profile::reset();
    let runtime = keyhog_profile::Runtime::new();
    let profile_guard = runtime.enter();
    let args = report_args(dir.path(), "csv", "report.csv");
    API.report_findings(&[], &args, &guard).expect("CSV report");
    let measurements = keyhog_profile::take_stage_measurements();
    let (events, _, _) = runtime.take_session_typed_events();
    drop(profile_guard);
    keyhog_profile::reset();
    keyhog_sources::reset_skipped_over_max_size();

    assert_only_stage(&measurements, Stage::Reporting, 2);
    let coverage_events: Vec<_> = events
        .iter()
        .filter(|event| event.event_id == EventId::CoverageGap)
        .collect();
    assert_eq!(
        coverage_events.len(),
        1,
        "one detection pass with gaps must record exactly one event, got {events:?}"
    );
    assert_eq!(coverage_events[0].value, 1);
}

/// WHY: the plain JSON arm never runs coverage-gap detection, so even with
/// polluted global skip counters it must record zero CoverageGap events. Locks
/// the event to the detection seam instead of firing per report.
#[test]
fn report_json_never_records_coverage_gap_events() {
    let dir = tempfile::tempdir().expect("tempdir");
    let guard = API.scan_runtime_guard_for_test();
    keyhog_sources::merge_skip_count_deltas(&keyhog_sources::SkipCounts {
        over_max_size: 3,
        ..Default::default()
    });
    keyhog_profile::reset();
    let runtime = keyhog_profile::Runtime::new();
    let profile_guard = runtime.enter();
    let args = report_args(dir.path(), "json", "report.json");
    API.report_findings(&[], &args, &guard)
        .expect("JSON report");
    let measurements = keyhog_profile::take_stage_measurements();
    let (events, _, _) = runtime.take_session_typed_events();
    drop(profile_guard);
    keyhog_profile::reset();
    keyhog_sources::reset_skipped_over_max_size();

    assert_only_stage(&measurements, Stage::Reporting, 2);
    assert!(
        events
            .iter()
            .all(|event| event.event_id != EventId::CoverageGap),
        "JSON reporting must not detect coverage gaps, got {events:?}"
    );
}

/// WHY: baseline load/parse is Preprocess-stage work per the instrumentation
/// contract; exactly one span per Baseline::load call.
#[test]
fn baseline_load_records_preprocess_span() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("baseline.json");
    let baseline = API.baseline_empty();
    API.baseline_save(&baseline, &path)
        .expect("seed baseline file");
    let measurements = measure(|| {
        API.baseline_load(&path).expect("load baseline");
    });
    assert_only_stage(&measurements, Stage::Preprocess, 1);
}

/// WHY: baseline persistence (serialize + atomic write) is Reporting-stage
/// work; exactly one span per Baseline::save call.
#[test]
fn baseline_save_records_reporting_span() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("baseline.json");
    let baseline = API.baseline_empty();
    let measurements = measure(|| {
        API.baseline_save(&baseline, &path).expect("save baseline");
    });
    assert_only_stage(&measurements, Stage::Reporting, 1);
}

/// WHY: baseline entry construction with sort/dedup is ResultMerge-stage work;
/// exactly one span per Baseline::from_findings call.
#[test]
fn baseline_from_findings_records_result_merge_span() {
    let findings = [
        verified_finding(1),
        verified_finding(1),
        verified_finding(2),
    ];
    let measurements = measure(|| {
        let baseline = API.baseline_from_findings(&findings);
        assert_eq!(baseline.entries.len(), 2, "dedup behavior unchanged");
    });
    assert_only_stage(&measurements, Stage::ResultMerge, 1);
}

/// WHY: baseline merge/update entry insertion is ResultMerge-stage work;
/// exactly one span per Baseline::merge call.
#[test]
fn baseline_merge_records_result_merge_span() {
    let mut baseline = API.baseline_from_findings(&[verified_finding(1)]);
    let new_findings = [verified_finding(1), verified_finding(3)];
    let measurements = measure(|| {
        API.baseline_merge(&mut baseline, &new_findings);
    });
    assert_eq!(baseline.entries.len(), 2, "merge behavior unchanged");
    assert_only_stage(&measurements, Stage::ResultMerge, 1);
}

/// WHY: baseline membership matching is Suppression-stage work; exactly one
/// span per Baseline::contains call.
#[test]
fn baseline_contains_records_suppression_span() {
    let known = verified_finding(1);
    let baseline = API.baseline_from_findings(std::slice::from_ref(&known));
    let measurements = measure(|| {
        assert!(API.baseline_contains(&baseline, &known));
        assert!(!API.baseline_contains(&baseline, &verified_finding(9)));
    });
    assert_only_stage(&measurements, Stage::Suppression, 2);
}

/// WHY: baseline filter_new is the hot suppression filter over the finding
/// set; exactly one span per call (the cached index build stays inside it).
#[test]
fn baseline_filter_new_records_suppression_span() {
    let known = verified_finding(1);
    let baseline = API.baseline_from_findings(std::slice::from_ref(&known));
    let findings = [known, verified_finding(2)];
    let measurements = measure(|| {
        let new = API.baseline_filter_new(&baseline, &findings);
        assert_eq!(new.len(), 1, "filter_new behavior unchanged");
    });
    assert_only_stage(&measurements, Stage::Suppression, 1);
}

/// WHY: inline suppression matching/evaluation is Suppression-stage work;
/// exactly one span per filter_inline_suppressions call, and the suppressed
/// finding must still be dropped (behavior unchanged by instrumentation).
#[test]
fn inline_filter_records_suppression_span() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_path, _chunk, m) = inline_fixture(dir.path());
    let measurements = measure(|| {
        let kept = API.filter_inline_suppressions(vec![m]);
        assert!(kept.is_empty(), "keyhog:ignore must still suppress");
    });
    assert_only_stage(&measurements, Stage::Suppression, 1);
}

/// WHY: inline suppression context parsing (single-chunk attach) is
/// Suppression-stage work; exactly one span per attach call.
#[test]
fn attach_context_single_chunk_records_suppression_span() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_path, chunk, m) = inline_fixture(dir.path());
    let measurements = measure(|| {
        let mut matches = vec![m];
        API.attach_inline_suppression_context_for_test(&chunk, &mut matches);
    });
    assert_only_stage(&measurements, Stage::Suppression, 1);
}

/// WHY: inline suppression context parsing (per-chunk batch attach) is
/// Suppression-stage work; exactly one span per batch call, not per match.
#[test]
fn attach_context_per_chunk_records_suppression_span() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_path, chunk, m) = inline_fixture(dir.path());
    let measurements = measure(|| {
        let chunks = [chunk];
        let mut per_chunk = vec![vec![m]];
        API.attach_inline_suppression_context_for_chunks_for_test(&chunks, &mut per_chunk);
    });
    assert_only_stage(&measurements, Stage::Suppression, 1);
}

/// WHY: Action receipt metadata assembly (report digest) and noclobber
/// publication are Reporting-stage work; exactly one span per receipt write.
#[test]
fn action_receipt_write_records_reporting_span() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (args, receipt) = receipt_fixture(dir.path());
    let measurements = measure(|| {
        API.write_scan_receipt_for_test(&args, 0, 0, keyhog_core::ScanCompletionStatus::Success)
            .expect("write receipt");
    });
    assert_only_stage(&measurements, Stage::Reporting, 1);
    let body = std::fs::read_to_string(&receipt).expect("receipt published");
    assert_eq!(body.lines().count(), 7, "receipt shape unchanged");
}

/// WHY: every instrumented path in this slice must be a zero-cost no-op
/// without an active runtime (one relaxed atomic check, no recording). A
/// regression that records unconditionally would break the disabled fast path.
#[test]
fn instrumented_paths_are_silent_without_runtime() {
    let dir = tempfile::tempdir().expect("tempdir");
    let guard = API.scan_runtime_guard_for_test();
    keyhog_profile::reset();

    // reporting.rs paths (JSON + CSV with a live coverage gap).
    keyhog_sources::merge_skip_count_deltas(&keyhog_sources::SkipCounts {
        over_max_size: 1,
        ..Default::default()
    });
    API.report_findings(&[], &report_args(dir.path(), "json", "a.json"), &guard)
        .expect("JSON report");
    API.report_findings(&[], &report_args(dir.path(), "csv", "a.csv"), &guard)
        .expect("CSV report");
    keyhog_sources::reset_skipped_over_max_size();

    // baseline.rs paths.
    let baseline_path = dir.path().join("baseline.json");
    let baseline = API.baseline_from_findings(&[verified_finding(1)]);
    API.baseline_save(&baseline, &baseline_path)
        .expect("save baseline");
    API.baseline_load(&baseline_path).expect("load baseline");
    let mut merged = API.baseline_empty();
    API.baseline_merge(&mut merged, &[verified_finding(2)]);
    assert!(API.baseline_contains(&baseline, &verified_finding(1)));
    let _ = API.baseline_filter_new(&baseline, &[verified_finding(1)]);

    // inline_suppression.rs paths.
    let (_path, chunk, m) = inline_fixture(dir.path());
    let _ = API.filter_inline_suppressions(vec![m.clone()]);
    let mut single = vec![m.clone()];
    API.attach_inline_suppression_context_for_test(&chunk, &mut single);
    let chunks = [chunk];
    let mut per_chunk = vec![vec![m]];
    API.attach_inline_suppression_context_for_chunks_for_test(&chunks, &mut per_chunk);

    // action_report.rs path.
    let (receipt_args, _receipt) = receipt_fixture(dir.path());
    API.write_scan_receipt_for_test(
        &receipt_args,
        0,
        0,
        keyhog_core::ScanCompletionStatus::Success,
    )
    .expect("write receipt");

    let measurements = keyhog_profile::take_stage_measurements();
    keyhog_profile::reset();
    assert_eq!(
        measurements,
        Vec::new(),
        "no stage may record without an active runtime"
    );
}
