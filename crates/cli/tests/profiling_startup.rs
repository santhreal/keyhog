//! Profiling instrumentation contract tests for the CLI startup/config slice:
//! clap parsing + startup, config file load + layer merge + validation,
//! detector corpus loading/validation, allowlist rule load + suppression
//! evaluation, and the install/update/doctor/uninstall command seams that are
//! exercisable without network access.
//!
//! Every test asserts the exact Stage and exact call count recorded under an
//! active `keyhog_profile::Runtime`, and the suite closes with a silence test
//! proving the same paths record nothing without one.

use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::testing::{CliTestApi as _, API};
use keyhog_core::{MatchLocation, RawMatch, Severity};
use keyhog_profile::{Stage, StageMeasurement};
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

/// Total recorded calls for one stage across the drained measurement set.
fn stage_calls(measurements: &[StageMeasurement], stage: Stage) -> u64 {
    measurements
        .iter()
        .filter(|measurement| measurement.stage == stage)
        .map(|measurement| measurement.calls)
        .sum()
}

/// Minimal raw match fixture; `detector_id` keys rule-suppressor evaluation.
fn raw_match(detector_id: &str) -> RawMatch {
    RawMatch {
        detector_id: Arc::from(detector_id),
        detector_name: Arc::from("Test Detector"),
        service: Arc::from("test"),
        severity: Severity::High,
        credential: keyhog_core::SensitiveString::from("secret"),
        credential_hash: [0u8; 32].into(),
        companions: std::collections::HashMap::new(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from("demo.txt")),
            line: Some(1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: None,
        evidence: keyhog_core::EvidenceVerdict::review_unattributed(),
    }
}

/// Write a `.keyhog.toml` carrying one detector policy override so the merge
/// exercises discovery, load, section merges, and detector-policy validation.
fn write_detector_policy_config(dir: &Path) {
    std::fs::write(
        dir.join(".keyhog.toml"),
        "[detector.demo-detector]\nenabled = false\n",
    )
    .expect("write config fixture");
}

/// WHY: the top-level clap parse is the CLI startup seam; it must record
/// exactly one Preprocess span per parse so startup cost is attributable.
/// Locks out a regression where the span is dropped (startup becomes
/// invisible) or duplicated (parse cost double-counted).
#[test]
fn args_try_parse_from_records_one_preprocess_span() {
    let measurements = measure(|| {
        keyhog::args::try_parse_from(["keyhog", "scan", ".", "--no-config"])
            .expect("parse must succeed");
    });
    assert_eq!(
        measurements.len(),
        1,
        "parse must record exactly one stage, got {measurements:?}"
    );
    assert_eq!(stage_calls(&measurements, Stage::Preprocess), 1);
}

/// WHY: `.keyhog.toml` handling is the config merge seam: discovery walk-up,
/// file read + TOML parse, the layer-merge/validation pass, and the two
/// always-run section merges each record Preprocess, while `[detector.<id>]`
/// policy validation records BackendSelect (it shapes the selected corpus).
/// Exact counts lock out lost spans (merge work invisible) and double-wrapped
/// helpers (config cost inflated) across config.rs and config/**.
#[test]
fn config_merge_records_preprocess_and_detector_policy_backend_select() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    write_detector_policy_config(dir.path());
    let scan_path = dir.path().to_string_lossy().to_string();
    let mut args =
        ScanArgs::try_parse_from(["scan", "--path", scan_path.as_str()]).expect("parse scan args");

    let measurements = measure(|| {
        API.apply_config_file_quiet(&mut args);
    });

    assert_eq!(
        measurements.len(),
        2,
        "config merge must record Preprocess and BackendSelect only, got {measurements:?}"
    );
    // find_config_file + file load + merge/validate + [scan] section merge +
    // [allowlist] section merge.
    assert_eq!(stage_calls(&measurements, Stage::Preprocess), 5);
    // [detector.demo-detector] policy resolution.
    assert_eq!(stage_calls(&measurements, Stage::BackendSelect), 1);
}

/// WHY: `.keyhogignore.toml` rule loading compiles the declarative suppressor
/// before any scan runs; that compile must record exactly one Preprocess span
/// so policy-load cost is visible at startup. Locks out a regression where the
/// compile span is lost (or moved into the per-match hot path, which would
/// inflate Preprocess on every finding).
#[test]
fn allowlist_rule_suppressor_load_records_one_preprocess_span() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    std::fs::write(
        dir.path().join(".keyhogignore.toml"),
        "[[suppress]]\ndetector = \"demo\"\n",
    )
    .expect("write suppressor fixture");

    let measurements = measure(|| {
        keyhog::profiling_test_seams::load_rule_suppressor(Some(dir.path()))
            .expect("suppressor must load");
    });

    assert_eq!(
        measurements.len(),
        1,
        "suppressor load must record exactly one stage, got {measurements:?}"
    );
    assert_eq!(stage_calls(&measurements, Stage::Preprocess), 1);
}

/// WHY: per-finding suppression evaluation is a hot post-scan path; it must
/// record Suppression (never Preprocess) exactly once per filter pass so the
/// stage split between rule compile and rule evaluation stays honest. Also
/// pins the functional contract: a matching rule actually drops the finding.
/// Locks out a stage-mapping regression that would mislabel evaluation cost.
#[test]
fn allowlist_eval_records_one_suppression_span_and_filters() {
    let suppressor: keyhog_core::RuleSuppressor = "[[suppress]]\ndetector = \"demo\"\n"
        .parse()
        .expect("suppressor fixture parses");

    let mut kept_len = usize::MAX;
    let measurements = measure(|| {
        let kept = keyhog::profiling_test_seams::filter_rule_suppressed(
            &suppressor,
            vec![raw_match("demo")],
        );
        kept_len = kept.len();
    });

    assert_eq!(kept_len, 0, "matching rule must suppress the finding");
    assert_eq!(
        measurements.len(),
        1,
        "suppression eval must record exactly one stage, got {measurements:?}"
    );
    assert_eq!(stage_calls(&measurements, Stage::Suppression), 1);
}

/// WHY: detector corpus loading backs the `detectors`, `explain`, `diff`, and
/// `daemon start` surfaces; the shared loader must record exactly one
/// BackendSelect span per load so corpus-load cost is attributed to backend
/// selection. Locks out a regression where the load span is dropped or where
/// per-surface callers each add their own span (count would exceed one).
#[test]
fn detector_corpus_load_records_one_backend_select_span() {
    let mut loaded = 0usize;
    let measurements = measure(|| {
        loaded = keyhog::profiling_test_seams::load_detector_corpus(Path::new("detectors"))
            .expect("embedded corpus must load")
            .len();
    });

    assert!(loaded > 0, "embedded corpus must be non-empty");
    assert_eq!(
        measurements.len(),
        1,
        "detector load must record exactly one stage, got {measurements:?}"
    );
    assert_eq!(stage_calls(&measurements, Stage::BackendSelect), 1);
}

/// WHY: the doctor host probe is the check-collection phase of
/// `keyhog doctor`; it must record exactly one Preprocess span so environment
/// probing is attributable at the collect boundary. Locks out a regression
/// where the probe span is dropped or wraps the whole report (which would mix
/// collect cost with output cost).
#[test]
fn doctor_host_probe_records_one_preprocess_span() {
    let measurements = measure(|| {
        let caps = keyhog::profiling_test_seams::doctor_host_probe();
        assert!(caps.logical_cores > 0, "probe must report host cores");
    });

    assert_eq!(
        measurements.len(),
        1,
        "doctor probe must record exactly one stage, got {measurements:?}"
    );
    assert_eq!(stage_calls(&measurements, Stage::Preprocess), 1);
}

/// WHY: every instrumented path in this slice must be measurement-free when no
/// runtime is active; the disabled span path is one relaxed atomic check and
/// production runs without a profiling session must not record. Locks out a
/// regression where spans record unconditionally (silent overhead + bogus
/// counters on the legacy drain).
#[test]
fn paths_are_silent_without_runtime() {
    keyhog_profile::reset();

    keyhog::args::try_parse_from(["keyhog", "scan", ".", "--no-config"])
        .expect("parse must succeed");

    let config_dir = tempfile::TempDir::new().expect("tempdir");
    write_detector_policy_config(config_dir.path());
    let scan_path = config_dir.path().to_string_lossy().to_string();
    let mut args =
        ScanArgs::try_parse_from(["scan", "--path", scan_path.as_str()]).expect("parse scan args");
    API.apply_config_file_quiet(&mut args);

    let suppressor_dir = tempfile::TempDir::new().expect("tempdir");
    std::fs::write(
        suppressor_dir.path().join(".keyhogignore.toml"),
        "[[suppress]]\ndetector = \"demo\"\n",
    )
    .expect("write suppressor fixture");
    let suppressor =
        keyhog::profiling_test_seams::load_rule_suppressor(Some(suppressor_dir.path()))
            .expect("suppressor must load");
    let kept =
        keyhog::profiling_test_seams::filter_rule_suppressed(&suppressor, vec![raw_match("demo")]);
    assert!(kept.is_empty());

    keyhog::profiling_test_seams::load_detector_corpus(Path::new("detectors"))
        .expect("embedded corpus must load");
    keyhog::profiling_test_seams::doctor_host_probe();

    let measurements = keyhog_profile::take_stage_measurements();
    keyhog_profile::reset();
    assert_eq!(stage_calls(&measurements, Stage::Preprocess), 0);
    assert_eq!(stage_calls(&measurements, Stage::BackendSelect), 0);
    assert_eq!(stage_calls(&measurements, Stage::Suppression), 0);
    assert_eq!(stage_calls(&measurements, Stage::Reporting), 0);
    assert_eq!(stage_calls(&measurements, Stage::SourceAcquire), 0);
    assert_eq!(stage_calls(&measurements, Stage::IncrementalLookup), 0);
}
