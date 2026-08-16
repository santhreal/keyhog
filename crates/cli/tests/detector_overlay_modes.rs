use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

const AWS_KEY: &str = "AKIAQYLPMN5HFIQR7XYA";
const CUSTOM_TOKEN: &str = "demo_secret_ABCD1234";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

fn write_detector(directory: &Path, id: &str) {
    std::fs::create_dir_all(directory).expect("create detector directory");
    let toml = r#"
[detector]
id = "__DETECTOR_ID__"
name = "Custom fixture"
service = "fixture"
severity = "high"
ml = { match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }
match_confidence = { literal_prefix_weight = 0.35, context_anchor_weight = 0.20, entropy_weight = 0.20, high_entropy_partial_weight = 0.12, moderate_entropy_threshold = 3.0, moderate_entropy_weight = 0.05, low_entropy_penalty_floor = 2.0, low_entropy_min_match_length = 10, low_entropy_penalty_multiplier = 0.60, keyword_nearby_weight = 0.10, sensitive_file_weight = 0.10, companion_weight = 0.05, very_high_entropy_margin = 1.3, named_anchor_floor = 0.55, assignment_context_multiplier = 1.0, string_literal_context_multiplier = 0.9, unknown_context_multiplier = 0.8, documentation_context_multiplier = 0.3, comment_context_multiplier = 0.4, test_context_multiplier = 0.3, encrypted_context_multiplier = 0.05, soft_context_suppression_threshold = 0.5, encrypted_context_suppression_threshold = 0.8, post_match = { placeholder_multiplier = 0.05, minimum_byte_diversity = 0.1, low_diversity_multiplier = 0.1, maximum_repeat_ratio = 0.8, degenerate_run_min_length = 10, degenerate_repeat_multiplier = 0.1, fixture_path_multiplier = 0.5, ml_context_reapply_below = 0.95 } }
keywords = ["demo_secret_"]

[[detector.patterns]]
regex = "demo_secret_[A-Z0-9]{8}"
"#
    .replace("__DETECTOR_ID__", id);
    std::fs::write(directory.join("custom.toml"), toml).expect("write custom detector");
}

fn run_scan(root: &Path, extra: &[&str]) -> Output {
    let fixture = root.join("planted.txt");
    std::fs::write(
        &fixture,
        format!("AWS_ACCESS_KEY_ID={AWS_KEY}\ncustom={CUSTOM_TOKEN}\n"),
    )
    .expect("write scan fixture");
    Command::new(binary())
        .current_dir(root)
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "cpu",
            "--format",
            "json-envelope",
            "--no-entropy",
            "--no-decode",
            "--no-suppress-test-fixtures",
            "--evidence-policy",
            "paranoid",
            "--threads",
            "1",
        ])
        .args(extra)
        .arg(&fixture)
        .env("HOME", root)
        .env("XDG_DATA_HOME", root.join("xdg-data"))
        .env("XDG_CACHE_HOME", root.join("xdg-cache"))
        .env_remove("KEYHOG_BACKEND")
        .output()
        .expect("run keyhog scan")
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "parse JSON envelope: {error}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn finding_ids(report: &Value) -> Vec<&str> {
    report["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .filter_map(|finding| finding["detector_id"].as_str())
        .collect()
}

fn effective<'a>(report: &'a Value, field: &str) -> &'a str {
    report["metadata"]["resolved_scan"]["effective"][field]
        .as_str()
        .unwrap_or_else(|| panic!("missing effective field {field}: {report}"))
}

/// Regression: an explicit custom directory preserves the historical replace default and never silently merges embedded rules.
#[test]
fn custom_directory_defaults_to_replace() {
    let root = TempDir::new().expect("tempdir");
    let custom = root.path().join("custom-detectors");
    write_detector(&custom, "demo-only");

    let output = run_scan(
        root.path(),
        &["--detectors", custom.to_str().expect("utf8 path")],
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = json(&output);
    let ids = finding_ids(&report);
    assert!(ids.contains(&"demo-only"), "report={report}");
    assert!(
        !ids.contains(&"aws-access-key"),
        "replace must exclude embedded detectors: {report}"
    );
    assert_eq!(effective(&report, "detector_corpus_mode"), "replace");
    assert_eq!(effective(&report, "detector_corpus_custom_count"), "1");
    assert_eq!(effective(&report, "detector_corpus_embedded_count"), "0");
}

/// Regression: two replace scans with identical normalized detector specs must
/// retain the selected corpus schema in their reported evidence identity.
/// Otherwise a manifest-free schema-1 scan could reuse cache or autoroute
/// evidence produced under schema 3's typed evidence contract.
#[test]
fn reported_digest_distinguishes_legacy_and_current_custom_schema() {
    let legacy_root = TempDir::new().expect("legacy tempdir");
    let current_root = TempDir::new().expect("current tempdir");
    let legacy = legacy_root.path().join("custom-detectors");
    let current = current_root.path().join("custom-detectors");
    write_detector(&legacy, "demo-only");
    write_detector(&current, "demo-only");
    std::fs::write(
        current.join("corpus.toml"),
        format!(
            "schema_version = {}\n",
            keyhog_core::DETECTOR_CORPUS_SCHEMA_VERSION
        ),
    )
    .expect("write current corpus manifest");

    let legacy_output = run_scan(
        legacy_root.path(),
        &["--detectors", legacy.to_str().expect("legacy path")],
    );
    let current_output = run_scan(
        current_root.path(),
        &["--detectors", current.to_str().expect("current path")],
    );
    assert_eq!(
        legacy_output.status.code(),
        Some(1),
        "legacy stderr={}",
        String::from_utf8_lossy(&legacy_output.stderr)
    );
    assert_eq!(
        current_output.status.code(),
        Some(1),
        "current stderr={}",
        String::from_utf8_lossy(&current_output.stderr)
    );
    let legacy_report = json(&legacy_output);
    let current_report = json(&current_output);
    let legacy_cached_output = run_scan(
        legacy_root.path(),
        &["--detectors", legacy.to_str().expect("legacy path")],
    );
    let current_cached_output = run_scan(
        current_root.path(),
        &["--detectors", current.to_str().expect("current path")],
    );
    let legacy_cached_report = json(&legacy_cached_output);
    let current_cached_report = json(&current_cached_output);
    assert_eq!(
        effective(&legacy_report, "detector_corpus_digest"),
        effective(&legacy_cached_report, "detector_corpus_digest"),
        "legacy schema identity must survive a detector parse-cache hit"
    );
    assert_eq!(
        effective(&current_report, "detector_corpus_digest"),
        effective(&current_cached_report, "detector_corpus_digest"),
        "current schema identity must survive a detector parse-cache hit"
    );
    assert_eq!(effective(&legacy_report, "detector_corpus_mode"), "replace");
    assert_eq!(
        effective(&current_report, "detector_corpus_mode"),
        "replace"
    );
    assert_eq!(finding_ids(&legacy_report), finding_ids(&current_report));
    assert_ne!(
        effective(&legacy_report, "detector_corpus_digest"),
        effective(&current_report, "detector_corpus_digest"),
        "equal specs under schema 1 and schema 3 need distinct reported identities"
    );
}

/// Regression: overlay is an explicit opt-in that reports both embedded and custom findings with effective-corpus identity.
#[test]
fn explicit_overlay_composes_and_reports_json_provenance() {
    let root = TempDir::new().expect("tempdir");
    let custom = root.path().join("custom-detectors");
    write_detector(&custom, "demo-only");

    let output = run_scan(
        root.path(),
        &[
            "--detectors",
            custom.to_str().expect("utf8 path"),
            "--detectors-mode",
            "overlay",
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = json(&output);
    let ids = finding_ids(&report);
    assert!(ids.contains(&"demo-only"), "report={report}");
    assert!(
        ids.contains(&"aws-access-key"),
        "overlay must retain embedded detectors: {report}"
    );
    assert_eq!(effective(&report, "detector_corpus_mode"), "overlay");
    assert!(effective(&report, "detector_corpus_source").starts_with("embedded+"));
    let digest = effective(&report, "detector_corpus_digest");
    assert_eq!(digest.len(), 64, "effective BLAKE3 digest: {digest}");
}

/// Regression: an overlay cannot shadow an embedded detector ID and must fail before scanning.
#[test]
fn overlay_rejects_embedded_id_collision() {
    let root = TempDir::new().expect("tempdir");
    let custom = root.path().join("custom-detectors");
    write_detector(&custom, "aws-access-key");

    let output = run_scan(
        root.path(),
        &[
            "--detectors",
            custom.to_str().expect("utf8 path"),
            "--detectors-mode",
            "overlay",
        ],
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("overlay collides") && stderr.contains("aws-access-key"),
        "stderr={stderr}"
    );
}

/// Regression: malformed custom TOML is a hard error in composition modes, never a fallback to embedded detectors.
#[test]
fn malformed_custom_corpus_fails_closed() {
    let root = TempDir::new().expect("tempdir");
    let custom = root.path().join("custom-detectors");
    std::fs::create_dir_all(&custom).expect("create detector directory");
    std::fs::write(custom.join("broken.toml"), "[detector\nid = ???")
        .expect("write malformed detector");

    let output = run_scan(
        root.path(),
        &[
            "--detectors",
            custom.to_str().expect("utf8 path"),
            "--detectors-mode",
            "overlay",
        ],
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("broken.toml") || stderr.contains("parse"),
        "stderr={stderr}"
    );
    assert!(
        output.stdout.is_empty(),
        "failed scan must not emit a clean report"
    );
}

/// Regression: omitting custom corpus options uses only embedded detectors and reports that provenance.
#[test]
fn default_scan_uses_embedded_corpus() {
    let root = TempDir::new().expect("tempdir");
    let output = run_scan(root.path(), &[]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = json(&output);
    assert!(
        finding_ids(&report).contains(&"aws-access-key"),
        "report={report}"
    );
    assert_eq!(effective(&report, "detector_corpus_mode"), "embedded");
    assert_eq!(effective(&report, "detector_corpus_source"), "embedded");
    assert_eq!(effective(&report, "detector_corpus_custom_count"), "0");
}

/// Regression: a composition mode without an explicit custom path must not merge an auto-discovered directory.
#[test]
fn detector_mode_without_custom_path_is_rejected() {
    let root = TempDir::new().expect("tempdir");
    let output = run_scan(root.path(), &["--detectors-mode", "overlay"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--detectors-mode requires a custom corpus"),
        "stderr={stderr}"
    );
    assert!(
        output.stdout.is_empty(),
        "ambiguous scan must not emit a report"
    );
}

/// Regression: TOML supplies detector path and overlay mode, while an explicit CLI mode wins after that merge.
#[test]
fn toml_then_cli_mode_precedence_is_explicit() {
    let root = TempDir::new().expect("tempdir");
    let custom = root.path().join("custom-detectors");
    write_detector(&custom, "demo-only");
    std::fs::write(
        root.path().join(".keyhog.toml"),
        "detectors = \"custom-detectors\"\ndetectors_mode = \"overlay\"\n",
    )
    .expect("write config");

    let from_toml = run_scan(root.path(), &[]);
    assert_eq!(
        from_toml.status.code(),
        Some(1),
        "stderr={}",
        String::from_utf8_lossy(&from_toml.stderr)
    );
    let toml_report = json(&from_toml);
    assert_eq!(effective(&toml_report, "detector_corpus_mode"), "overlay");
    assert!(finding_ids(&toml_report).contains(&"aws-access-key"));

    let cli_override = run_scan(root.path(), &["--detectors-mode", "replace"]);
    assert_eq!(
        cli_override.status.code(),
        Some(1),
        "stderr={}",
        String::from_utf8_lossy(&cli_override.stderr)
    );
    let cli_report = json(&cli_override);
    assert_eq!(effective(&cli_report, "detector_corpus_mode"), "replace");
    assert!(finding_ids(&cli_report).contains(&"demo-only"));
    assert!(!finding_ids(&cli_report).contains(&"aws-access-key"));
}
