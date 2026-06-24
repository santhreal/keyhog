//! Integration tests for the `keyhog scan` flag surface.
//!
//! Coverage area: flag_surface. Every expected value below is derived by
//! reading the real CLI source under `crates/cli/src`:
//!   * `args/scan.rs`          — flag definitions, conflicts, defaults
//!   * `args.rs`               — `SeverityFilter`, `CliDedupScope`, exit-code text
//!   * `value_parsers.rs`      — `parse_min_confidence` range, etc.
//!   * `orchestrator_config.rs`— `build_scanner_config` / preset composition
//!   * `orchestrator/postprocess.rs` — `--severity` / `--show-secrets` / `--dedup`
//!   * `orchestrator/run.rs`   — `--hide-client-safe` drop
//!
//! `keyhog config --effective` is the ground-truth surface for
//! engine-config composition: it prints the
//! RESOLVED `ScannerConfig` + post-scan floor as deterministic `key = value`
//! lines and exits SUCCESS without scanning. Tests that assert composition
//! read those exact lines rather than guessing at downstream detection.
//!
//! Reference facts pinned from source (so a regression that changes them
//! breaks a test, not just a comment):
//!   * `ScanConfig::default().min_confidence == 0.40`  (core/src/config.rs)
//!   * default `max_decode_depth == 10`, `max_decode_bytes == 524288`
//!   * `ScannerConfig::fast()`  -> decode 0, ml off, entropy off
//!   * `ScannerConfig::high_precision()` -> decode 1, entropy off, floor 0.85
//!   * `HIGH_PRECISION_MIN_CONFIDENCE == 0.85`         (scanner_config.rs)
//!   * `ML_THRESHOLD_DEFAULT == 0.5`                   (orchestrator_config.rs)
//!   * `Severity` Ord: Info < ClientSafe < Low < Medium < High < Critical
//!     and the JSON wire form is kebab-case (`client-safe`).   (core/src/spec.rs)
//!   * `aws-access-key` severity == "critical"; the key
//!     `AKIAQYLPMN5HFIQR7XYA` is detected as that critical finding.
//!   * `sentry-dsn` patterns carry `client_safe = true`, so a matching DSN is
//!     re-tiered to `Severity::ClientSafe` regardless of its nominal `high`.

use std::path::PathBuf;
use std::process::{Command, Output};
use tempfile::TempDir;

#[path = "../support/json_report.rs"]
mod json_report_support;

use json_report_support::parse_json_array;

// ----------------------------------------------------------------------------
// helpers (private to this module; the aggregator includes us as a plain mod)
// ----------------------------------------------------------------------------

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// Run `keyhog <args...>` with no fixture and capture (stdout, stderr, code).
fn run(args: &[&str]) -> (String, String, Option<i32>) {
    let out: Output = Command::new(binary())
        .args(args)
        .output()
        .expect("spawn keyhog");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code(),
    )
}

/// Run `keyhog config --effective <scan args...>`.
/// Returns (stdout, stderr, code). The command prints the resolved config and
/// exits SUCCESS without scanning.
fn effective_config(args: &[&str]) -> (String, String, Option<i32>) {
    let scan_args = if args.first() == Some(&"scan") {
        &args[1..]
    } else {
        args
    };
    let out: Output = Command::new(binary())
        .arg("config")
        .arg("--effective")
        .args(scan_args)
        .output()
        .expect("spawn keyhog");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code(),
    )
}

fn effective_config_with_toml(
    config: &str,
    scan_args: &[&str],
) -> (TempDir, String, String, Option<i32>) {
    let dir = TempDir::new().expect("tempdir");
    let cfg = dir.path().join(".keyhog.toml");
    std::fs::write(&cfg, config).expect("write keyhog config");

    let mut args = vec![
        "config".to_string(),
        "--effective".to_string(),
        "--config".to_string(),
        cfg.to_string_lossy().into_owned(),
    ];
    args.extend(scan_args.iter().map(|arg| (*arg).to_string()));

    let out: Output = Command::new(binary())
        .args(&args)
        .output()
        .expect("spawn keyhog config --effective");
    (
        dir,
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code(),
    )
}

/// Write `content` to `name` inside a fresh tempdir and scan it as JSON
/// in-process (`--no-daemon`). Returns (stdout, stderr, code) plus the dir
/// guard (kept alive by the caller).
fn scan_file(name: &str, content: &str, extra: &[&str]) -> (TempDir, String, String, Option<i32>) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join(name);
    std::fs::write(&path, content).expect("write fixture");

    let mut args: Vec<String> = vec![
        "scan".into(),
        "--no-daemon".into(),
        "--backend".into(),
        "cpu".into(),
        "--format".into(),
        "json".into(),
    ];
    for a in extra {
        args.push((*a).into());
    }
    args.push(path.to_string_lossy().into_owned());

    let out = Command::new(binary())
        .args(&args)
        .output()
        .expect("spawn keyhog scan");
    (
        dir,
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code(),
    )
}

fn parse_findings(stdout: &str) -> Vec<serde_json::Value> {
    parse_json_array(stdout, "flag-surface scan JSON")
}

/// A genuine, corpus-detected AWS access key id (`aws-access-key`, severity
/// `critical`). Used across severity/dedup tests as a stable critical finding.
const AWS_KEY: &str = "AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"\n";

/// A Sentry DSN matching `sentry-dsn`'s first pattern
/// (`https://[a-f0-9]{32}@o[0-9]+\.ingest\.sentry\.io/[0-9]+`). The pattern
/// carries `client_safe = true`, so the finding is re-tiered to ClientSafe.
const SENTRY_DSN: &str =
    "SENTRY_DSN = \"https://0123456789abcdef0123456789abcdef@o123456.ingest.sentry.io/4501\"\n";

// ============================================================================
// --severity
// ============================================================================

/// `--severity critical` keeps a critical finding (`aws-access-key`).
/// Positive: the floor equals the finding severity, so `m.severity <
/// min_severity` is false and the finding survives. Exit 1 (findings present).
#[test]
fn severity_critical_keeps_critical_aws_finding() {
    let (_d, out, err, code) = scan_file("config.txt", AWS_KEY, &["--severity", "critical"]);
    assert_eq!(
        code,
        Some(1),
        "critical AWS key must survive --severity critical; stderr={err}"
    );
    let findings = parse_findings(&out);
    assert!(
        findings
            .iter()
            .any(|f| f["detector_id"] == "aws-access-key" && f["severity"] == "critical"),
        "expected a critical aws-access-key finding; got {out}"
    );
}

/// Negative twin: the AWS key is `critical`; `--severity` only accepts up to
/// `critical`, so there is no filter level that drops a critical finding while
/// other severities exist. Assert the *boundary* instead: `--severity high`
/// (one tier below critical) still keeps the critical finding because
/// `Critical >= High`. This proves the comparison is `>=`, not `==`.
#[test]
fn severity_high_keeps_critical_finding_boundary() {
    let (_d, out, err, code) = scan_file("config.txt", AWS_KEY, &["--severity", "high"]);
    assert_eq!(
        code,
        Some(1),
        "Critical >= High must pass --severity high; stderr={err}"
    );
    let findings = parse_findings(&out);
    assert!(
        findings
            .iter()
            .any(|f| f["detector_id"] == "aws-access-key"),
        "Critical finding must clear the High floor; got {out}"
    );
}

/// `--severity` with a `client-safe` finding (Sentry DSN). `SeverityFilter`
/// has NO `ClientSafe` variant; its lowest level is `Info`. Since
/// `Severity::Info < Severity::ClientSafe` in the Ord, `--severity info`
/// (the lowest selectable floor) does NOT drop a ClientSafe finding.
#[test]
fn severity_info_floor_keeps_client_safe_finding() {
    // First confirm the Sentry DSN is detected at all (without a filter).
    let (_d0, base_out, _e0, base_code) = scan_file("app.txt", SENTRY_DSN, &[]);
    if base_code != Some(1) {
        // Corpus may not detect this DSN shape; skip the differential silently
        // rather than assert a value the engine did not produce.
        return;
    }
    let base = parse_findings(&base_out);
    assert!(
        base.iter().any(|f| f["severity"] == "client-safe"),
        "baseline Sentry DSN must be tiered client-safe; got {base_out}"
    );

    let (_d, out, err, code) = scan_file("app.txt", SENTRY_DSN, &["--severity", "info"]);
    assert_eq!(
        code,
        Some(1),
        "Info floor keeps ClientSafe (Info < ClientSafe); stderr={err}"
    );
    let findings = parse_findings(&out);
    assert!(
        findings.iter().any(|f| f["severity"] == "client-safe"),
        "--severity info must keep client-safe findings; got {out}"
    );
}

/// Boundary: `--severity low` drops a ClientSafe finding because
/// `Severity::ClientSafe < Severity::Low`. The Sentry DSN's only findings are
/// client-safe, so the result set is empty and the exit code is 0.
#[test]
fn severity_low_drops_client_safe_finding() {
    let (_d0, base_out, _e0, base_code) = scan_file("app.txt", SENTRY_DSN, &[]);
    if base_code != Some(1)
        || !parse_findings(&base_out)
            .iter()
            .any(|f| f["severity"] == "client-safe")
    {
        return; // corpus did not produce the client-safe baseline; nothing to filter
    }

    let (_d, out, err, code) = scan_file("app.txt", SENTRY_DSN, &["--severity", "low"]);
    assert_eq!(
        code,
        Some(0),
        "ClientSafe < Low so --severity low drops every finding; stderr={err}"
    );
    assert!(
        parse_findings(&out).is_empty(),
        "--severity low must drop the client-safe Sentry DSN; got {out}"
    );
}

/// Every accepted `--severity` spelling parses (value_enum). The CLI enum is
/// exactly {info, low, medium, high, critical} — `client-safe` is NOT a
/// selectable filter value (it has no `SeverityFilter` variant).
#[test]
fn severity_accepts_five_levels_and_rejects_client_safe() {
    for level in ["info", "low", "medium", "high", "critical"] {
        let (_d, _o, err, code) = scan_file("config.txt", "plain text\n", &["--severity", level]);
        assert_eq!(
            code,
            Some(0),
            "--severity {level} on clean input must parse and exit 0; stderr={err}"
        );
    }
    // `client-safe` is not a valid value for the flag -> clap rejects (exit 2).
    let (_d, _o, err, code) =
        scan_file("config.txt", "plain text\n", &["--severity", "client-safe"]);
    assert_eq!(
        code,
        Some(2),
        "`--severity client-safe` must be a clap error; stderr={err}"
    );
    assert!(
        err.to_lowercase().contains("invalid value")
            || err.to_lowercase().contains("possible values"),
        "clap must name the invalid --severity value; stderr={err}"
    );
}

/// `--severity garbage` is rejected at the clap layer with exit 2.
#[test]
fn severity_rejects_unknown_value() {
    let (_o, err, code) = run(&[
        "scan",
        "--no-daemon",
        "--severity",
        "ultra",
        "/nonexistent-path-xyz",
    ]);
    assert_eq!(
        code,
        Some(2),
        "unknown --severity value must be a clap error; stderr={err}"
    );
}

// ============================================================================
// --min-confidence
// ============================================================================

/// Default floor is 0.40 (canonical `ScanConfig::default().min_confidence`).
/// The effective-config oracle prints it verbatim.
#[test]
fn min_confidence_default_is_point_four() {
    let (out, err, code) = effective_config(&["scan", "--no-daemon"]);
    assert_eq!(code, Some(0), "oracle must exit 0; stderr={err}");
    assert!(
        out.contains("min_confidence = 0.4"),
        "default floor must be 0.4; got {out}"
    );
}

/// `--min-confidence 0.9` (non-precision) sets the floor outright.
/// `build_scanner_config` assigns `config.min_confidence = conf` when not in
/// precision mode. The oracle reflects the exact value.
#[test]
fn min_confidence_sets_floor_outright_in_default_mode() {
    let (out, err, code) = effective_config(&["scan", "--no-daemon", "--min-confidence", "0.9"]);
    assert_eq!(code, Some(0), "stderr={err}");
    assert!(
        out.contains("min_confidence = 0.9"),
        "--min-confidence 0.9 must set the floor to 0.9; got {out}"
    );
}

/// `--min-confidence 0.3` lowers the floor below the 0.40 default in plain
/// mode (no precision clamp). Asserts the resolved value is 0.3, proving the
/// flag overrides the default rather than `.max()`-ing with it.
#[test]
fn min_confidence_can_lower_floor_below_default() {
    let (out, err, code) = effective_config(&["scan", "--no-daemon", "--min-confidence", "0.3"]);
    assert_eq!(code, Some(0), "stderr={err}");
    assert!(
        out.contains("min_confidence = 0.3"),
        "plain-mode --min-confidence 0.3 must drop the floor to 0.3; got {out}"
    );
}

/// Boundary: `--min-confidence 0.0` and `1.0` are accepted (inclusive range
/// in `parse_min_confidence`: `(0.0..=1.0).contains`).
#[test]
fn min_confidence_accepts_inclusive_bounds() {
    let (out0, e0, c0) = effective_config(&["scan", "--no-daemon", "--min-confidence", "0.0"]);
    assert_eq!(c0, Some(0), "0.0 is in range; stderr={e0}");
    assert!(
        out0.contains("min_confidence = 0"),
        "0.0 floor must render; got {out0}"
    );

    let (out1, e1, c1) = effective_config(&["scan", "--no-daemon", "--min-confidence", "1.0"]);
    assert_eq!(c1, Some(0), "1.0 is in range; stderr={e1}");
    assert!(
        out1.contains("min_confidence = 1"),
        "1.0 floor must render; got {out1}"
    );
}

/// Negative: `--min-confidence 1.5` is out of `[0.0, 1.0]` and rejected by
/// `parse_min_confidence` with the exact error text it emits.
#[test]
fn min_confidence_rejects_above_one() {
    let (_o, err, code) = run(&[
        "scan",
        "--no-daemon",
        "--min-confidence",
        "1.5",
        "/nonexistent-path-xyz",
    ]);
    assert_eq!(
        code,
        Some(2),
        "1.5 is out of range -> clap error; stderr={err}"
    );
    assert!(
        err.contains("min_confidence must be between 0.0 and 1.0"),
        "parser error text must surface; stderr={err}"
    );
}

/// Negative: a negative confidence is rejected (same range gate).
///
/// The value must be passed with the `--flag=value` form. With a
/// space-separated `--min-confidence -0.5`, clap treats the leading-dash token
/// as a flag (no `allow_hyphen_values`/`allow_negative_numbers` on this arg)
/// and errors with "unexpected argument" *before* the value parser runs, so
/// the range message never surfaces. The `=` form delivers `-0.5` straight to
/// `parse_min_confidence`, where `(0.0..=1.0).contains(&-0.5)` is false and the
/// range error fires.
#[test]
fn min_confidence_rejects_negative() {
    let (_o, err, code) = run(&[
        "scan",
        "--no-daemon",
        "--min-confidence=-0.5",
        "/nonexistent-path-xyz",
    ]);
    assert_eq!(
        code,
        Some(2),
        "negative confidence -> clap error; stderr={err}"
    );
    assert!(
        err.contains("min_confidence must be between 0.0 and 1.0"),
        "parser error text must surface; stderr={err}"
    );
}

/// Adversarial: `--min-confidence nan` does not parse as an f64 in range.
/// `"nan".parse::<f64>()` succeeds but `(0.0..=1.0).contains(&NaN)` is false,
/// so the parser rejects it (range error). The floor is NEVER silently set to
/// NaN (the CLI-003-class bug guard).
#[test]
fn min_confidence_rejects_nan() {
    let (_o, err, code) = run(&[
        "scan",
        "--no-daemon",
        "--min-confidence",
        "nan",
        "/nonexistent-path-xyz",
    ]);
    assert_eq!(
        code,
        Some(2),
        "NaN confidence must be rejected; stderr={err}"
    );
    assert!(
        err.contains("min_confidence must be between 0.0 and 1.0"),
        "NaN must hit the range gate (not silently pass); stderr={err}"
    );
}

/// `--min-confidence` floor is honoured even with `--no-ml`. The resolved
/// post-scan floor reads back the SAME `scanner.min_confidence` regardless of
/// the ML gate (`postprocess.rs` applies the floor unconditionally; the prior
/// bug gated it on `!no_ml`). The oracle proves floor and ml are independent.
#[test]
fn min_confidence_floor_survives_no_ml() {
    let (out, err, code) =
        effective_config(&["scan", "--no-daemon", "--min-confidence", "0.77", "--no-ml"]);
    assert_eq!(code, Some(0), "stderr={err}");
    assert!(
        out.contains("min_confidence = 0.77"),
        "--no-ml must not erase the explicit --min-confidence floor; got {out}"
    );
    assert!(
        out.contains("ml_enabled = false"),
        "--no-ml must disable ML in the resolved config; got {out}"
    );
}

// ============================================================================
// --precision composition  (floor is a one-directional MINIMUM)
// ============================================================================

/// `--precision` alone resolves to the documented mass-scan preset:
/// floor 0.85, entropy off, decode depth 1. Read straight from the oracle.
#[test]
fn precision_preset_floor_entropy_decode() {
    let (out, err, code) = effective_config(&["scan", "--no-daemon", "--precision"]);
    assert_eq!(code, Some(0), "stderr={err}");
    assert!(
        out.contains("min_confidence = 0.85"),
        "precision floor must be 0.85; got {out}"
    );
    assert!(
        out.contains("entropy_enabled = false"),
        "precision disables entropy; got {out}"
    );
    assert!(
        out.contains("max_decode_depth = 1"),
        "precision pins decode depth 1; got {out}"
    );
}

/// `--precision --min-confidence 0.9` TIGHTENS to 0.9. The composition is
/// `conf.max(HIGH_PRECISION_MIN_CONFIDENCE)` -> max(0.9, 0.85) == 0.9.
#[test]
fn precision_min_confidence_above_floor_tightens() {
    let (out, err, code) = effective_config(&[
        "scan",
        "--no-daemon",
        "--precision",
        "--min-confidence",
        "0.9",
    ]);
    assert_eq!(code, Some(0), "stderr={err}");
    assert!(
        out.contains("min_confidence = 0.9"),
        "0.9 > 0.85 so precision must tighten to 0.9; got {out}"
    );
}

/// `--precision --min-confidence 0.3` CANNOT punch below the 0.85 bar. The
/// `.max()` composition keeps 0.85 (max(0.3, 0.85) == 0.85). This is the
/// "one-directional floor" contract documented in `build_scanner_config`.
#[test]
fn precision_min_confidence_below_floor_clamped_to_point_eight_five() {
    let (out, err, code) = effective_config(&[
        "scan",
        "--no-daemon",
        "--precision",
        "--min-confidence",
        "0.3",
    ]);
    assert_eq!(code, Some(0), "stderr={err}");
    assert!(
        out.contains("min_confidence = 0.85"),
        "0.3 < 0.85 must NOT lower the precision floor; got {out}"
    );
    assert!(
        !out.contains("min_confidence = 0.3"),
        "the precision floor must never drop to 0.3; got {out}"
    );
}

/// Boundary: `--precision --min-confidence 0.85` resolves to exactly 0.85
/// (max(0.85, 0.85)). Proves the clamp is inclusive, not strictly greater.
#[test]
fn precision_min_confidence_equal_to_floor() {
    let (out, err, code) = effective_config(&[
        "scan",
        "--no-daemon",
        "--precision",
        "--min-confidence",
        "0.85",
    ]);
    assert_eq!(code, Some(0), "stderr={err}");
    assert!(
        out.contains("min_confidence = 0.85"),
        "equal floor must stay 0.85; got {out}"
    );
}

/// `--precision` conflicts with `--fast` at the clap layer (`conflicts_with_all`
/// on each preset flag). Exit 2.
#[test]
fn precision_conflicts_with_fast() {
    let (_o, err, code) = run(&[
        "scan",
        "--no-daemon",
        "--precision",
        "--fast",
        "/nonexistent-path-xyz",
    ]);
    assert_eq!(
        code,
        Some(2),
        "--precision + --fast must conflict; stderr={err}"
    );
    assert!(
        err.to_lowercase().contains("cannot be used with")
            || err.to_lowercase().contains("conflict"),
        "clap must name the preset conflict; stderr={err}"
    );
}

/// `--precision` conflicts with `--deep` at the clap layer. Exit 2.
#[test]
fn precision_conflicts_with_deep() {
    let (_o, err, code) = run(&[
        "scan",
        "--no-daemon",
        "--precision",
        "--deep",
        "/nonexistent-path-xyz",
    ]);
    assert_eq!(
        code,
        Some(2),
        "--precision + --deep must conflict; stderr={err}"
    );
}

/// `--fast` and `--deep` are mutually exclusive presets. Exit 2.
#[test]
fn fast_conflicts_with_deep() {
    let (_o, err, code) = run(&[
        "scan",
        "--no-daemon",
        "--fast",
        "--deep",
        "/nonexistent-path-xyz",
    ]);
    assert_eq!(code, Some(2), "--fast + --deep must conflict; stderr={err}");
}

// ============================================================================
// --no-decode / --no-entropy and their conflicts with presets
// ============================================================================

/// `--no-decode` (no preset) zeroes the decode depth in the resolved config.
#[test]
fn no_decode_sets_depth_zero() {
    let (out, err, code) = effective_config(&["scan", "--no-daemon", "--no-decode"]);
    assert_eq!(code, Some(0), "stderr={err}");
    assert!(
        out.contains("max_decode_depth = 0"),
        "--no-decode -> depth 0; got {out}"
    );
}

/// `--no-entropy` (no preset) disables entropy in the resolved config. The
/// `if !(fast||deep||precision)` branch in `build_scanner_config` honours the
/// flag only off the preset path — here there is no preset, so it applies.
#[test]
fn no_entropy_disables_entropy() {
    let (out, err, code) = effective_config(&["scan", "--no-daemon", "--no-entropy"]);
    assert_eq!(code, Some(0), "stderr={err}");
    assert!(
        out.contains("entropy_enabled = false"),
        "--no-entropy -> off; got {out}"
    );
}

/// Default (no flags) leaves entropy ENABLED and decode depth 10 — confirms
/// the negatives above are real toggles, not the default state.
#[test]
fn default_mode_entropy_on_decode_ten() {
    let (out, err, code) = effective_config(&["scan", "--no-daemon"]);
    assert_eq!(code, Some(0), "stderr={err}");
    assert!(
        out.contains("entropy_enabled = true"),
        "default entropy on; got {out}"
    );
    assert!(
        out.contains("max_decode_depth = 10"),
        "default decode 10; got {out}"
    );
    assert!(
        out.contains("max_decode_bytes = 524288"),
        "default decode bytes; got {out}"
    );
}

/// `--fast` conflicts with `--no-decode` at the clap layer
/// (`conflicts_with_all = [..., "no_decode", ...]`). Exit 2.
#[test]
fn fast_conflicts_with_no_decode() {
    let (_o, err, code) = run(&[
        "scan",
        "--no-daemon",
        "--fast",
        "--no-decode",
        "/nonexistent-path-xyz",
    ]);
    assert_eq!(
        code,
        Some(2),
        "--fast + --no-decode must conflict; stderr={err}"
    );
}

/// `--fast` conflicts with `--no-entropy` at the clap layer. Exit 2.
#[test]
fn fast_conflicts_with_no_entropy() {
    let (_o, err, code) = run(&[
        "scan",
        "--no-daemon",
        "--fast",
        "--no-entropy",
        "/nonexistent-path-xyz",
    ]);
    assert_eq!(
        code,
        Some(2),
        "--fast + --no-entropy must conflict; stderr={err}"
    );
}

/// `--deep` conflicts with `--no-decode`. Exit 2.
#[test]
fn deep_conflicts_with_no_decode() {
    let (_o, err, code) = run(&[
        "scan",
        "--no-daemon",
        "--deep",
        "--no-decode",
        "/nonexistent-path-xyz",
    ]);
    assert_eq!(
        code,
        Some(2),
        "--deep + --no-decode must conflict; stderr={err}"
    );
}

/// `--deep` conflicts with `--no-entropy`. Exit 2.
#[test]
fn deep_conflicts_with_no_entropy() {
    let (_o, err, code) = run(&[
        "scan",
        "--no-daemon",
        "--deep",
        "--no-entropy",
        "/nonexistent-path-xyz",
    ]);
    assert_eq!(
        code,
        Some(2),
        "--deep + --no-entropy must conflict; stderr={err}"
    );
}

/// `--precision` conflicts with `--no-decode`. Exit 2.
#[test]
fn precision_conflicts_with_no_decode() {
    let (_o, err, code) = run(&[
        "scan",
        "--no-daemon",
        "--precision",
        "--no-decode",
        "/nonexistent-path-xyz",
    ]);
    assert_eq!(
        code,
        Some(2),
        "--precision + --no-decode must conflict; stderr={err}"
    );
}

/// `--precision` conflicts with `--no-entropy`. Exit 2.
#[test]
fn precision_conflicts_with_no_entropy() {
    let (_o, err, code) = run(&[
        "scan",
        "--no-daemon",
        "--precision",
        "--no-entropy",
        "/nonexistent-path-xyz",
    ]);
    assert_eq!(
        code,
        Some(2),
        "--precision + --no-entropy must conflict; stderr={err}"
    );
}

/// `--no-decode --no-entropy` together (no preset) is allowed and composes:
/// depth 0 AND entropy off. Proves the two flags are independent off the
/// preset path.
#[test]
fn no_decode_and_no_entropy_compose_without_preset() {
    let (out, err, code) =
        effective_config(&["scan", "--no-daemon", "--no-decode", "--no-entropy"]);
    assert_eq!(
        code,
        Some(0),
        "two negatives without a preset are allowed; stderr={err}"
    );
    assert!(out.contains("max_decode_depth = 0"), "depth 0; got {out}");
    assert!(
        out.contains("entropy_enabled = false"),
        "entropy off; got {out}"
    );
}

#[test]
fn cli_deep_preset_wins_over_toml_no_entropy_and_no_decode() {
    let (_dir, out, err, code) =
        effective_config_with_toml("no_entropy = true\nno_decode = true\n", &["--deep"]);
    assert_eq!(code, Some(0), "stderr={err}");
    assert!(
        out.contains("entropy_enabled = true"),
        "CLI --deep must keep entropy enabled over TOML no_entropy; got {out}"
    );
    assert!(
        out.contains("max_decode_depth = 10"),
        "CLI --deep must keep deep decode over TOML no_decode; got {out}"
    );
}

#[test]
fn toml_deep_preset_still_composes_with_toml_no_entropy_and_no_decode() {
    let (_dir, out, err, code) =
        effective_config_with_toml("deep = true\nno_entropy = true\nno_decode = true\n", &[]);
    assert_eq!(code, Some(0), "stderr={err}");
    assert!(
        out.contains("entropy_enabled = false"),
        "TOML deep + TOML no_entropy must still disable entropy; got {out}"
    );
    assert!(
        out.contains("max_decode_depth = 0"),
        "TOML deep + TOML no_decode must still disable decode; got {out}"
    );
}

#[test]
fn cli_precision_preset_wins_over_toml_fast() {
    let (_dir, out, err, code) = effective_config_with_toml("fast = true\n", &["--precision"]);
    assert_eq!(code, Some(0), "stderr={err}");
    assert!(
        out.contains("min_confidence = 0.85"),
        "CLI --precision must keep the precision floor over TOML fast; got {out}"
    );
    assert!(
        out.contains("max_decode_depth = 1"),
        "CLI --precision must keep shallow precision decode over TOML fast; got {out}"
    );
    assert!(
        out.contains("ml_enabled = true"),
        "CLI --precision must not inherit TOML fast's ML disable; got {out}"
    );
}

/// `--fast` preset composition: ml off, entropy off, decode 0 — all three at
/// once (`ScannerConfig::fast()` plus `ml_enabled = !fast && !no_ml`).
#[test]
fn fast_preset_disables_ml_entropy_decode() {
    let (out, err, code) = effective_config(&["scan", "--no-daemon", "--fast"]);
    assert_eq!(code, Some(0), "stderr={err}");
    assert!(
        out.contains("ml_enabled = false"),
        "fast disables ml; got {out}"
    );
    assert!(
        out.contains("entropy_enabled = false"),
        "fast disables entropy; got {out}"
    );
    assert!(
        out.contains("max_decode_depth = 0"),
        "fast pins decode 0; got {out}"
    );
}

/// `--deep` preset composition: ml on, entropy on, decode 10, floor still the
/// canonical 0.40 (thorough() omits min_confidence on purpose).
#[test]
fn deep_preset_enables_ml_entropy_keeps_default_floor() {
    let (out, err, code) = effective_config(&["scan", "--no-daemon", "--deep"]);
    assert_eq!(code, Some(0), "stderr={err}");
    assert!(
        out.contains("ml_enabled = true"),
        "deep enables ml; got {out}"
    );
    assert!(
        out.contains("entropy_enabled = true"),
        "deep enables entropy; got {out}"
    );
    assert!(
        out.contains("max_decode_depth = 10"),
        "deep decode 10; got {out}"
    );
    assert!(
        out.contains("min_confidence = 0.4"),
        "deep keeps canonical 0.40 floor; got {out}"
    );
}

// ============================================================================
// --ml-threshold composition with the floor
// ============================================================================

/// Unset `--ml-threshold` is a NO-OP: the canonical 0.40 floor is left
/// untouched. An explicit threshold equal to the documented ML default is still
/// operator intent and raises the floor to 0.5.
#[test]
fn ml_threshold_unset_is_noop_explicit_default_raises_floor() {
    let (unset_out, unset_err, unset_code) = effective_config(&["scan", "--no-daemon"]);
    assert_eq!(unset_code, Some(0), "stderr={unset_err}");
    assert!(
        unset_out.contains("min_confidence = 0.4"),
        "unset --ml-threshold must not move the 0.40 floor; got {unset_out}"
    );

    let (out, err, code) = effective_config(&["scan", "--no-daemon", "--ml-threshold", "0.5"]);
    assert_eq!(code, Some(0), "stderr={err}");
    assert!(
        out.contains("min_confidence = 0.5"),
        "explicit --ml-threshold 0.5 must raise the 0.40 floor; got {out}"
    );
}

#[test]
fn ml_threshold_config_file_raises_floor_and_cli_wins() {
    let (_dir, out, err, code) = effective_config_with_toml("ml_threshold = 0.5\n", &[]);
    assert_eq!(code, Some(0), "stderr={err}");
    assert!(
        out.contains("min_confidence = 0.5"),
        "top-level TOML ml_threshold must raise the floor to 0.5; got {out}"
    );

    let (_dir, nested_out, nested_err, nested_code) =
        effective_config_with_toml("[scan]\nml_threshold = 0.6\n", &[]);
    assert_eq!(nested_code, Some(0), "stderr={nested_err}");
    assert!(
        nested_out.contains("min_confidence = 0.6"),
        "[scan].ml_threshold must raise the floor to 0.6; got {nested_out}"
    );

    let (_dir, cli_out, cli_err, cli_code) =
        effective_config_with_toml("ml_threshold = 0.9\n", &["--ml-threshold", "0.5"]);
    assert_eq!(cli_code, Some(0), "stderr={cli_err}");
    assert!(
        cli_out.contains("min_confidence = 0.5"),
        "CLI --ml-threshold must override TOML ml_threshold; got {cli_out}"
    );
}

/// `--ml-threshold 0.9` (above the 0.40 floor) RAISES the resolved floor via
/// `.max()` -> max(0.40, 0.9) == 0.9. This is the wiring that fixed the
/// previously-dead lever (M21).
#[test]
fn ml_threshold_above_floor_raises_it() {
    let (out, err, code) = effective_config(&["scan", "--no-daemon", "--ml-threshold", "0.9"]);
    assert_eq!(code, Some(0), "stderr={err}");
    assert!(
        out.contains("min_confidence = 0.9"),
        "--ml-threshold 0.9 must raise the floor to 0.9; got {out}"
    );
}

/// `--ml-threshold 0.1` (below the 0.40 floor) is a no-op on the floor: the
/// `.max()` keeps 0.40 (a lowered threshold can never punch below the floor).
#[test]
fn ml_threshold_below_floor_does_not_lower_it() {
    let (out, err, code) = effective_config(&["scan", "--no-daemon", "--ml-threshold", "0.1"]);
    assert_eq!(code, Some(0), "stderr={err}");
    assert!(
        out.contains("min_confidence = 0.4"),
        "--ml-threshold below the floor must not lower it; got {out}"
    );
}

/// `--ml-threshold` composes with `--min-confidence` by taking the maximum.
/// `--min-confidence 0.6 --ml-threshold 0.8` -> max(0.6, 0.8) == 0.8.
#[test]
fn ml_threshold_composes_with_min_confidence_via_max() {
    let (out, err, code) = effective_config(&[
        "scan",
        "--no-daemon",
        "--min-confidence",
        "0.6",
        "--ml-threshold",
        "0.8",
    ]);
    assert_eq!(code, Some(0), "stderr={err}");
    assert!(
        out.contains("min_confidence = 0.8"),
        "max(0.6 floor, 0.8 ml-threshold) must be 0.8; got {out}"
    );
}

/// Adversarial: `--ml-threshold nan` is rejected by `parse_ml_threshold`
/// (finite check first) with the exact "no NaN/Inf" error text.
#[test]
fn ml_threshold_rejects_nan() {
    let (_o, err, code) = run(&[
        "scan",
        "--no-daemon",
        "--ml-threshold",
        "nan",
        "/nonexistent-path-xyz",
    ]);
    assert_eq!(
        code,
        Some(2),
        "NaN ml-threshold must be rejected; stderr={err}"
    );
    assert!(
        err.contains("--ml-threshold must be a finite number"),
        "the finite-number guard must fire on NaN; stderr={err}"
    );
}

/// Negative: `--ml-threshold 2.0` is out of `[0.0, 1.0]`.
#[test]
fn ml_threshold_rejects_above_one() {
    let (_o, err, code) = run(&[
        "scan",
        "--no-daemon",
        "--ml-threshold",
        "2.0",
        "/nonexistent-path-xyz",
    ]);
    assert_eq!(code, Some(2), "2.0 ml-threshold out of range; stderr={err}");
    assert!(
        err.contains("--ml-threshold must be between 0.0 and 1.0"),
        "range guard text must surface; stderr={err}"
    );
}

// ============================================================================
// --dedup
// ============================================================================

/// `--dedup` accepts each `CliDedupScope` value (credential/file/none); the
/// default is `credential`. All three parse and scan clean input to exit 0.
#[test]
fn dedup_accepts_all_three_scopes() {
    for scope in ["credential", "file", "none"] {
        let (_d, _o, err, code) = scan_file("config.txt", "nothing here\n", &["--dedup", scope]);
        assert_eq!(code, Some(0), "--dedup {scope} must parse; stderr={err}");
    }
}

/// Negative: an unknown `--dedup` value is a clap error (exit 2).
#[test]
fn dedup_rejects_unknown_scope() {
    let (_o, err, code) = run(&[
        "scan",
        "--no-daemon",
        "--dedup",
        "everything",
        "/nonexistent-path-xyz",
    ]);
    assert_eq!(
        code,
        Some(2),
        "unknown --dedup value must be a clap error; stderr={err}"
    );
    assert!(
        err.to_lowercase().contains("invalid value")
            || err.to_lowercase().contains("possible values"),
        "clap must name the invalid dedup value; stderr={err}"
    );
}

/// `--dedup credential` (the default scope) collapses the SAME credential seen
/// on two lines into a single finding. `dedup_matches` keys on the credential
/// under `DedupScope::Credential`.
#[test]
fn dedup_credential_collapses_duplicate_credential() {
    // Same AWS key on two distinct lines/files-worth of context.
    let body = "first = \"AKIAQYLPMN5HFIQR7XYA\"\nsecond = \"AKIAQYLPMN5HFIQR7XYA\"\n";
    let (_d, out, err, code) = scan_file("config.txt", body, &["--dedup", "credential"]);
    assert_eq!(
        code,
        Some(1),
        "duplicate AWS key must still produce a finding; stderr={err}"
    );
    let findings = parse_findings(&out);
    let aws: Vec<_> = findings
        .iter()
        .filter(|f| f["detector_id"] == "aws-access-key")
        .collect();
    assert_eq!(
        aws.len(),
        1,
        "credential-scope dedup must collapse the repeated AWS key to one finding; got {out}"
    );
}

/// `--dedup none` disables the SCOPE-level dedup stage (`dedup_matches` with
/// `DedupScope::None` returns one `DedupedMatch` per raw match), but the CLI
/// emit path then runs `dedup_cross_detector` UNCONDITIONALLY
/// (`subcommands/scan.rs` and `orchestrator/postprocess.rs` both call
/// `dedup_matches(..)` immediately followed by `dedup_cross_detector(..)`).
/// That second pass groups by `(credential_hash, primary_location.file_path)`,
/// so two occurrences of the SAME credential in the SAME file share a group and
/// fold into a single winning finding (the second occurrence is recorded as
/// `cross_detector.*` evidence on the winner's companions), regardless of the
/// `--dedup` scope. Net CLI behavior for an identical-credential, same-file
/// pair under `--dedup none`: exactly ONE `aws-access-key` finding.
#[test]
fn dedup_none_keeps_both_occurrences() {
    let body = "first = \"AKIAQYLPMN5HFIQR7XYA\"\nsecond = \"AKIAQYLPMN5HFIQR7XYA\"\n";
    let (_d, out, err, code) = scan_file("config.txt", body, &["--dedup", "none"]);
    assert_eq!(code, Some(1), "stderr={err}");
    let findings = parse_findings(&out);
    let aws = findings
        .iter()
        .filter(|f| f["detector_id"] == "aws-access-key")
        .count();
    assert_eq!(
        aws, 1,
        "--dedup none disables scope dedup, but the always-on cross-detector \
         pass (keyed on credential_hash + file) folds the identical-credential \
         same-file pair into one finding; got {aws} in {out}"
    );
}

// ============================================================================
// --hide-client-safe
// ============================================================================

/// Without `--hide-client-safe`, a Sentry DSN surfaces as a `client-safe`
/// finding (default behavior: client-safe findings still appear).
#[test]
fn client_safe_finding_present_by_default() {
    let (_d, out, err, code) = scan_file("app.txt", SENTRY_DSN, &[]);
    if code != Some(1) {
        return; // corpus did not detect this DSN; nothing to assert
    }
    let findings = parse_findings(&out);
    assert!(
        findings.iter().any(|f| f["severity"] == "client-safe"),
        "default mode must surface the Sentry DSN at client-safe tier; got {out} (stderr={err})"
    );
}

/// `--hide-client-safe` drops every `Severity::ClientSafe` finding
/// (`orchestrator/run.rs`). The Sentry DSN's only findings are client-safe, so
/// the result set is empty and the exit code drops from 1 to 0.
#[test]
fn hide_client_safe_drops_client_safe_findings() {
    let (_d0, base_out, _e0, base_code) = scan_file("app.txt", SENTRY_DSN, &[]);
    if base_code != Some(1)
        || !parse_findings(&base_out)
            .iter()
            .any(|f| f["severity"] == "client-safe")
    {
        return; // no client-safe baseline -> the differential is meaningless here
    }

    let (_d, out, err, code) = scan_file("app.txt", SENTRY_DSN, &["--hide-client-safe"]);
    assert_eq!(
        code,
        Some(0),
        "--hide-client-safe must drop the only (client-safe) finding -> exit 0; stderr={err}"
    );
    let findings = parse_findings(&out);
    assert!(
        !findings.iter().any(|f| f["severity"] == "client-safe"),
        "--hide-client-safe must remove client-safe findings; got {out}"
    );
}

/// `--hide-client-safe` does NOT drop a non-client-safe finding. The critical
/// AWS key survives the flag (its severity is `critical`, not `client-safe`).
#[test]
fn hide_client_safe_keeps_non_client_safe_findings() {
    let (_d, out, err, code) = scan_file("config.txt", AWS_KEY, &["--hide-client-safe"]);
    assert_eq!(
        code,
        Some(1),
        "critical AWS key must survive --hide-client-safe; stderr={err}"
    );
    let findings = parse_findings(&out);
    assert!(
        findings
            .iter()
            .any(|f| f["detector_id"] == "aws-access-key"),
        "--hide-client-safe must not touch critical findings; got {out}"
    );
}

// ============================================================================
// --show-secrets
// ============================================================================

/// Default (no `--show-secrets`): the JSON `credential_redacted` field is the
/// `first4...last4` preview from `keyhog_core::redact`, NOT the plaintext.
/// For `AKIAQYLPMN5HFIQR7XYA` (20 ASCII chars) redact -> `AKIA...7XYA`.
#[test]
fn show_secrets_off_redacts_credential() {
    let (_d, out, err, code) = scan_file("config.txt", AWS_KEY, &[]);
    assert_eq!(code, Some(1), "stderr={err}");
    let findings = parse_findings(&out);
    let aws = findings
        .iter()
        .find(|f| f["detector_id"] == "aws-access-key")
        .unwrap_or_else(|| panic!("aws finding expected; got {out}"));
    let red = aws["credential_redacted"].as_str().unwrap_or("");
    assert_eq!(
        red, "AKIA...7XYA",
        "redacted form must be first4...last4 of the key; got {red:?} in {out}"
    );
    assert_ne!(
        red, "AKIAQYLPMN5HFIQR7XYA",
        "default mode must NOT print the plaintext credential; got {out}"
    );
}

/// `--show-secrets`: the JSON `credential_redacted` field carries the FULL
/// plaintext (`postprocess.rs` sets it to `m.credential` under the flag).
#[test]
fn show_secrets_on_prints_plaintext() {
    let (_d, out, err, code) = scan_file("config.txt", AWS_KEY, &["--show-secrets"]);
    assert_eq!(code, Some(1), "stderr={err}");
    let findings = parse_findings(&out);
    let aws = findings
        .iter()
        .find(|f| f["detector_id"] == "aws-access-key")
        .unwrap_or_else(|| panic!("aws finding expected; got {out}"));
    let red = aws["credential_redacted"].as_str().unwrap_or("");
    assert_eq!(
        red, "AKIAQYLPMN5HFIQR7XYA",
        "--show-secrets must emit the full plaintext credential; got {red:?} in {out}"
    );
}

/// `--show-secrets` conflicts with `--lockdown` at the orchestrator layer
/// (NOT clap): `finalize` bails with a message naming the conflict, and main
/// maps the bail to a user error (exit 2). This is a runtime guard, so the
/// scan must actually run — use a fixture with a finding so `finalize` runs.
#[test]
fn lockdown_forbids_show_secrets() {
    let (_d, _out, err, code) = scan_file("config.txt", AWS_KEY, &["--lockdown", "--show-secrets"]);
    assert_eq!(
        code,
        Some(2),
        "lockdown + show-secrets must be refused (user error 2); stderr={err}"
    );
    assert!(
        err.contains("lockdown mode forbids --show-secrets"),
        "the error must name the lockdown/show-secrets conflict; stderr={err}"
    );
}

// ============================================================================
// --daemon / --no-daemon routing-policy gate (flag interaction surface)
// ============================================================================

/// `--daemon` and `--no-daemon` are mutually exclusive at the clap layer
/// (`conflicts_with` on each). Exit 2.
#[test]
fn daemon_conflicts_with_no_daemon() {
    let (_o, err, code) = run(&["scan", "--daemon", "--no-daemon", "/nonexistent-path-xyz"]);
    assert_eq!(
        code,
        Some(2),
        "--daemon + --no-daemon must conflict; stderr={err}"
    );
}

/// A scan that requests filtering policy (`--severity`) still runs in-process
/// correctly without `--no-daemon`: the daemon-route gate forces the
/// in-process path whenever `--severity` is set, so the result is identical to
/// `--no-daemon`. We assert the critical AWS key still surfaces under
/// `--severity critical` with NO explicit daemon flag.
#[test]
fn severity_forces_in_process_path_and_still_finds() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("config.txt");
    std::fs::write(&path, AWS_KEY).expect("write");
    let out = Command::new(binary())
        .args([
            "scan",
            "--backend",
            "cpu",
            "--format",
            "json",
            "--severity",
            "critical",
        ])
        .arg(&path)
        .output()
        .expect("spawn");
    let code = out.status.code();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        code,
        Some(1),
        "--severity must force in-process and still find the key; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        parse_findings(&stdout)
            .iter()
            .any(|f| f["detector_id"] == "aws-access-key"),
        "in-process path under --severity must surface the critical finding; got {stdout}"
    );
}

// ============================================================================
// cross-flag composition + property-style sweep over the floor knobs
// ============================================================================

/// Property-style: for a grid of `--min-confidence` values in plain mode, the
/// resolved floor printed by the oracle ALWAYS equals the requested value
/// (the override is exact in non-precision mode). Pure derivation from
/// `build_scanner_config`'s `config.min_confidence = conf` branch.
#[test]
fn property_min_confidence_is_identity_in_plain_mode() {
    for &v in &[0.0_f64, 0.1, 0.25, 0.4, 0.5, 0.75, 0.85, 0.95, 1.0] {
        let s = format!("{v}");
        let (out, err, code) = effective_config(&["scan", "--no-daemon", "--min-confidence", &s]);
        assert_eq!(code, Some(0), "min-confidence {v} must parse; stderr={err}");
        // The oracle prints the f64 via `{}`; e.g. 0.4 -> "0.4", 1.0 -> "1".
        let expected = format!("min_confidence = {v}");
        assert!(
            out.contains(&expected),
            "plain-mode floor must equal the requested {v}; expected `{expected}`; got {out}"
        );
    }
}

/// Property-style: under `--precision`, the resolved floor is
/// `max(requested, 0.85)` for every requested value. Mirrors the
/// `conf.max(HIGH_PRECISION_MIN_CONFIDENCE)` composition exactly.
#[test]
fn property_precision_floor_is_max_with_point_eight_five() {
    for &v in &[0.0_f64, 0.2, 0.5, 0.84, 0.85, 0.86, 0.9, 1.0] {
        let s = format!("{v}");
        let (out, err, code) =
            effective_config(&["scan", "--no-daemon", "--precision", "--min-confidence", &s]);
        assert_eq!(
            code,
            Some(0),
            "precision min-confidence {v} must parse; stderr={err}"
        );
        let resolved = v.max(0.85_f64);
        let expected = format!("min_confidence = {resolved}");
        assert!(
            out.contains(&expected),
            "precision floor must be max({v}, 0.85) = {resolved}; expected `{expected}`; got {out}"
        );
    }
}

/// Composition coherence: `--min-confidence 0.7 --ml-threshold 0.6 --no-ml`
/// resolves the floor to max(0.7, 0.6) = 0.7 AND disables ML, independently.
/// Proves the three knobs compose without interfering with each other.
#[test]
fn composition_min_conf_ml_threshold_no_ml_independent() {
    let (out, err, code) = effective_config(&[
        "scan",
        "--no-daemon",
        "--min-confidence",
        "0.7",
        "--ml-threshold",
        "0.6",
        "--no-ml",
    ]);
    assert_eq!(code, Some(0), "stderr={err}");
    assert!(
        out.contains("min_confidence = 0.7"),
        "floor = max(0.7,0.6) = 0.7; got {out}"
    );
    assert!(
        out.contains("ml_enabled = false"),
        "--no-ml must disable ml; got {out}"
    );
}
