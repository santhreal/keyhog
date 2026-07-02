//! Regression: `keyhog scan` severity floor filtering (`-s`/`--severity`).
//!
//! The real flag is `--severity` (short `-s`), declared in
//! `crates/cli/src/args/scan.rs` as
//!   `#[arg(short, long, value_enum)] pub severity: Option<SeverityFilter>`
//! with help text "Min severity to report: info, low, medium, high, critical".
//! The filter lives in `orchestrator/postprocess.rs`:
//!   `if m.severity < min_severity.to_severity() { return false; }`
//! i.e. a match is KEPT iff `severity >= threshold` (strict `<` drops), using
//! the derived `Ord` on `keyhog_core::Severity`
//!   Info < ClientSafe < Low < Medium < High < Critical  (spec.rs).
//!
//! Two real findings are planted, both fire on the CPU/AC-literal path (each
//! detector carries literal keywords, so this is HOST-INDEPENDENT — no
//! Hyperscan/accelerator required) and run under `--backend cpu`:
//!   * CRITICAL: a bare GitHub classic PAT (`ghp_` + 36 alnum, valid checksum)
//!     fires `github-classic-pat` (service github, severity `critical`). Its
//!     deterministic sha256 is pinned (pure hashing, identical every host).
//!   * LOW: `rome2rio=<40 high-entropy alnum>` fires `rome2rio-api-key`
//!     (service rome2rio, severity `low`) via the detector's pattern-2 keyword
//!     anchor. The value carries no `key`/`secret`/`token`/`api`/`password`
//!     word, so the generic-keyword bridge does NOT add a stray finding.
//!
//! Coverage: positive (both surface unfiltered), boundary (`--severity low`
//! keeps the low finding because `low` is NOT `< low`), negative-twin
//! (`--severity high`/`medium`/`critical` drop the low finding, keep the
//! critical), exit codes (survivor => 1, filtered-to-empty => 0), short-flag
//! parity (`-s`), adversarial (an invalid enum value is a user error => exit 2;
//! filtering must not corrupt the surviving finding's identity fields).

use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

/// Bare GitHub classic PAT (`ghp_` + 36 alnum, clean boundary, valid checksum).
/// Fires `github-classic-pat` on its own bytes with NO keyword context, so it
/// contributes exactly one `critical` finding.
const GH_PAT: &str = "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";
const GH_ID: &str = "github-classic-pat";
const GH_SERVICE: &str = "github";
const GH_SEVERITY: &str = "critical";
/// Deterministic sha256 of `GH_PAT` (host-independent: pure hashing).
const GH_HASH: &str = "7b85310a29300230c865bc48ca1836f15b81bd50ac85e8c0785e8145e98ff175";

/// A `rome2rio`-anchored high-entropy 40-char alnum value. Fires
/// `rome2rio-api-key` (severity `low`) via pattern
/// `(?:rome2rio|Rome2rio|Rome2Rio)[=:\s"']+([A-Za-z0-9]{32,64})`. No credential
/// keyword in the line, so no generic-keyword finding is added.
const ROME_VALUE: &str = "aZ4rT9kL2mQ7xB5nV8wY3cF6sH1dJ0gPeUoIsRbX";
const ROME_ID: &str = "rome2rio-api-key";
const ROME_SEVERITY: &str = "low";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// A file containing ONLY the critical GitHub PAT (line 1).
fn crit_only_fixture() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("crit.txt");
    std::fs::write(&path, format!("{GH_PAT}\n")).expect("write crit fixture");
    (dir, path)
}

/// A file containing ONLY the low rome2rio secret (line 1).
fn low_only_fixture() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("low.txt");
    std::fs::write(&path, format!("rome2rio={ROME_VALUE}\n")).expect("write low fixture");
    (dir, path)
}

/// A file with the critical PAT on line 1 and the low secret on line 2.
fn combined_fixture() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("both.txt");
    std::fs::write(&path, format!("{GH_PAT}\nrome2rio={ROME_VALUE}\n"))
        .expect("write combined fixture");
    (dir, path)
}

/// Run `keyhog scan --no-daemon --backend cpu --no-suppress-test-fixtures
/// <extra…> <path>` and return (exit-code, stdout, stderr). `--backend cpu` is
/// always available (unlike `simd`, which fail-closes on the `ci` build), so
/// this is host-independent.
fn scan(path: &Path, extra: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args([
        "scan",
        "--no-daemon",
        "--backend",
        "cpu",
        "--no-suppress-test-fixtures",
    ]);
    cmd.args(extra);
    cmd.arg(path);
    cmd.env_remove("KEYHOG_BACKEND");
    let out = cmd.output().expect("spawn keyhog scan");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Parse a `--format json` array report into its finding objects.
fn findings(stdout: &str) -> Vec<serde_json::Value> {
    let v: serde_json::Value =
        serde_json::from_str(stdout).unwrap_or_else(|e| panic!("stdout not JSON ({e}):\n{stdout}"));
    v.as_array()
        .expect("json report is a top-level array")
        .clone()
}

/// Count findings whose `detector_id` equals `id`.
fn count_detector(stdout: &str, id: &str) -> usize {
    findings(stdout)
        .iter()
        .filter(|f| f.get("detector_id").and_then(|d| d.as_str()) == Some(id))
        .count()
}

/// Collect the `severity` string of every finding (duplicates preserved).
fn severities(stdout: &str) -> Vec<String> {
    findings(stdout)
        .iter()
        .filter_map(|f| f.get("severity").and_then(|s| s.as_str()).map(String::from))
        .collect()
}

// ---------------------------------------------------------------------------
// Flag surface truth
// ---------------------------------------------------------------------------

/// `scan --help` documents the real flag name `--severity` and its value list.
#[test]
fn scan_help_documents_severity_flag_and_values() {
    let out = Command::new(binary())
        .args(["scan", "--help"])
        .output()
        .expect("spawn keyhog scan --help");
    assert_eq!(out.status.code(), Some(0), "--help exits 0");
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(
        help.contains("--severity"),
        "help must document the long flag `--severity`; got:\n{help}"
    );
    assert!(
        help.contains("Min severity to report"),
        "help must carry the severity floor description; got:\n{help}"
    );
    for level in ["info", "low", "medium", "high", "critical"] {
        assert!(
            help.contains(level),
            "help must list severity level `{level}`; got:\n{help}"
        );
    }
}

// ---------------------------------------------------------------------------
// Per-detector baselines (each fixture fires exactly its one detector)
// ---------------------------------------------------------------------------

/// The critical fixture fires exactly one `github-classic-pat` at severity
/// `critical` and exits 1.
#[test]
fn crit_only_fixture_reports_one_critical_github_finding() {
    let (_d, path) = crit_only_fixture();
    let (code, out, err) = scan(&path, &["--format", "json"]);
    assert_eq!(code, Some(1), "a finding must exit 1; stderr={err}");
    assert_eq!(
        count_detector(&out, GH_ID),
        1,
        "exactly one github-classic-pat; got {out}"
    );
    let sevs = severities(&out);
    assert_eq!(
        sevs,
        vec![GH_SEVERITY.to_string()],
        "single critical severity"
    );
}

/// The low fixture fires exactly one `rome2rio-api-key` at severity `low` and
/// exits 1 (a low finding is still a reportable finding).
#[test]
fn low_only_fixture_reports_one_low_rome2rio_finding() {
    let (_d, path) = low_only_fixture();
    let (code, out, err) = scan(&path, &["--format", "json"]);
    assert_eq!(code, Some(1), "a finding must exit 1; stderr={err}");
    assert_eq!(
        count_detector(&out, ROME_ID),
        1,
        "exactly one rome2rio-api-key; got {out}"
    );
    let sevs = severities(&out);
    assert_eq!(sevs, vec![ROME_SEVERITY.to_string()], "single low severity");
}

// ---------------------------------------------------------------------------
// Unfiltered combined: both severities present
// ---------------------------------------------------------------------------

/// With NO severity floor, the combined fixture reports both findings: exactly
/// one critical github finding and one low rome2rio finding, exit 1.
#[test]
fn combined_no_filter_reports_both_critical_and_low() {
    let (_d, path) = combined_fixture();
    let (code, out, err) = scan(&path, &["--format", "json"]);
    assert_eq!(code, Some(1), "findings present must exit 1; stderr={err}");
    assert_eq!(
        count_detector(&out, GH_ID),
        1,
        "one github critical; got {out}"
    );
    assert_eq!(
        count_detector(&out, ROME_ID),
        1,
        "one rome2rio low; got {out}"
    );
    let mut sevs = severities(&out);
    sevs.sort();
    assert_eq!(
        sevs,
        vec!["critical".to_string(), "low".to_string()],
        "exactly the critical+low pair, nothing else; got {out}"
    );
}

// ---------------------------------------------------------------------------
// Filtering: strict `<` drops below-threshold findings
// ---------------------------------------------------------------------------

/// `--severity critical` keeps ONLY the critical github finding; the low
/// rome2rio finding is dropped (`low < critical`). Exit 1 (survivor present).
#[test]
fn severity_critical_keeps_only_the_critical_finding() {
    let (_d, path) = combined_fixture();
    let (code, out, err) = scan(&path, &["--format", "json", "--severity", "critical"]);
    assert_eq!(code, Some(1), "critical survivor exits 1; stderr={err}");
    assert_eq!(count_detector(&out, GH_ID), 1, "github kept; got {out}");
    assert_eq!(
        count_detector(&out, ROME_ID),
        0,
        "rome2rio dropped; got {out}"
    );
    assert_eq!(
        severities(&out),
        vec!["critical".to_string()],
        "only critical survives; got {out}"
    );
}

/// `--severity high` drops the low finding (`low < high`) and keeps the
/// critical (`critical >= high`). No surviving finding is below `high`.
#[test]
fn severity_high_drops_low_keeps_critical() {
    let (_d, path) = combined_fixture();
    let (code, out, err) = scan(&path, &["--format", "json", "--severity", "high"]);
    assert_eq!(code, Some(1), "critical survives high floor; stderr={err}");
    assert_eq!(
        count_detector(&out, ROME_ID),
        0,
        "low dropped by high floor; got {out}"
    );
    assert_eq!(count_detector(&out, GH_ID), 1, "critical kept; got {out}");
    for sev in severities(&out) {
        assert!(
            sev == "high" || sev == "critical",
            "high floor must leave only high/critical; saw `{sev}` in {out}"
        );
    }
}

/// `--severity medium` still drops the low finding (`low < medium`) and keeps
/// the critical. Confirms the floor is the requested tier, not a fixed one.
#[test]
fn severity_medium_drops_low_keeps_critical() {
    let (_d, path) = combined_fixture();
    let (code, out, err) = scan(&path, &["--format", "json", "--severity", "medium"]);
    assert_eq!(
        code,
        Some(1),
        "critical survives medium floor; stderr={err}"
    );
    assert_eq!(
        count_detector(&out, ROME_ID),
        0,
        "low dropped by medium floor; got {out}"
    );
    assert_eq!(count_detector(&out, GH_ID), 1, "critical kept; got {out}");
    assert!(
        !severities(&out).iter().any(|s| s == "low"),
        "no `low` finding may survive a medium floor; got {out}"
    );
}

/// BOUNDARY: `--severity low` keeps the low finding because the gate is strict
/// (`low < low` is false), so BOTH findings survive. Exit 1.
#[test]
fn severity_low_boundary_keeps_both_findings() {
    let (_d, path) = combined_fixture();
    let (code, out, err) = scan(&path, &["--format", "json", "--severity", "low"]);
    assert_eq!(code, Some(1), "findings present exits 1; stderr={err}");
    assert_eq!(
        count_detector(&out, GH_ID),
        1,
        "critical kept at low floor; got {out}"
    );
    assert_eq!(
        count_detector(&out, ROME_ID),
        1,
        "low finding kept at exactly-equal low floor; got {out}"
    );
}

/// `--severity info` is the lowest floor and keeps everything: both findings
/// survive, exit 1.
#[test]
fn severity_info_floor_keeps_both_findings() {
    let (_d, path) = combined_fixture();
    let (code, out, err) = scan(&path, &["--format", "json", "--severity", "info"]);
    assert_eq!(code, Some(1), "findings present exits 1; stderr={err}");
    assert_eq!(count_detector(&out, GH_ID), 1, "critical kept; got {out}");
    assert_eq!(
        count_detector(&out, ROME_ID),
        1,
        "low kept under info floor; got {out}"
    );
}

// ---------------------------------------------------------------------------
// Exit-code contract: filtering to empty is a clean exit 0
// ---------------------------------------------------------------------------

/// A low-only fixture under `--severity critical` filters out its single
/// finding, so the report is exactly the empty array and the scan exits 0
/// (nothing to report is a clean run, not an error).
#[test]
fn low_finding_filtered_by_critical_floor_exits_zero_empty() {
    let (_d, path) = low_only_fixture();
    let (code, out, err) = scan(&path, &["--format", "json", "--severity", "critical"]);
    assert_eq!(
        code,
        Some(0),
        "empty post-filter report exits 0; stderr={err}"
    );
    assert_eq!(
        out.trim_end(),
        "[]",
        "report must be exactly `[]`; got {out:?}"
    );
    assert_eq!(findings(&out).len(), 0, "zero findings survive the floor");
}

/// Same fixture under `--severity high` also empties (`low < high`) => exit 0.
/// Confirms the empty-exit-0 behavior is not special to the top tier.
#[test]
fn low_finding_filtered_by_high_floor_exits_zero_empty() {
    let (_d, path) = low_only_fixture();
    let (code, out, err) = scan(&path, &["--format", "json", "--severity", "high"]);
    assert_eq!(
        code,
        Some(0),
        "empty post-filter report exits 0; stderr={err}"
    );
    assert_eq!(
        findings(&out).len(),
        0,
        "zero findings survive the high floor; got {out}"
    );
}

// ---------------------------------------------------------------------------
// Short-flag parity + adversarial
// ---------------------------------------------------------------------------

/// The short flag `-s critical` behaves identically to `--severity critical`:
/// keeps only the critical github finding, drops the low one, exit 1.
#[test]
fn short_flag_s_matches_long_severity() {
    let (_d, path) = combined_fixture();
    let (code, out, err) = scan(&path, &["--format", "json", "-s", "critical"]);
    assert_eq!(
        code,
        Some(1),
        "short -s critical survivor exits 1; stderr={err}"
    );
    assert_eq!(
        count_detector(&out, GH_ID),
        1,
        "github kept via -s; got {out}"
    );
    assert_eq!(
        count_detector(&out, ROME_ID),
        0,
        "rome2rio dropped via -s; got {out}"
    );
}

/// ADVERSARIAL: an unknown severity level is a value-enum parse error — a user
/// error (exit 2), and clap names the offending flag in its diagnostic.
#[test]
fn invalid_severity_value_is_user_error_exit_two() {
    let (_d, path) = combined_fixture();
    let (code, _out, err) = scan(&path, &["--format", "json", "--severity", "extreme"]);
    assert_eq!(
        code,
        Some(2),
        "unknown --severity value is a user error; stderr={err}"
    );
    assert!(
        err.contains("severity"),
        "clap error must name the `severity` flag; got {err}"
    );
}

/// ADVERSARIAL: filtering must not corrupt the surviving finding. Under
/// `--severity critical` the github finding keeps its exact identity — service
/// `github` and the deterministic sha256 of the planted PAT.
#[test]
fn filter_preserves_surviving_finding_identity() {
    let (_d, path) = combined_fixture();
    let (code, out, _e) = scan(&path, &["--format", "json", "--severity", "critical"]);
    assert_eq!(code, Some(1), "survivor exits 1");
    let f = findings(&out);
    assert_eq!(
        f.len(),
        1,
        "exactly one finding survives the critical floor; got {out}"
    );
    let obj = &f[0];
    assert_eq!(
        obj.get("detector_id").and_then(|d| d.as_str()),
        Some(GH_ID),
        "survivor is the github detector"
    );
    assert_eq!(
        obj.get("service").and_then(|s| s.as_str()),
        Some(GH_SERVICE),
        "survivor service unchanged by filtering"
    );
    assert_eq!(
        obj.get("credential_hash").and_then(|h| h.as_str()),
        Some(GH_HASH),
        "survivor credential_hash is the exact sha256 of the planted PAT"
    );
}
