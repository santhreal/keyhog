//! Regression: the `keyhog scan` roll-up SUMMARY must report the EXACT finding
//! count, and that count must be identical whether the operator reads the human
//! `--format text` "N secret(s) found" line, counts the `--format json` array,
//! or scrapes the `--stream` per-finding preview lines. A serializer or summary
//! path that miscounts (drops a finding, double-counts a folded root, or lets
//! the text tally disagree with the machine formats) is a silent recall/UX bug
//! this pins shut with concrete integers.
//!
//! Fixture strategy, deterministic and HOST-INDEPENDENT:
//!   * One planted secret shape is used everywhere: a GitHub classic PAT
//!     (`ghp_` + 36 alnum) with a valid trailing checksum, proven by the
//!     format/backend parity e2e to fire `github-classic-pat` on its own bytes.
//!     Because it carries the literal `ghp_` anchor it triggers on the scalar
//!     Aho-Corasick literal path, it does NOT depend on Hyperscan/SIMD/GPU, so
//!     every count below reproduces on an accelerator-less host. All runs pin
//!     `--backend cpu` for the same reason.
//!   * Distinct FINDING counts are produced by planting the token in N separate
//!     files and passing `--dedup none` (each on-disk location is its own
//!     finding). The DEFAULT `--dedup credential` scope is exercised separately
//!     and MUST collapse identical values to a single finding.
//!
//! Every assertion pins a concrete value (exact integer / exact string / exact
//! exit code). None is a bare `!is_empty` / `is_ok`. `--daemon=off`,
//! `--backend cpu`, and `--no-suppress-test-fixtures` keep every run hermetic.

use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

/// A GitHub classic PAT with a valid trailing checksum, proven (by the
/// format/backend parity e2e) to fire `github-classic-pat` on its own bytes via
/// the literal `ghp_` anchor (scalar path; no accelerator required).
const PLANTED: &str = "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";

/// Exact honest empty-findings line the Text reporter writes (never "clean").
const NO_SECRETS_LINE: &str = "No secrets detected in the scanned files.";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// Write `n` files, each containing exactly one copy of the planted token on
/// its own line, into a fresh tempdir. Returns the dir (kept alive by the
/// caller) and the ordered list of file paths.
fn plant_tokens(n: usize) -> (TempDir, Vec<PathBuf>) {
    let dir = TempDir::new().expect("tempdir");
    let mut paths = Vec::with_capacity(n);
    for i in 0..n {
        let p = dir.path().join(format!("leak_{i}.txt"));
        std::fs::write(&p, format!("{PLANTED}\n")).expect("write leak file");
        paths.push(p);
    }
    (dir, paths)
}

/// A single file with no credential-shaped content (negative twin).
fn clean_file() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let p = dir.path().join("notes.txt");
    // No credential-bridge keywords (secret/key/token/password/api) so nothing
    // fires at all (a true negative twin).
    std::fs::write(&p, "just ordinary prose with plain everyday words here\n")
        .expect("write clean file");
    (dir, p)
}

/// Run `keyhog scan --daemon=off --backend cpu --no-suppress-test-fixtures
/// [--dedup <scope>] [extra…] --format <fmt> <paths…>`.
/// Returns (exit code, stdout, stderr).
fn run_scan(
    format: &str,
    dedup: Option<&str>,
    extra: &[&str],
    paths: &[&Path],
) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args([
        "scan",
        "--daemon=off",
        "--backend",
        "cpu",
        "--no-suppress-test-fixtures",
    ]);
    if let Some(scope) = dedup {
        cmd.args(["--dedup", scope]);
    }
    cmd.args(extra);
    cmd.args(["--format", format]);
    for p in paths {
        cmd.arg(p);
    }
    let output = cmd.output().expect("spawn keyhog scan");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Parse the "N secret(s) found" integer out of the Text summary. Returns the
/// exact count the human roll-up claims, or `None` if the line is absent.
fn text_summary_count(out: &str) -> Option<usize> {
    for line in out.lines() {
        // The summary reads e.g. "  1 secret found · 1 unverified" or
        // "  5 secrets found · 5 unverified".
        if let Some(idx) = line.find(" secret") {
            // Walk left across the immediate integer.
            let prefix = &line[..idx];
            let digits: String = prefix
                .chars()
                .rev()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
                .chars()
                .rev()
                .collect();
            if !digits.is_empty() {
                // Only the roll-up line has " secret" immediately after a bare
                // integer AND the word "found" later on the same line.
                if line.contains("found") {
                    return digits.parse().ok();
                }
            }
        }
    }
    None
}

/// Count the elements of the JSON report array on stdout.
fn json_finding_count(out: &str) -> usize {
    let v: serde_json::Value = serde_json::from_str(out).expect("json stdout must parse");
    v.as_array()
        .expect("json report must be a top-level array")
        .len()
}

// ---------------------------------------------------------------------------
// Text summary: exact finding count, singular/plural boundary
// ---------------------------------------------------------------------------

/// One planted secret -> the SINGULAR "1 secret found", exit 1.
#[test]
fn text_single_finding_says_one_secret_found() {
    let (_dir, paths) = plant_tokens(1);
    let refs: Vec<&Path> = paths.iter().map(|p| p.as_path()).collect();
    let (code, out, err) = run_scan("text", None, &[], &refs);
    let combined = format!("{out}\n{err}");
    assert_eq!(code, Some(1), "one finding must exit 1; stderr={err}");
    assert!(
        combined.contains("1 secret found"),
        "singular summary must read '1 secret found', got:\n{combined}"
    );
    // Singular: the word is exactly "secret", never "secrets", in the roll-up.
    assert!(
        !combined.contains("1 secrets found"),
        "one finding must NOT pluralize to '1 secrets found', got:\n{combined}"
    );
    assert_eq!(text_summary_count(&combined), Some(1), "parsed count == 1");
}

/// Two findings (2 files, dedup off) -> the PLURAL "2 secrets found", the
/// singular/plural boundary at N == 2.
#[test]
fn text_two_findings_uses_plural_form() {
    let (_dir, paths) = plant_tokens(2);
    let refs: Vec<&Path> = paths.iter().map(|p| p.as_path()).collect();
    let (code, out, err) = run_scan("text", Some("none"), &[], &refs);
    let combined = format!("{out}\n{err}");
    assert_eq!(code, Some(1), "two findings must exit 1; stderr={err}");
    assert!(
        combined.contains("2 secrets found"),
        "two findings must pluralize to '2 secrets found', got:\n{combined}"
    );
    assert_eq!(text_summary_count(&combined), Some(2), "parsed count == 2");
}

/// A large multi-finding scan (17 files, dedup off) reports the EXACT total in
/// the human roll-up: "17 secrets found".
#[test]
fn text_large_scan_reports_exact_total() {
    let (_dir, paths) = plant_tokens(17);
    let refs: Vec<&Path> = paths.iter().map(|p| p.as_path()).collect();
    let (code, out, err) = run_scan("text", Some("none"), &[], &refs);
    let combined = format!("{out}\n{err}");
    assert_eq!(code, Some(1), "17 findings must exit 1; stderr={err}");
    assert!(
        combined.contains("17 secrets found"),
        "large scan must read '17 secrets found', got:\n{combined}"
    );
    assert_eq!(
        text_summary_count(&combined),
        Some(17),
        "parsed count == 17"
    );
}

/// The Text roll-up's "N unverified" tally equals the finding count when no
/// `--verify` ran (liveness unknown for every finding).
#[test]
fn text_summary_unverified_tally_equals_count() {
    let (_dir, paths) = plant_tokens(5);
    let refs: Vec<&Path> = paths.iter().map(|p| p.as_path()).collect();
    let (_code, out, err) = run_scan("text", Some("none"), &[], &refs);
    let combined = format!("{out}\n{err}");
    assert!(
        combined.contains("5 secrets found"),
        "found tally must be 5, got:\n{combined}"
    );
    assert!(
        combined.contains("5 unverified"),
        "with no --verify all 5 findings are unverified, got:\n{combined}"
    );
    // Neither live nor dead segments appear without verification.
    assert!(
        !combined.contains(" live") && !combined.contains(" dead"),
        "no verification ran -> no live/dead segments, got:\n{combined}"
    );
}

// ---------------------------------------------------------------------------
// JSON count == Text count (cross-format agreement)
// ---------------------------------------------------------------------------

/// The JSON array length equals the exact number of planted findings.
#[test]
fn json_array_length_equals_planted_count() {
    let (_dir, paths) = plant_tokens(5);
    let refs: Vec<&Path> = paths.iter().map(|p| p.as_path()).collect();
    let (code, out, err) = run_scan("json", Some("none"), &[], &refs);
    assert_eq!(code, Some(1), "5 findings must exit 1; stderr={err}");
    assert_eq!(
        json_finding_count(&out),
        5,
        "json array must hold 5 findings"
    );
}

/// The text roll-up count and the json array length AGREE for the same scan
/// a serializer that drops a finding on one path (recall hole) fails here.
#[test]
fn text_and_json_counts_agree() {
    let (_dir, paths) = plant_tokens(5);
    let refs: Vec<&Path> = paths.iter().map(|p| p.as_path()).collect();

    let (_c1, json_out, _e1) = run_scan("json", Some("none"), &[], &refs);
    let (_c2, text_out, text_err) = run_scan("text", Some("none"), &[], &refs);

    let json_n = json_finding_count(&json_out);
    let text_n = text_summary_count(&format!("{text_out}\n{text_err}"))
        .expect("text summary must carry a count");
    assert_eq!(json_n, 5, "json count anchor");
    assert_eq!(text_n, 5, "text count anchor");
    assert_eq!(
        text_n, json_n,
        "text roll-up and json array must report the SAME total"
    );
}

/// A large total (17) agrees across text and json.
#[test]
fn large_total_agrees_across_text_and_json() {
    let (_dir, paths) = plant_tokens(17);
    let refs: Vec<&Path> = paths.iter().map(|p| p.as_path()).collect();

    let (_c1, json_out, _e1) = run_scan("json", Some("none"), &[], &refs);
    let (_c2, text_out, text_err) = run_scan("text", Some("none"), &[], &refs);

    assert_eq!(json_finding_count(&json_out), 17, "json holds 17");
    assert_eq!(
        text_summary_count(&format!("{text_out}\n{text_err}")),
        Some(17),
        "text roll-up reads 17"
    );
}

// ---------------------------------------------------------------------------
// Default credential dedup collapses identical values
// ---------------------------------------------------------------------------

/// Five files carrying the SAME credential value, under the DEFAULT
/// `--dedup credential` scope, collapse to exactly ONE finding in both formats.
#[test]
fn default_credential_dedup_collapses_identical_values() {
    let (_dir, paths) = plant_tokens(5);
    let refs: Vec<&Path> = paths.iter().map(|p| p.as_path()).collect();

    // No --dedup flag -> the default "credential" scope.
    let (jcode, json_out, _je) = run_scan("json", None, &[], &refs);
    assert_eq!(jcode, Some(1), "still one finding -> exit 1");
    assert_eq!(
        json_finding_count(&json_out),
        1,
        "identical values collapse to ONE finding under credential dedup"
    );

    let (_tc, text_out, text_err) = run_scan("text", None, &[], &refs);
    let combined = format!("{text_out}\n{text_err}");
    assert!(
        combined.contains("1 secret found"),
        "credential-deduped roll-up must read '1 secret found', got:\n{combined}"
    );
}

// ---------------------------------------------------------------------------
// Directory walk path
// ---------------------------------------------------------------------------

/// Scanning a DIRECTORY (single positional root) with 5 planted files reports
/// the exact total of 5 in both json and text under `--dedup none`.
#[test]
fn directory_scan_reports_exact_total() {
    let (dir, _paths) = plant_tokens(5);
    let root = dir.path();

    let (jcode, json_out, _je) = run_scan("json", Some("none"), &[], &[root]);
    assert_eq!(jcode, Some(1), "directory with findings exits 1");
    assert_eq!(
        json_finding_count(&json_out),
        5,
        "directory walk must surface all 5 planted findings"
    );

    let (_tc, text_out, text_err) = run_scan("text", Some("none"), &[], &[root]);
    assert!(
        format!("{text_out}\n{text_err}").contains("5 secrets found"),
        "directory text roll-up must read '5 secrets found'"
    );
}

// ---------------------------------------------------------------------------
// --stream preview lines == finding count
// ---------------------------------------------------------------------------

/// The `--stream` stderr preview emits exactly one `[stream]` line per REPORTED
/// finding, so the scrapeable count matches the json array length (5).
#[test]
fn stream_preview_line_count_equals_finding_count() {
    let (_dir, paths) = plant_tokens(5);
    let refs: Vec<&Path> = paths.iter().map(|p| p.as_path()).collect();
    let (code, out, err) = run_scan("json", Some("none"), &["--stream"], &refs);
    assert_eq!(code, Some(1), "5 findings -> exit 1");
    let json_n = json_finding_count(&out);
    let stream_n = err.lines().filter(|l| l.contains("[stream]")).count();
    assert_eq!(json_n, 5, "json anchor == 5");
    assert_eq!(
        stream_n, 5,
        "one [stream] line per reported finding, got {stream_n}"
    );
    assert_eq!(stream_n, json_n, "stream line count must equal json count");
}

// ---------------------------------------------------------------------------
// Adversarial: duplicate root folds (no double-count)
// ---------------------------------------------------------------------------

/// Passing the SAME file path twice on the command line, even with dedup off,
/// folds the duplicate root (the summary counts the finding ONCE, not twice).
#[test]
fn duplicate_root_does_not_double_count() {
    let (_dir, paths) = plant_tokens(1);
    let p = paths[0].as_path();
    let (code, out, err) = run_scan("json", Some("none"), &[], &[p, p]);
    assert_eq!(code, Some(1), "one finding across folded roots -> exit 1");
    assert_eq!(
        json_finding_count(&out),
        1,
        "a duplicate root must not inflate the count; stderr={err}"
    );
}

// ---------------------------------------------------------------------------
// Negative twin: clean scan
// ---------------------------------------------------------------------------

/// A clean file exits 0, prints the honest no-secrets line (never "clean"), and
/// the json report is exactly the empty array `[]` (count 0).
#[test]
fn clean_scan_zero_findings_and_honest_line() {
    let (_dir, path) = clean_file();
    let p = path.as_path();

    let (tcode, text_out, text_err) = run_scan("text", None, &[], &[p]);
    let combined = format!("{text_out}\n{text_err}");
    assert_eq!(tcode, Some(0), "clean scan must exit 0");
    assert!(
        combined.contains(NO_SECRETS_LINE),
        "clean text scan must print the honest no-secrets line, got:\n{combined}"
    );
    // The roll-up "N secret(s) found" line must be absent entirely.
    assert_eq!(
        text_summary_count(&combined),
        None,
        "clean scan must NOT emit a 'N secret(s) found' roll-up"
    );

    let (jcode, json_out, _je) = run_scan("json", None, &[], &[p]);
    assert_eq!(jcode, Some(0), "clean json scan must exit 0");
    assert_eq!(
        json_out.trim_end(),
        "[]",
        "clean json report must be exactly the empty array, got: {json_out:?}"
    );
    assert_eq!(json_finding_count(&json_out), 0, "clean json count == 0");
}

/// Exit-code contract paired with the count: findings present -> exit 1, no
/// findings -> exit 0, across the same fixture family.
#[test]
fn exit_code_tracks_presence_of_findings() {
    let (_leak_dir, leak_paths) = plant_tokens(3);
    let leak_refs: Vec<&Path> = leak_paths.iter().map(|p| p.as_path()).collect();
    let (leak_code, leak_out, _le) = run_scan("json", Some("none"), &[], &leak_refs);
    assert_eq!(json_finding_count(&leak_out), 3, "3 planted findings");
    assert_eq!(leak_code, Some(1), "findings present -> exit 1");

    let (_clean_dir, clean_path) = clean_file();
    let (clean_code, clean_out, _ce) = run_scan("json", None, &[], &[clean_path.as_path()]);
    assert_eq!(json_finding_count(&clean_out), 0, "no findings");
    assert_eq!(clean_code, Some(0), "no findings -> exit 0");
}
