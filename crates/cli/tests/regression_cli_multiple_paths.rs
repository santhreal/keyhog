//! Regression: `keyhog scan <dir1> <dir2> …` over MULTIPLE positional roots,
//! driven end-to-end over the SHIPPED binary. Pins the multi-root contract that
//! `lane5`/`diff_explain` (single-root) do not: findings from EVERY requested
//! root are surfaced with their own exact per-file location, the finding set is
//! the union of the per-root scans and is independent of argument order, cross-
//! root dedup collapses a repeated credential to ONE finding spanning both
//! files, a duplicated path argument is not double-counted, and a single
//! nonexistent root fails the whole run closed (exit 2, named path, fix
//! guidance) — never a partial/silent report.
//!
//! HOST-INDEPENDENCE: both planted detectors — `github-classic-pat` (literal
//! `ghp_`) and `slack-bot-token` (literal `xoxb-`) — are literal-anchored, so
//! they fire on the always-available CPU/aho-corasick path and do NOT depend on
//! Hyperscan/SIMD/GPU. github maps to the SAME id (`github-classic-pat`) on both
//! the named-detector and simdsieve hot-pattern paths, so no host-dependent
//! `hot-*` variant appears. All runs force `--backend cpu --no-daemon` with
//! `KEYHOG_NO_GPU=1`, so no accelerator is assumed.
//!
//! Every assertion pins a concrete value (exact exit code, detector id, service,
//! severity, redaction bytes, sha256 hash, confidence f64, line/offset int,
//! location count, or diagnostic substring). None is a bare `!is_empty` /
//! `is_ok` / `len() > 0`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

// --- Planted credentials (split-literal so this test file is not itself a
// planted secret for the repo self-scan). Both proven to fire on a filesystem
// file via `--backend cpu`. ---

/// GitHub classic PAT with a valid CRC32 tail -> `github-classic-pat`.
const GITHUB: &str = concat!("ghp_", "1234567890123456789012345678902PDSiF");
const GITHUB_ID: &str = "github-classic-pat";
const GITHUB_NAME: &str = "GitHub Classic PAT";
/// sha256(GITHUB) — `credential_hash` is sha256(value) verbatim.
const GITHUB_HASH: &str = "7b85310a29300230c865bc48ca1836f15b81bd50ac85e8c0785e8145e98ff175";
const GITHUB_REDACTED: &str = "ghp_...DSiF";

/// Slack bot token -> `slack-bot-token`.
const SLACK: &str = concat!(
    "xoxb-",
    "1234567890123-1234567890123-abcdefghijklmnopqrstuvwx"
);
const SLACK_ID: &str = "slack-bot-token";
const SLACK_NAME: &str = "Slack Bot Token";
/// sha256(SLACK).
const SLACK_HASH: &str = "a8dd917042994f6c6f183c6f0718ab4241065165b299050b51302d3167cc3901";
const SLACK_REDACTED: &str = "xoxb...uvwx";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// Run `keyhog scan --no-daemon --backend cpu --no-suppress-test-fixtures
/// --format <format> <paths…>`. Returns (exit code, stdout, stderr).
fn scan_paths(paths: &[&Path], format: &str) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args([
        "scan",
        "--no-daemon",
        "--backend",
        "cpu",
        "--no-suppress-test-fixtures",
        "--format",
        format,
    ]);
    for p in paths {
        cmd.arg(p);
    }
    cmd.env("KEYHOG_NO_GPU", "1");
    cmd.env("NO_COLOR", "1");
    cmd.env_remove("KEYHOG_BACKEND");
    let out = cmd.output().expect("spawn keyhog scan");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn json_report(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout)
        .unwrap_or_else(|e| panic!("stdout is not a JSON report ({e}):\n{stdout}"))
}

/// The set of `detector_id` values in a JSON array report.
fn detector_ids(report: &serde_json::Value) -> BTreeSet<String> {
    report
        .as_array()
        .expect("report is a JSON array")
        .iter()
        .map(|f| {
            f["detector_id"]
                .as_str()
                .expect("each finding has a detector_id")
                .to_string()
        })
        .collect()
}

/// The single finding whose `detector_id` == `id` (panics unless exactly one).
fn sole_finding<'a>(report: &'a serde_json::Value, id: &str) -> &'a serde_json::Value {
    let hits: Vec<&serde_json::Value> = report
        .as_array()
        .expect("report is a JSON array")
        .iter()
        .filter(|f| f["detector_id"].as_str() == Some(id))
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "expected exactly one `{id}` finding, got {}; report:\n{report}",
        hits.len()
    );
    hits[0]
}

/// The basename of a finding's primary `location.file_path`.
fn basename(f: &serde_json::Value) -> String {
    let p = f["location"]["file_path"]
        .as_str()
        .expect("location.file_path is a string");
    Path::new(p)
        .file_name()
        .expect("file_path has a basename")
        .to_string_lossy()
        .into_owned()
}

/// Two sibling tempdirs: dir1 holds a bare GitHub PAT on line 1 of
/// `leak_a.env`, dir2 holds a bare Slack bot token on line 1 of `leak_b.env`.
/// Distinct credentials -> two distinct findings, one per root.
fn two_dirs_distinct() -> (TempDir, TempDir) {
    let d1 = TempDir::new().expect("tempdir 1");
    let d2 = TempDir::new().expect("tempdir 2");
    std::fs::write(d1.path().join("leak_a.env"), format!("{GITHUB}\n")).expect("write a");
    std::fs::write(d2.path().join("leak_b.env"), format!("{SLACK}\n")).expect("write b");
    (d1, d2)
}

// ---------------------------------------------------------------------------
// Union: findings from BOTH roots
// ---------------------------------------------------------------------------

/// `scan dir1 dir2` surfaces a finding from EACH root: exactly two findings,
/// exit 1, detector-id set == {github-classic-pat, slack-bot-token}.
#[test]
fn both_dirs_surface_distinct_detectors_exit_1() {
    let (d1, d2) = two_dirs_distinct();
    let (code, stdout, stderr) = scan_paths(&[d1.path(), d2.path()], "json");
    assert_eq!(
        code,
        Some(1),
        "a multi-root scan with findings must exit 1; stderr={stderr}"
    );
    let v = json_report(&stdout);
    assert_eq!(
        v.as_array().expect("array").len(),
        2,
        "two roots, one distinct secret each -> exactly two findings; got {stdout}"
    );
    let expected: BTreeSet<String> = [GITHUB_ID.to_string(), SLACK_ID.to_string()]
        .into_iter()
        .collect();
    assert_eq!(
        detector_ids(&v),
        expected,
        "the union of both roots must carry both detector ids; got {stdout}"
    );
}

/// Each finding names ITS OWN file, on line 1, with source `filesystem` — the
/// github finding points at `leak_a.env` (dir1) and the slack finding at
/// `leak_b.env` (dir2); the locations are never crossed.
#[test]
fn each_finding_names_its_own_file_on_line_one() {
    let (d1, d2) = two_dirs_distinct();
    let (_code, stdout, _err) = scan_paths(&[d1.path(), d2.path()], "json");
    let v = json_report(&stdout);

    let gh = sole_finding(&v, GITHUB_ID);
    assert_eq!(
        basename(gh),
        "leak_a.env",
        "github finding names dir1's file"
    );
    assert_eq!(
        gh["location"]["line"].as_u64(),
        Some(1),
        "github token is on line 1"
    );
    assert_eq!(
        gh["location"]["source"].as_str(),
        Some("filesystem"),
        "a filesystem root labels source `filesystem`"
    );

    let sl = sole_finding(&v, SLACK_ID);
    assert_eq!(
        basename(sl),
        "leak_b.env",
        "slack finding names dir2's file"
    );
    assert_eq!(
        sl["location"]["line"].as_u64(),
        Some(1),
        "slack token is on line 1"
    );
    // The github file must NOT be attributed to the slack finding, and vice versa.
    assert_ne!(
        basename(gh),
        basename(sl),
        "the two roots' findings must point at different files"
    );
}

/// The github finding carries its exact identity across roots: id / name /
/// service / severity / redaction / confidence / verification / hash.
#[test]
fn github_finding_exact_identity_fields() {
    let (d1, d2) = two_dirs_distinct();
    let (_code, stdout, _err) = scan_paths(&[d1.path(), d2.path()], "json");
    let v = json_report(&stdout);
    let f = sole_finding(&v, GITHUB_ID);

    assert_eq!(f["detector_name"].as_str(), Some(GITHUB_NAME));
    assert_eq!(f["service"].as_str(), Some("github"));
    assert_eq!(f["severity"].as_str(), Some("critical"));
    assert_eq!(
        f["credential_redacted"].as_str(),
        Some(GITHUB_REDACTED),
        "github must redact to {GITHUB_REDACTED}, never the raw token"
    );
    assert_eq!(
        f["confidence"].as_f64(),
        Some(1.0),
        "a checksum-valid github PAT on the filesystem path reports confidence 1.0"
    );
    assert_eq!(
        f["verification"].as_str(),
        Some("skipped"),
        "no live verification requested -> skipped"
    );
    assert_eq!(
        f["credential_hash"].as_str(),
        Some(GITHUB_HASH),
        "credential_hash must be sha256(github token) verbatim"
    );
    assert!(
        !stdout.contains(GITHUB),
        "the raw github token must never appear in the report; got {stdout}"
    );
}

/// The slack finding (from the OTHER root) carries its own exact identity —
/// proving neither root's fields bleed into the other.
#[test]
fn slack_finding_exact_identity_fields() {
    let (d1, d2) = two_dirs_distinct();
    let (_code, stdout, _err) = scan_paths(&[d1.path(), d2.path()], "json");
    let v = json_report(&stdout);
    let f = sole_finding(&v, SLACK_ID);

    assert_eq!(f["detector_name"].as_str(), Some(SLACK_NAME));
    assert_eq!(f["service"].as_str(), Some("slack"));
    assert_eq!(f["severity"].as_str(), Some("critical"));
    assert_eq!(
        f["credential_redacted"].as_str(),
        Some(SLACK_REDACTED),
        "slack must redact to {SLACK_REDACTED}"
    );
    assert_eq!(
        f["confidence"].as_f64(),
        Some(0.9),
        "the slack bot token reports confidence 0.9"
    );
    assert_eq!(
        f["credential_hash"].as_str(),
        Some(SLACK_HASH),
        "credential_hash must be sha256(slack token) verbatim"
    );
    assert!(
        !stdout.contains(SLACK),
        "the raw slack token must never appear in the report; got {stdout}"
    );
}

/// The `credential_hash` of each cross-root finding equals sha256 of the exact
/// planted token bytes — a serializer that hashed a truncated/salted form would
/// break this.
#[test]
fn credential_hash_equals_sha256_of_each_token() {
    let (d1, d2) = two_dirs_distinct();
    let (_code, stdout, _err) = scan_paths(&[d1.path(), d2.path()], "json");
    let v = json_report(&stdout);
    assert_eq!(
        sole_finding(&v, GITHUB_ID)["credential_hash"].as_str(),
        Some(GITHUB_HASH),
    );
    assert_eq!(
        sole_finding(&v, SLACK_ID)["credential_hash"].as_str(),
        Some(SLACK_HASH),
    );
}

/// Argument order is irrelevant to the union: `scan dir2 dir1` yields the SAME
/// detector-id set and the same count as `scan dir1 dir2`.
#[test]
fn path_order_swapped_yields_same_detector_set() {
    let (d1, d2) = two_dirs_distinct();
    let (c_ab, out_ab, _e1) = scan_paths(&[d1.path(), d2.path()], "json");
    let (c_ba, out_ba, _e2) = scan_paths(&[d2.path(), d1.path()], "json");
    assert_eq!(c_ab, Some(1), "dir1 dir2 exits 1");
    assert_eq!(c_ba, Some(1), "dir2 dir1 exits 1");

    let v_ab = json_report(&out_ab);
    let v_ba = json_report(&out_ba);
    assert_eq!(
        v_ab.as_array().unwrap().len(),
        2,
        "dir1 dir2 -> two findings"
    );
    assert_eq!(
        v_ba.as_array().unwrap().len(),
        2,
        "dir2 dir1 -> two findings"
    );
    assert_eq!(
        detector_ids(&v_ab),
        detector_ids(&v_ba),
        "the detector-id set must not depend on the order the roots were given"
    );
}

/// The union of a two-root scan equals the union of the two single-root scans:
/// scan(dir1) = {github}, scan(dir2) = {slack}, scan(dir1,dir2) = {github,slack}.
#[test]
fn multi_root_union_equals_union_of_single_root_scans() {
    let (d1, d2) = two_dirs_distinct();
    let (_c1, out1, _e1) = scan_paths(&[d1.path()], "json");
    let (_c2, out2, _e2) = scan_paths(&[d2.path()], "json");
    let (_cb, outb, _eb) = scan_paths(&[d1.path(), d2.path()], "json");

    let s1 = detector_ids(&json_report(&out1));
    let s2 = detector_ids(&json_report(&out2));
    let sb = detector_ids(&json_report(&outb));

    assert_eq!(
        s1,
        [GITHUB_ID.to_string()].into_iter().collect(),
        "dir1 alone yields only github"
    );
    assert_eq!(
        s2,
        [SLACK_ID.to_string()].into_iter().collect(),
        "dir2 alone yields only slack"
    );
    let union: BTreeSet<String> = s1.union(&s2).cloned().collect();
    assert_eq!(
        sb, union,
        "the multi-root scan must equal the union of the single-root scans"
    );
}

// ---------------------------------------------------------------------------
// Structured / human formats over two roots
// ---------------------------------------------------------------------------

/// SARIF over two roots: exactly two results, ruleId set == {github, slack},
/// both at level `error` (critical).
#[test]
fn sarif_over_two_paths_two_results_both_ruleids() {
    let (d1, d2) = two_dirs_distinct();
    let (code, stdout, stderr) = scan_paths(&[d1.path(), d2.path()], "sarif");
    assert_eq!(code, Some(1), "sarif multi-root exits 1; stderr={stderr}");
    let v = json_report(&stdout);
    let results = v
        .pointer("/runs/0/results")
        .and_then(|r| r.as_array())
        .expect("sarif runs[0].results array");
    assert_eq!(
        results.len(),
        2,
        "two roots -> two SARIF results; got {stdout}"
    );

    let rule_ids: BTreeSet<String> = results
        .iter()
        .map(|r| r["ruleId"].as_str().expect("ruleId").to_string())
        .collect();
    let expected: BTreeSet<String> = [GITHUB_ID.to_string(), SLACK_ID.to_string()]
        .into_iter()
        .collect();
    assert_eq!(rule_ids, expected, "both roots' ruleIds must appear");
    for r in results {
        assert_eq!(
            r["level"].as_str(),
            Some("error"),
            "both critical findings map to SARIF level `error`"
        );
    }
}

/// Text over two roots: the roll-up reads "2 secrets found", and the block
/// names BOTH detectors and BOTH file basenames.
#[test]
fn text_over_two_paths_reports_two_secrets_found() {
    let (d1, d2) = two_dirs_distinct();
    let (code, stdout, stderr) = scan_paths(&[d1.path(), d2.path()], "text");
    assert_eq!(code, Some(1), "text multi-root exits 1");
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        combined.contains("2 secrets found"),
        "the roll-up must count both roots' secrets; got:\n{combined}"
    );
    assert!(
        combined.contains(GITHUB_NAME) && combined.contains(SLACK_NAME),
        "both detector names must appear; got:\n{combined}"
    );
    assert!(
        combined.contains("leak_a.env") && combined.contains("leak_b.env"),
        "both roots' file basenames must appear; got:\n{combined}"
    );
}

// ---------------------------------------------------------------------------
// Per-file location precision on a non-first line
// ---------------------------------------------------------------------------

/// A secret on line 2 of a file in one of several roots reports the exact line
/// (2) and absolute byte offset (33 = 20-byte first line + 13-byte
/// `GITHUB_TOKEN=` prefix) — multi-root scanning does not corrupt per-file
/// offsets.
#[test]
fn secret_on_second_line_reports_exact_line_and_offset() {
    let d1 = TempDir::new().expect("tempdir 1");
    let d2 = TempDir::new().expect("tempdir 2");
    // Line 1 is exactly "harmless-first-line\n" (20 bytes); line 2 opens with
    // "GITHUB_TOKEN=" (13 bytes), so the token begins at absolute offset 33.
    std::fs::write(
        d1.path().join("nested.env"),
        format!("harmless-first-line\nGITHUB_TOKEN={GITHUB}\n"),
    )
    .expect("write nested");
    std::fs::write(d2.path().join("other.env"), format!("{SLACK}\n")).expect("write other");

    let (code, stdout, stderr) = scan_paths(&[d1.path(), d2.path()], "json");
    assert_eq!(code, Some(1), "exit 1; stderr={stderr}");
    let v = json_report(&stdout);
    let gh = sole_finding(&v, GITHUB_ID);
    assert_eq!(
        gh["location"]["line"].as_u64(),
        Some(2),
        "the github token sits on line 2; got {stdout}"
    );
    assert_eq!(
        gh["location"]["offset"].as_u64(),
        Some(33),
        "the token begins at absolute byte offset 33; got {stdout}"
    );
    assert_eq!(basename(gh), "nested.env");
}

// ---------------------------------------------------------------------------
// Cross-root dedup
// ---------------------------------------------------------------------------

/// The SAME credential planted in files under BOTH roots dedups to exactly ONE
/// finding (identity is `(detector, credential)`, not path).
#[test]
fn same_token_in_both_dirs_dedups_to_single_finding() {
    let d1 = TempDir::new().expect("tempdir 1");
    let d2 = TempDir::new().expect("tempdir 2");
    std::fs::write(d1.path().join("dup_a.env"), format!("A={GITHUB}\n")).expect("write a");
    std::fs::write(d2.path().join("dup_b.env"), format!("B={GITHUB}\n")).expect("write b");

    let (code, stdout, stderr) = scan_paths(&[d1.path(), d2.path()], "json");
    assert_eq!(code, Some(1), "dedup scan exits 1; stderr={stderr}");
    let v = json_report(&stdout);
    let count = v
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["detector_id"].as_str() == Some(GITHUB_ID))
        .count();
    assert_eq!(
        count, 1,
        "the same token across two roots must collapse to ONE finding; got {stdout}"
    );
}

/// The deduped finding records exactly ONE additional location, and the primary
/// + additional locations together name BOTH files across the two roots.
#[test]
fn dedup_records_one_additional_location_covering_both_files() {
    let d1 = TempDir::new().expect("tempdir 1");
    let d2 = TempDir::new().expect("tempdir 2");
    std::fs::write(d1.path().join("dup_a.env"), format!("A={GITHUB}\n")).expect("write a");
    std::fs::write(d2.path().join("dup_b.env"), format!("B={GITHUB}\n")).expect("write b");

    let (_code, stdout, _err) = scan_paths(&[d1.path(), d2.path()], "json");
    let v = json_report(&stdout);
    let f = sole_finding(&v, GITHUB_ID);
    let additional = f["additional_locations"]
        .as_array()
        .expect("additional_locations array");
    assert_eq!(
        additional.len(),
        1,
        "one duplicate across roots -> exactly one additional location; got {stdout}"
    );

    let mut names: BTreeSet<String> = BTreeSet::new();
    names.insert(basename(f));
    for loc in additional {
        let p = loc["file_path"].as_str().expect("additional file_path");
        names.insert(
            Path::new(p)
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
        );
    }
    let expected: BTreeSet<String> = ["dup_a.env".to_string(), "dup_b.env".to_string()]
        .into_iter()
        .collect();
    assert_eq!(
        names, expected,
        "the finding's locations must cover both roots' files"
    );
}

/// The deduped cross-root finding's `credential_hash` equals the hash from a
/// single-root scan of the same token — the identity is stable regardless of
/// how many roots the credential appears in.
#[test]
fn dedup_finding_hash_matches_single_scan_identity() {
    let d1 = TempDir::new().expect("tempdir 1");
    let d2 = TempDir::new().expect("tempdir 2");
    std::fs::write(d1.path().join("dup_a.env"), format!("A={GITHUB}\n")).expect("write a");
    std::fs::write(d2.path().join("dup_b.env"), format!("B={GITHUB}\n")).expect("write b");

    let (_c, out_multi, _e) = scan_paths(&[d1.path(), d2.path()], "json");
    let (_c1, out_single, _e1) = scan_paths(&[d1.path()], "json");

    let multi_hash = sole_finding(&json_report(&out_multi), GITHUB_ID)["credential_hash"]
        .as_str()
        .map(str::to_string);
    let single_hash = sole_finding(&json_report(&out_single), GITHUB_ID)["credential_hash"]
        .as_str()
        .map(str::to_string);
    assert_eq!(
        multi_hash.as_deref(),
        Some(GITHUB_HASH),
        "the deduped finding's hash must be sha256(github token)"
    );
    assert_eq!(
        multi_hash, single_hash,
        "the credential identity must be independent of how many roots it spans"
    );
}

/// Passing the SAME root twice does not double-count: `scan dir1 dir1` yields
/// exactly one github finding with zero additional locations (the identical
/// file path is not a second location).
#[test]
fn duplicate_path_argument_does_not_double_count() {
    let d1 = TempDir::new().expect("tempdir 1");
    std::fs::write(d1.path().join("leak_a.env"), format!("{GITHUB}\n")).expect("write a");

    let (code, stdout, stderr) = scan_paths(&[d1.path(), d1.path()], "json");
    assert_eq!(code, Some(1), "duplicate-arg scan exits 1; stderr={stderr}");
    let v = json_report(&stdout);
    assert_eq!(
        v.as_array().unwrap().len(),
        1,
        "the same root given twice must not duplicate the finding; got {stdout}"
    );
    let f = sole_finding(&v, GITHUB_ID);
    assert_eq!(
        f["additional_locations"].as_array().map(|a| a.len()),
        Some(0),
        "the identical file path must not be recorded as a second location; got {stdout}"
    );
}

// ---------------------------------------------------------------------------
// A nonexistent root fails the whole run closed
// ---------------------------------------------------------------------------

/// A nonexistent SECOND root (a good root followed by a typo) fails the whole
/// scan with exit 2 and an error naming the exact missing path.
#[test]
fn nonexistent_second_path_exits_2_and_names_it() {
    let d1 = TempDir::new().expect("tempdir 1");
    std::fs::write(d1.path().join("leak_a.env"), format!("{GITHUB}\n")).expect("write a");
    let missing = d1.path().join("keyhog-nonexistent-second-root-xyz");

    let (code, _stdout, stderr) = scan_paths(&[d1.path(), &missing], "json");
    assert_eq!(
        code,
        Some(2),
        "a missing extra root is a user error -> exit 2; stderr={stderr}"
    );
    assert!(
        stderr.contains("does not exist"),
        "the error must state the path does not exist; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("keyhog-nonexistent-second-root-xyz"),
        "the error must name the exact missing path; stderr:\n{stderr}"
    );
}

/// A nonexistent FIRST root fails closed BEFORE any report is produced: exit 2
/// and NO findings report on stdout (never a partial/silent scan of the valid
/// remaining root).
#[test]
fn nonexistent_first_path_exits_2_no_report_on_stdout() {
    let d2 = TempDir::new().expect("tempdir 2");
    std::fs::write(d2.path().join("leak_b.env"), format!("{SLACK}\n")).expect("write b");
    let missing = d2.path().join("keyhog-nonexistent-first-root-xyz");

    let (code, stdout, _stderr) = scan_paths(&[&missing, d2.path()], "json");
    assert_eq!(
        code,
        Some(2),
        "a missing first root fails the whole run closed -> exit 2"
    );
    assert!(
        !stdout.contains(SLACK_ID),
        "no partial report may leak the surviving root's finding; stdout:\n{stdout}"
    );
    // stdout must not be a non-empty findings array either.
    let parsed = serde_json::from_str::<serde_json::Value>(stdout.trim())
        .ok()
        .and_then(|v| v.as_array().map(|a| a.len()));
    assert_ne!(
        parsed,
        Some(1),
        "a fail-closed run must not emit a findings report on stdout; stdout:\n{stdout}"
    );
}

/// The missing-root diagnostic is actionable: it offers the fix guidance
/// ("Check the spelling") a typoing operator needs.
#[test]
fn nonexistent_path_error_gives_fix_guidance() {
    let d1 = TempDir::new().expect("tempdir 1");
    std::fs::write(d1.path().join("leak_a.env"), format!("{GITHUB}\n")).expect("write a");
    let missing = d1.path().join("keyhog-typo-root-xyz");

    let (code, _stdout, stderr) = scan_paths(&[d1.path(), &missing], "json");
    assert_eq!(code, Some(2));
    assert!(
        stderr.contains("Check the spelling"),
        "the missing-path error must offer fix guidance; stderr:\n{stderr}"
    );
}
