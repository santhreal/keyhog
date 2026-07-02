//! Regression e2e — the `keyhog diff <before> <after>` baseline-delta surface,
//! driven over the SHIPPED `keyhog` binary and pinned to EXACT values.
//!
//! `diff` compares two baseline JSON files (the `scan --create-baseline` format)
//! keyed on `(detector_id, credential_hash)` and reports three buckets:
//!   NEW       — in `after`, not in `before`  (a regression → exit 1).
//!   RESOLVED  — in `before`, not in `after`  (a fixed leak → does not fail CI).
//!   UNCHANGED — present in both.
//! Exit contract: 0 when there are ZERO new entries, `EXIT_FINDINGS` (1) when any
//! NEW entry exists, `EXIT_USER_ERROR` (2) when a baseline file is missing or
//! malformed. See `subcommands/diff.rs` + `baseline.rs` + `lib.rs` error mapping.
//!
//! Distinct from `regression_cli_scan_diff_explain_e2e.rs` (which pins the
//! single-finding new/resolved/missing-file basics): this file drives the
//! MULTI-finding count arithmetic, the `--json summary` dual-field consistency
//! and sum invariants, detector-id sort order, the key-is-the-PAIR adversarial
//! cases, and the two MALFORMED-baseline shapes (garbage JSON + a findings
//! report fed in place of a baseline), each of which must exit 2 and name the
//! offending file.
//!
//! Every assertion pins a concrete load-bearing value — an exact exit code, an
//! integer bucket count, a `summary.*` field, a `detector_id` string, or an
//! error substring. No assertion uses `is_empty()` / `is_ok()` / `len() > 0` as
//! its only check (Law 6).

use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// Wrap a comma-joined entry list into a version-1 baseline document.
fn baseline_json(entries: &str) -> String {
    format!(r#"{{"version": 1, "created": "test", "entries": [{entries}]}}"#)
}

/// One baseline entry. `credential_hash` is compared as an opaque string by
/// `diff` (it never re-hashes), so distinct string values model distinct creds.
fn entry_json(detector_id: &str, credential_hash: &str, file_path: &str, line: usize) -> String {
    format!(
        r#"{{"detector_id": "{detector_id}", "credential_hash": "{credential_hash}", "file_path": "{file_path}", "line": {line}, "status": "acknowledged"}}"#
    )
}

/// Write `before`/`after` docs into a fresh tempdir and return their paths.
fn baselines(before: &str, after: &str) -> (TempDir, PathBuf, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let bp = dir.path().join("before.json");
    let ap = dir.path().join("after.json");
    std::fs::write(&bp, before).expect("write before");
    std::fs::write(&ap, after).expect("write after");
    (dir, bp, ap)
}

/// Run `keyhog diff [--json] <before> <after>` and return (code, stdout, stderr).
fn diff(before: &Path, after: &Path, json: bool) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(binary());
    cmd.arg("diff");
    if json {
        cmd.arg("--json");
    }
    cmd.arg(before).arg(after);
    cmd.env("NO_COLOR", "1");
    let out = cmd.output().expect("spawn keyhog diff");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Parse `diff --json` stdout, panicking with the raw bytes on failure.
fn json_of(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout)
        .unwrap_or_else(|e| panic!("diff --json stdout is not JSON ({e}):\n{stdout}"))
}

// ---------------------------------------------------------------------------
// NEW-only — exit 1, exact new_count (single + multi)
// ---------------------------------------------------------------------------

/// AFTER introduces one entry the empty BEFORE never had: exactly one NEW,
/// nothing resolved/unchanged, and the presence of a NEW leak exits 1.
#[test]
fn new_only_single_exits_one_with_new_count_one() {
    let (_d, bp, ap) = baselines(
        &baseline_json(""),
        &baseline_json(&entry_json("github-classic-pat", "hashN", "/n.env", 7)),
    );
    let (code, stdout, stderr) = diff(&bp, &ap, true);
    assert_eq!(code, Some(1), "one NEW entry → exit 1; stderr={stderr}");

    let v = json_of(&stdout);
    assert_eq!(
        v["summary"]["new_count"].as_u64(),
        Some(1),
        "summary.new_count must be 1; got {v}"
    );
    assert_eq!(
        v["summary"]["resolved_count"].as_u64(),
        Some(0),
        "summary.resolved_count must be 0; got {v}"
    );
    assert_eq!(
        v["summary"]["unchanged_count"].as_u64(),
        Some(0),
        "summary.unchanged_count must be 0; got {v}"
    );
    assert_eq!(
        v["new"].as_array().expect("new array").len(),
        1,
        "the new array length must match new_count=1; got {v}"
    );
    assert_eq!(
        v["new"][0]["detector_id"].as_str(),
        Some("github-classic-pat"),
        "the NEW entry must carry its exact detector_id; got {v}"
    );
}

/// Three brand-new entries against an empty BEFORE: new_count is exactly 3 and
/// the exit code is 1 regardless of how many NEW there are (any >0 fails CI).
#[test]
fn new_only_multi_exits_one_with_new_count_three() {
    let after = baseline_json(&format!(
        "{},{},{}",
        entry_json("aws-access-key", "h1", "/a.env", 1),
        entry_json("slack-bot-token", "h2", "/b.env", 2),
        entry_json("github-classic-pat", "h3", "/c.env", 3),
    ));
    let (_d, bp, ap) = baselines(&baseline_json(""), &after);
    let (code, stdout, stderr) = diff(&bp, &ap, true);
    assert_eq!(code, Some(1), "3 NEW entries → exit 1; stderr={stderr}");

    let v = json_of(&stdout);
    assert_eq!(
        v["summary"]["new_count"].as_u64(),
        Some(3),
        "summary.new_count must be exactly 3; got {v}"
    );
    assert_eq!(
        v["new"].as_array().expect("new array").len(),
        3,
        "the new array must hold 3 entries; got {v}"
    );
}

// ---------------------------------------------------------------------------
// RESOLVED-only — exit 0, exact resolved_count, detector-id sort order
// ---------------------------------------------------------------------------

/// Three entries in BEFORE, none in AFTER: all three are RESOLVED, zero NEW, so
/// there is no new leak and the command exits 0. resolved_count is exactly 3.
#[test]
fn resolved_only_multi_exits_zero_with_resolved_count_three() {
    let before = baseline_json(&format!(
        "{},{},{}",
        entry_json("aws-access-key", "h1", "/a.env", 1),
        entry_json("slack-bot-token", "h2", "/b.env", 2),
        entry_json("github-classic-pat", "h3", "/c.env", 3),
    ));
    let (_d, bp, ap) = baselines(&before, &baseline_json(""));
    let (code, stdout, stderr) = diff(&bp, &ap, true);
    assert_eq!(
        code,
        Some(0),
        "RESOLVED-only has no new leak → exit 0; stderr={stderr}"
    );

    let v = json_of(&stdout);
    assert_eq!(
        v["summary"]["resolved_count"].as_u64(),
        Some(3),
        "summary.resolved_count must be exactly 3; got {v}"
    );
    assert_eq!(
        v["summary"]["new_count"].as_u64(),
        Some(0),
        "summary.new_count must be 0; got {v}"
    );
}

/// RESOLVED entries are emitted sorted by `detector_id` (diff.rs sorts each
/// bucket): a BEFORE listing `zeta` before `alpha` must come back `alpha` first.
#[test]
fn resolved_entries_are_sorted_by_detector_id() {
    let before = baseline_json(&format!(
        "{},{}",
        entry_json("zeta-detector", "hz", "/z.env", 9),
        entry_json("alpha-detector", "ha", "/a.env", 1),
    ));
    let (_d, bp, ap) = baselines(&before, &baseline_json(""));
    let (code, stdout, _e) = diff(&bp, &ap, true);
    assert_eq!(code, Some(0));

    let v = json_of(&stdout);
    let resolved = v["resolved"].as_array().expect("resolved array");
    assert_eq!(resolved.len(), 2, "two resolved entries; got {v}");
    assert_eq!(
        resolved[0]["detector_id"].as_str(),
        Some("alpha-detector"),
        "resolved must be sorted: alpha-detector first; got {v}"
    );
    assert_eq!(
        resolved[1]["detector_id"].as_str(),
        Some("zeta-detector"),
        "resolved must be sorted: zeta-detector second; got {v}"
    );
}

// ---------------------------------------------------------------------------
// UNCHANGED — exact `=` count, exit 0
// ---------------------------------------------------------------------------

/// BEFORE == AFTER (two identical entries): both are UNCHANGED, zero new/resolved,
/// exit 0. The `--json summary.unchanged_count` is exactly 2 and the text summary
/// renders `= 2`.
#[test]
fn identical_baselines_report_unchanged_count_and_exit_zero() {
    let both = baseline_json(&format!(
        "{},{}",
        entry_json("aws-access-key", "h1", "/a.env", 1),
        entry_json("github-classic-pat", "h2", "/b.env", 2),
    ));
    let (_d, bp, ap) = baselines(&both, &both);

    // JSON form.
    let (jcode, jstdout, jstderr) = diff(&bp, &ap, true);
    assert_eq!(
        jcode,
        Some(0),
        "identical baselines → no new leak → exit 0; stderr={jstderr}"
    );
    let v = json_of(&jstdout);
    assert_eq!(
        v["summary"]["unchanged_count"].as_u64(),
        Some(2),
        "summary.unchanged_count must be exactly 2; got {v}"
    );
    assert_eq!(
        v["summary"]["new_count"].as_u64(),
        Some(0),
        "no NEW entries; got {v}"
    );
    assert_eq!(
        v["summary"]["resolved_count"].as_u64(),
        Some(0),
        "no RESOLVED entries; got {v}"
    );
    assert_eq!(
        v["unchanged"].as_array().expect("unchanged array").len(),
        2,
        "the unchanged array must hold 2 entries; got {v}"
    );

    // Text form: the dim summary reads `= 2` and the pass line is printed.
    let (tcode, tstdout, _te) = diff(&bp, &ap, false);
    assert_eq!(tcode, Some(0));
    assert!(
        tstdout.contains("= 2"),
        "text summary must count 2 unchanged as `= 2`; got {tstdout}"
    );
    assert!(
        tstdout.contains("PASS no new findings"),
        "no new findings must print the PASS line; got {tstdout}"
    );
}

// ---------------------------------------------------------------------------
// summary — dual-field consistency + sum invariants
// ---------------------------------------------------------------------------

/// BEFORE {A,B,C} vs AFTER {A,D,E}: A unchanged, {B,C} resolved, {D,E} new.
/// Every `summary.<x>` and its `<x>_count` twin must agree, and the buckets must
/// satisfy new+unchanged == |after| and resolved+unchanged == |before|.
#[test]
fn mixed_summary_dual_fields_agree_and_counts_sum() {
    let before = baseline_json(&format!(
        "{},{},{}",
        entry_json("det-a", "hA", "/a.env", 1),
        entry_json("det-b", "hB", "/b.env", 2),
        entry_json("det-c", "hC", "/c.env", 3),
    ));
    let after = baseline_json(&format!(
        "{},{},{}",
        entry_json("det-a", "hA", "/a.env", 1),
        entry_json("det-d", "hD", "/d.env", 4),
        entry_json("det-e", "hE", "/e.env", 5),
    ));
    let (_d, bp, ap) = baselines(&before, &after);
    let (code, stdout, stderr) = diff(&bp, &ap, true);
    assert_eq!(code, Some(1), "two NEW entries → exit 1; stderr={stderr}");

    let v = json_of(&stdout);
    let new = v["summary"]["new_count"].as_u64().expect("new_count");
    let resolved = v["summary"]["resolved_count"]
        .as_u64()
        .expect("resolved_count");
    let unchanged = v["summary"]["unchanged_count"]
        .as_u64()
        .expect("unchanged_count");
    assert_eq!(new, 2, "new_count must be 2 (D,E); got {v}");
    assert_eq!(resolved, 2, "resolved_count must be 2 (B,C); got {v}");
    assert_eq!(unchanged, 1, "unchanged_count must be 1 (A); got {v}");

    // Dual fields (`new` vs `new_count`, etc.) must never diverge.
    assert_eq!(
        v["summary"]["new"].as_u64(),
        Some(new),
        "summary.new must equal summary.new_count; got {v}"
    );
    assert_eq!(
        v["summary"]["resolved"].as_u64(),
        Some(resolved),
        "summary.resolved must equal summary.resolved_count; got {v}"
    );
    assert_eq!(
        v["summary"]["unchanged"].as_u64(),
        Some(unchanged),
        "summary.unchanged must equal summary.unchanged_count; got {v}"
    );

    // Sum invariants tie the buckets back to the input cardinalities.
    assert_eq!(
        new + unchanged,
        3,
        "new + unchanged must equal |after| = 3; got {v}"
    );
    assert_eq!(
        resolved + unchanged,
        3,
        "resolved + unchanged must equal |before| = 3; got {v}"
    );
}

// ---------------------------------------------------------------------------
// key is the (detector_id, credential_hash) PAIR — adversarial twins
// ---------------------------------------------------------------------------

/// Same credential_hash, DIFFERENT detector_id: the identity key is the PAIR,
/// so the old pairing resolves and the new pairing is NEW — not unchanged.
/// new_count=1, resolved_count=1, unchanged_count=0, exit 1.
#[test]
fn same_hash_different_detector_is_new_not_unchanged() {
    let (_d, bp, ap) = baselines(
        &baseline_json(&entry_json("detector-old", "SAMEHASH", "/x.env", 1)),
        &baseline_json(&entry_json("detector-new", "SAMEHASH", "/x.env", 1)),
    );
    let (code, stdout, stderr) = diff(&bp, &ap, true);
    assert_eq!(
        code,
        Some(1),
        "a new (detector,hash) pair is a NEW leak → exit 1; stderr={stderr}"
    );
    let v = json_of(&stdout);
    assert_eq!(v["summary"]["new_count"].as_u64(), Some(1), "got {v}");
    assert_eq!(v["summary"]["resolved_count"].as_u64(), Some(1), "got {v}");
    assert_eq!(
        v["summary"]["unchanged_count"].as_u64(),
        Some(0),
        "a shared hash under a different detector is NOT unchanged; got {v}"
    );
    assert_eq!(
        v["new"][0]["detector_id"].as_str(),
        Some("detector-new"),
        "the NEW entry must be the detector-new pairing; got {v}"
    );
}

/// Same detector_id, DIFFERENT credential_hash (a rotated secret): the old hash
/// resolves and the new hash is NEW. Proves the hash half of the key matters.
#[test]
fn same_detector_different_hash_is_new_and_resolved() {
    let (_d, bp, ap) = baselines(
        &baseline_json(&entry_json("aws-access-key", "OLDHASH", "/x.env", 1)),
        &baseline_json(&entry_json("aws-access-key", "NEWHASH", "/x.env", 1)),
    );
    let (code, stdout, stderr) = diff(&bp, &ap, true);
    assert_eq!(
        code,
        Some(1),
        "rotated secret is a NEW leak → exit 1; stderr={stderr}"
    );
    let v = json_of(&stdout);
    assert_eq!(v["summary"]["new_count"].as_u64(), Some(1), "got {v}");
    assert_eq!(v["summary"]["resolved_count"].as_u64(), Some(1), "got {v}");
    assert_eq!(v["summary"]["unchanged_count"].as_u64(), Some(0), "got {v}");
}

// ---------------------------------------------------------------------------
// --hide-unchanged — array nulled, summary count still exact
// ---------------------------------------------------------------------------

/// `--hide-unchanged` nulls the `unchanged` JSON array but MUST NOT zero the
/// `summary.unchanged_count`: the count is authoritative, the array is display.
#[test]
fn hide_unchanged_nulls_array_but_keeps_exact_count() {
    let both = baseline_json(&format!(
        "{},{}",
        entry_json("det-a", "hA", "/a.env", 1),
        entry_json("det-b", "hB", "/b.env", 2),
    ));
    let (_d, bp, ap) = baselines(&both, &both);
    let out = Command::new(binary())
        .arg("diff")
        .arg("--json")
        .arg("--hide-unchanged")
        .arg(&bp)
        .arg(&ap)
        .env("NO_COLOR", "1")
        .output()
        .expect("spawn keyhog diff --json --hide-unchanged");
    assert_eq!(
        out.status.code(),
        Some(0),
        "no new leak → exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v = json_of(&String::from_utf8_lossy(&out.stdout));
    assert!(
        v["unchanged"].is_null(),
        "--hide-unchanged must null the unchanged array; got {v}"
    );
    assert_eq!(
        v["summary"]["unchanged_count"].as_u64(),
        Some(2),
        "summary.unchanged_count must survive --hide-unchanged as 2; got {v}"
    );
}

// ---------------------------------------------------------------------------
// empty vs empty — degenerate all-zero
// ---------------------------------------------------------------------------

/// Two empty baselines: every bucket is 0 and the command exits 0 with the PASS
/// line — the degenerate "nothing to compare" case must not error.
#[test]
fn empty_vs_empty_all_zero_exits_zero() {
    let (_d, bp, ap) = baselines(&baseline_json(""), &baseline_json(""));
    let (code, stdout, stderr) = diff(&bp, &ap, true);
    assert_eq!(code, Some(0), "empty vs empty → exit 0; stderr={stderr}");
    let v = json_of(&stdout);
    assert_eq!(v["summary"]["new_count"].as_u64(), Some(0), "got {v}");
    assert_eq!(v["summary"]["resolved_count"].as_u64(), Some(0), "got {v}");
    assert_eq!(v["summary"]["unchanged_count"].as_u64(), Some(0), "got {v}");

    let (tcode, tstdout, _e) = diff(&bp, &ap, false);
    assert_eq!(tcode, Some(0));
    assert!(
        tstdout.contains("PASS no new findings"),
        "text form must print the PASS line for empty diff; got {tstdout}"
    );
}

// ---------------------------------------------------------------------------
// malformed baseline — exit 2, names the file (two shapes)
// ---------------------------------------------------------------------------

/// A BEFORE file of garbage (unparseable) JSON is a user error: exit 2 and the
/// error names the file so the operator knows which path is corrupt.
#[test]
fn malformed_garbage_before_exits_two_and_names_file() {
    let dir = TempDir::new().expect("tempdir");
    let bad = dir.path().join("corrupt-before.json");
    let ap = dir.path().join("after.json");
    std::fs::write(&bad, "{ this is not valid json at all ][").expect("write bad");
    std::fs::write(&ap, baseline_json("")).expect("write after");

    let (code, _stdout, stderr) = diff(&bad, &ap, false);
    assert_eq!(
        code,
        Some(2),
        "a malformed baseline is a user error → exit 2; stderr={stderr}"
    );
    assert!(
        stderr.contains("corrupt-before.json"),
        "the parse error must name the offending file; got {stderr}"
    );
    assert!(
        stderr.contains("parsing baseline file"),
        "the error must say it failed parsing the baseline; got {stderr}"
    );
}

/// Feeding a `scan --format json` FINDINGS report (a JSON array) where a baseline
/// is expected exits 2, names the file, AND emits the actionable
/// `--create-baseline` hint (the shape-detection branch in baseline.rs::load).
#[test]
fn findings_report_as_baseline_exits_two_with_create_baseline_hint() {
    let dir = TempDir::new().expect("tempdir");
    let bad = dir.path().join("findings-report.json");
    let ap = dir.path().join("after.json");
    // A findings report is a top-level JSON ARRAY, not a {version,entries} object.
    std::fs::write(
        &bad,
        r#"[{"detector_id":"github-classic-pat","credential_redacted":"ghp_...DSiF"}]"#,
    )
    .expect("write findings report");
    std::fs::write(&ap, baseline_json("")).expect("write after");

    let (code, _stdout, stderr) = diff(&bad, &ap, false);
    assert_eq!(
        code,
        Some(2),
        "a findings report is not a baseline → user error → exit 2; stderr={stderr}"
    );
    assert!(
        stderr.contains("findings-report.json"),
        "the error must name the mis-fed file; got {stderr}"
    );
    assert!(
        stderr.contains("--create-baseline"),
        "the error must point at `--create-baseline` to fix it; got {stderr}"
    );
}

/// A syntactically valid baseline carrying an UNSUPPORTED version is rejected:
/// exit 2 and the error states the seen and expected version numbers.
#[test]
fn unsupported_baseline_version_exits_two_naming_versions() {
    let dir = TempDir::new().expect("tempdir");
    let bad = dir.path().join("v999.json");
    let ap = dir.path().join("after.json");
    std::fs::write(
        &bad,
        r#"{"version": 999, "created": "test", "entries": []}"#,
    )
    .expect("write v999");
    std::fs::write(&ap, baseline_json("")).expect("write after");

    let (code, _stdout, stderr) = diff(&bad, &ap, false);
    assert_eq!(
        code,
        Some(2),
        "an unsupported baseline version is a user error → exit 2; stderr={stderr}"
    );
    assert!(
        stderr.contains("unsupported baseline version 999"),
        "the error must state the unsupported version 999; got {stderr}"
    );
    assert!(
        stderr.contains("expected 1"),
        "the error must state the expected version 1; got {stderr}"
    );
}
