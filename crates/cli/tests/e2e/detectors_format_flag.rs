//! CLI-01 coherence guard — `detectors --format` parity with `scan --format`.
//!
//! WHY THIS FILE EXISTS
//! --------------------
//! Dogfood (DF-01) hit `keyhog detectors --format json` → exit 2 "unexpected
//! argument '--format'": the `detectors` listing exposed only a boolean `--json`
//! while `scan` used `--format <text|json|...>`, so the two surfaces disagreed on
//! the output-format convention (CLI-01). `--format` is now the sole detector
//! listing format surface.
//!
//! WHAT THIS GUARDS
//! ----------------
//! 1. `detectors --format json` is accepted and emits the structured array.
//! 2. `detectors --format text` is accepted and is NOT JSON (human summary).
//! 3. The narrow format set is enforced: a findings-report-only format
//!    (`sarif`) is rejected for `detectors` rather than silently accepted —
//!    the `detectors` surface intentionally offers only text|json.
//! 4. The retired `--json` duplicate is rejected instead of silently choosing
//!    a second path to the same behavior.

use crate::e2e::support::run;

#[test]
fn detectors_format_json_emits_the_embedded_corpus() {
    let via_format = run(&["detectors", "--format", "json"]);
    assert_eq!(
        via_format.status.code(),
        Some(0),
        "`detectors --format json` must be accepted (CLI-01 regression: exit {:?}, stderr: {})",
        via_format.status.code(),
        String::from_utf8_lossy(&via_format.stderr),
    );
    let from_format: Vec<serde_json::Value> =
        serde_json::from_slice(&via_format.stdout).expect("--format json emits a JSON array");

    assert!(
        from_format.len() > 100,
        "expected hundreds of detectors via --format json; got {}",
        from_format.len()
    );
    assert_eq!(from_format.len(), keyhog_core::embedded_detector_count());
}

#[test]
fn detectors_format_text_is_not_json() {
    let out = run(&["detectors", "--format", "text"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "`detectors --format text` must be accepted; stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    // The human summary starts with the loaded-detectors banner and is not a
    // JSON array — parsing it as a JSON array must fail.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Loaded") && stdout.contains("detectors"),
        "text format must print the human grouped summary; got:\n{stdout}"
    );
    assert!(
        serde_json::from_str::<Vec<serde_json::Value>>(stdout.trim()).is_err(),
        "text format must NOT be a JSON array"
    );
}

#[test]
fn detectors_format_rejects_findings_only_format() {
    // SARIF is a findings-report shape with no meaning for a detector listing.
    // `detectors` deliberately offers only text|json, so this must be rejected
    // (exit 2) — not silently accepted, and not crashing.
    let out = run(&["detectors", "--format", "sarif"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "`detectors --format sarif` must be a clean clap rejection (exit 2)"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("sarif") || stderr.to_lowercase().contains("invalid"),
        "rejection must name the bad value; stderr: {stderr}"
    );
}

#[test]
fn detectors_json_alias_is_retired() {
    let out = run(&["detectors", "--json"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "the retired `--json` duplicate must be rejected (exit 2)"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("unexpected argument '--json'"));
}
