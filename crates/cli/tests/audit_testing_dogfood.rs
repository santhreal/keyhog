//! Adversarial audit — VECTOR 12 (TESTING) + VECTOR 13 (DOGFOODING).
//!
//! Each test documents a REAL, reproducible defect in the shipped `keyhog`
//! binary and is written to FAIL against today's code and PASS once the defect
//! is properly fixed. Every assertion checks observable truth (exact stderr
//! bytes, stdout JSON, exit code) — never `!is_empty()` or `Ok(())`.
//!
//! Standalone integration-test file: cargo auto-discovers it as its own test
//! binary (`autotests = true`), so it shares no `mod` wiring with the other
//! tests/ files and `CARGO_BIN_EXE_keyhog` points at the freshly built CLI.
//!
//! Findings:
//!   AUD-testing_dogfood-1  `--stream` emits raw matches that the final report
//!                          then SUPPRESSES, so the live stream contradicts the
//!                          report + exit code (two reproductions: `--min-confidence`
//!                          floor and the bundled test-fixture suppression list).
//!   AUD-testing_dogfood-2  empty detector directories must fail closed before
//!                          scanning and must not preserve stale detector-list
//!                          guidance.

use std::process::Command;
use tempfile::TempDir;

fn binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// A generic key/value secret whose reported confidence sits strictly INSIDE the
/// `(0.40, 0.99)` band: `--min-confidence 0.40` keeps it, `--min-confidence 0.99`
/// drops it. The stream/min-confidence contract is only non-vacuous with such a
/// straddle fixture — a 1.0-confidence finding can never be dropped by any floor.
/// (As `api_key = "<this>"` it scores ~0.59 via `generic-secret`.) If a detector
/// retune pushes it to >=0.99 or stops firing, the `run("0.40")`/`run("0.99")`
/// preconditions below fail loudly — pick a new value back in the band, do not
/// relax the asserts. The earlier `aAbBcCdDeEfFgGhH12345678` fixture drifted to
/// `entropy-api-key` confidence 1.0 and made `--min-confidence 0.99` vacuous.
const FIRING_LOW_CONFIDENCE_SECRET: &str = "hunter2hunter2hunter2xy";

/// Stripe's published docs example secret key. keyhog's bundled test-fixture
/// suppression list silences this one (it is a tutorial copy, not a leak), so
/// the final report is empty even though the regex matches.
const STRIPE_DOCS_EXAMPLE: &str = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";

fn count_json_findings(stdout: &str) -> usize {
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout is not JSON: {e}\nstdout was: {stdout:?}"));
    v.as_array()
        .map(|a| a.len())
        .unwrap_or_else(|| panic!("scan JSON output must be an array; got: {v}"))
}

/// Count `[stream]` preview lines on stderr (the `--stream` UX hint).
fn count_stream_lines(stderr: &str) -> usize {
    stderr.lines().filter(|l| l.contains("[stream]")).count()
}

/// AUD-testing_dogfood-1a — `--stream` must not preview a finding that the
/// `--min-confidence` floor then drops, so the stream lies about the result.
///
/// FINDING: `--stream` is wired to the RAW scanner matches, not to the
/// post-filter reported findings. `stream_finding_preview(w, m)` is called on
/// every `RawMatch` as it comes off the scanner thread
/// (crates/cli/src/orchestrator/dispatch.rs:220, helper at
/// crates/cli/src/orchestrator/reporting.rs:9 — it takes a `&RawMatch`),
/// which is BEFORE `filter_and_resolve` / `finalize` and the
/// `--min-confidence` floor in crates/cli/src/orchestrator/run.rs apply.
///
/// Historical evidence (reproduced against the shipped binary):
///   $ keyhog scan c.txt --stream --min-confidence 0.99 --format json
///   stderr: [stream] MEDIUM generic/generic-secret  c.txt:1  aAbB...5678
///   stdout: []
///   exit:   0
/// A developer (or CI log scraper) watching the stream sees a secret
/// "discovered", but the authoritative report is empty and the tool exits 0
/// (clean). The `--stream` help calls it "purely a UX hint that the scanner is
/// making progress"; emitting findings the report disowns is a correctness bug,
/// not a hint.
///
/// EXPECTED FIX: gate `stream_finding_preview` on the same confidence floor /
/// `--min-confidence` the report uses, so a streamed line implies a reported
/// finding. After the fix, with `--min-confidence 0.99` no `[stream]` line is
/// emitted (stream count == report count == 0).
#[test]
fn stream_preview_must_not_show_findings_dropped_by_min_confidence() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("c.txt");
    std::fs::write(
        &path,
        format!("api_key = \"{FIRING_LOW_CONFIDENCE_SECRET}\"\n"),
    )
    .unwrap();

    let run = |min_confidence: &str| {
        Command::new(binary())
            .args([
                "scan",
                "--no-daemon",
                "--backend",
                "simd",
                "--stream",
                "--min-confidence",
                min_confidence,
                "--format",
                "json",
            ])
            .arg(&path)
            .output()
            .expect("spawn keyhog scan")
    };

    let control = run("0.40");
    let control_stdout = String::from_utf8_lossy(&control.stdout);
    assert_eq!(
        count_json_findings(&control_stdout),
        1,
        "precondition: the fixture must produce one reportable generic-secret finding below the strict floor; stdout={control_stdout:?}; stderr={}",
        String::from_utf8_lossy(&control.stderr)
    );

    let out = run("0.99");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    // Preconditions: the report DID suppress the finding (this is the correct
    // half of the behavior), so the run is clean.
    assert_eq!(
        count_json_findings(&stdout),
        0,
        "precondition: --min-confidence 0.99 must suppress the sub-0.99 generic-secret finding in the report; stdout={stdout:?}"
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "precondition: a clean report must exit 0; stderr={stderr}"
    );

    // The defect: the stream contradicts the clean report by previewing the
    // suppressed finding. This assert FAILS if the stream is wired to raw
    // scanner matches and PASSES when the stream honors the confidence floor.
    assert_eq!(
        count_stream_lines(&stderr),
        0,
        "VECTOR-12/13 DEFECT: --stream previewed a finding that the report \
         dropped via --min-confidence. The stream must be consistent with the \
         report + exit code (0 findings here). stderr was:\n{stderr}"
    );
}

/// AUD-testing_dogfood-1b — `--stream` previews a credential that keyhog's own
/// test-fixture suppression list silences, so the stream surfaces a tutorial
/// copy keyhog deliberately decided is NOT a leak.
///
/// FINDING: same root cause as 1a — the stream fires on raw matches before the
/// suppression layer. Stripe's published docs example
/// `sk_live_4eC39HqLyjWDarjtT1zdp7dc` is on the bundled suppression list
/// (crates/cli/src/test_fixture_suppressions.rs and the --dogfood trace), so
/// the report is empty and exit is 0, yet `--stream` emits a CRITICAL
/// `stripe/stripe-secret-key` preview line.
///
/// EVIDENCE:
///   $ keyhog scan s.txt --stream --format json
///   stderr: [stream] CRITICAL stripe/stripe-secret-key  s.txt:1  sk_l...p7dc
///   stdout: []
///   exit:   0
///
/// EXPECTED FIX: route `--stream` previews through the same suppression /
/// confidence pipeline the report uses; a streamed line must correspond to a
/// reported finding. After the fix, the suppressed example emits zero
/// `[stream]` lines.
#[test]
fn stream_preview_must_not_show_test_fixture_suppressed_credential() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("s.txt");
    std::fs::write(&path, format!("stripe_key = \"{STRIPE_DOCS_EXAMPLE}\"\n")).unwrap();

    let out = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--backend",
            "simd",
            "--stream",
            "--format",
            "json",
        ])
        .arg(&path)
        .output()
        .expect("spawn keyhog scan");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert_eq!(
        count_json_findings(&stdout),
        0,
        "precondition: the Stripe docs example must be suppressed in the report; stdout={stdout:?}"
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "precondition: a fully-suppressed scan must exit 0; stderr={stderr}"
    );

    assert_eq!(
        count_stream_lines(&stderr),
        0,
        "VECTOR-12/13 DEFECT: --stream previewed a credential keyhog itself \
         classifies as a non-leak (test-fixture suppressed) and dropped from \
         the report. The stream must agree with the report. stderr was:\n{stderr}"
    );
}

/// AUD-testing_dogfood-2 — an empty detector directory is a hard user error,
/// not a valid empty corpus that can scan a target and return "no findings".
///
/// This also pins the historical detector-list coherence fix: scan errors must
/// not cite stale `detectors list` guidance, while `keyhog detectors list`
/// remains a valid compatibility alias for the default detector listing action.
#[test]
fn empty_detector_scan_fails_closed_without_phantom_list_guidance() {
    let dir = TempDir::new().expect("tempdir");
    let empty_detectors = dir.path().join("empty_detectors");
    std::fs::create_dir_all(&empty_detectors).unwrap();
    let target = dir.path().join("c.txt");
    std::fs::write(
        &target,
        format!("api_key = \"{FIRING_LOW_CONFIDENCE_SECRET}\"\n"),
    )
    .unwrap();

    let scan = Command::new(binary())
        .args(["scan", "--no-daemon", "--backend", "simd", "-d"])
        .arg(&empty_detectors)
        .arg(&target)
        .output()
        .expect("spawn keyhog scan");
    let scan_stderr = String::from_utf8_lossy(&scan.stderr);
    assert_eq!(
        scan.status.code(),
        Some(2),
        "scanning with an empty detector directory must be a user error (exit 2); stderr={scan_stderr}"
    );
    assert!(
        scan_stderr.contains("no detector TOML files")
            && scan_stderr.contains("refusing to scan"),
        "empty detector error must explain that no detector corpus exists and the scan was refused; stderr={scan_stderr}"
    );
    assert!(
        !scan_stderr.contains("no findings"),
        "empty detector scans must not look like clean scans; stderr={scan_stderr}"
    );
    assert!(
        !scan_stderr.contains("detectors list"),
        "scan errors must not cite stale detector-list guidance; stderr={scan_stderr}"
    );

    let detectors_list = Command::new(binary())
        .args(["detectors", "list"])
        .output()
        .expect("spawn keyhog detectors list");
    let detectors_list_stderr = String::from_utf8_lossy(&detectors_list.stderr);
    assert!(
        detectors_list.status.success(),
        "`keyhog detectors list` must remain a valid alias for the default list action; stderr={detectors_list_stderr}"
    );
    assert!(
        !detectors_list_stderr.contains("unexpected argument 'list'"),
        "`keyhog detectors list` must not regress into a clap positional error; stderr={detectors_list_stderr}"
    );
}
