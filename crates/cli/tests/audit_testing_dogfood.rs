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
//!   AUD-testing_dogfood-2  the "loaded zero detectors" error tells the operator
//!                          to run `keyhog detectors list`, but `list` is not a
//!                          valid subcommand — the suggested fix itself errors.

use std::process::Command;
use tempfile::TempDir;

fn binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// A real AWS access key with a valid checksum that the engine fires on at the
/// default 0.80 confidence (see crates/cli/tests/e2e/scan_planted_aws_exit_one.rs,
/// which uses the same literal). NOT on the test-fixture suppression list.
const FIRING_AWS_KEY: &str = "AKIAQYLPMN5HFIQR7XYA";

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

/// AUD-testing_dogfood-1a — `--stream` previews a CRITICAL finding that the
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
/// EVIDENCE (reproduced against the shipped binary):
///   $ keyhog scan c.txt --stream --min-confidence 0.99 --format json
///   stderr: [stream] CRITICAL aws/aws-access-key  c.txt:1  AKIA...7XYA
///   stdout: []
///   exit:   0
/// A developer (or CI log scraper) watching the stream sees a CRITICAL AWS leak
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
    std::fs::write(&path, format!("AWS_ACCESS_KEY_ID = \"{FIRING_AWS_KEY}\"\n")).unwrap();

    let out = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--stream",
            "--min-confidence",
            "0.99",
            "--format",
            "json",
        ])
        .arg(&path)
        .output()
        .expect("spawn keyhog scan");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    // Preconditions: the report DID suppress the finding (this is the correct
    // half of the behavior), so the run is clean.
    assert_eq!(
        count_json_findings(&stdout),
        0,
        "precondition: --min-confidence 0.99 must suppress the 0.80 AWS finding in the report; stdout={stdout:?}"
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "precondition: a clean report must exit 0; stderr={stderr}"
    );

    // The defect: the stream contradicts the clean report by previewing the
    // suppressed finding. This assert FAILS today (stream count == 1) and
    // PASSES once the stream honors the confidence floor (stream count == 0).
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
        .args(["scan", "--no-daemon", "--stream", "--format", "json"])
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

/// AUD-testing_dogfood-2 — the "loaded zero detectors" error tells the operator
/// to run `keyhog detectors list`, but `list` is not a valid subcommand.
///
/// FINDING: when a scan resolves zero detectors,
/// crates/cli/src/orchestrator_config.rs:248 bails with:
///   "... (run `keyhog detectors list --detectors <DIR>` to see which TOMLs
///    were rejected, if any) ..."
/// and crates/core/src/spec/load.rs:302 has the twin message
///   "(run `keyhog detectors list` for the full skip list)".
/// But `keyhog detectors` has NO `list` subcommand (its usage is
/// `keyhog detectors [OPTIONS]`); the directory is the `-d/--detectors` flag.
/// Following keyhog's own suggested fix yields a SECOND error:
///   $ keyhog detectors list --detectors <DIR>
///   error: unexpected argument 'list' found
///   (exit 2)
/// This violates the CLAUDE.md Engineering Standard "Error messages include
/// context and the fix" and the COHERENCE vector (help/examples/errors must
/// agree): the suggested fix is itself broken.
///
/// EXPECTED FIX: change both messages to the valid invocation
/// `keyhog detectors --detectors <DIR>` (no `list`). After the fix, the command
/// keyhog suggests runs cleanly instead of erroring on `unexpected argument
/// 'list'`.
///
/// This test asserts BOTH halves of the coherence contract:
///   (a) the suggested command, run verbatim, must NOT error with
///       "unexpected argument 'list'";
///   (b) the error text must therefore not contain the literal
///       "detectors list".
#[test]
fn zero_detectors_error_must_suggest_a_valid_command() {
    let dir = TempDir::new().expect("tempdir");
    let empty_detectors = dir.path().join("empty_detectors");
    std::fs::create_dir_all(&empty_detectors).unwrap();
    let target = dir.path().join("c.txt");
    std::fs::write(&target, format!("{FIRING_AWS_KEY}\n")).unwrap();

    // 1) Trigger the zero-detectors error.
    let scan = Command::new(binary())
        .args(["scan", "--no-daemon", "-d"])
        .arg(&empty_detectors)
        .arg(&target)
        .output()
        .expect("spawn keyhog scan");
    let scan_stderr = String::from_utf8_lossy(&scan.stderr);
    assert_eq!(
        scan.status.code(),
        Some(2),
        "precondition: scanning with zero detectors loaded must be a user error (exit 2); stderr={scan_stderr}"
    );
    assert!(
        scan_stderr.contains("loaded zero detectors"),
        "precondition: expected the zero-detectors guidance; stderr={scan_stderr}"
    );

    // 2) Independently prove `keyhog detectors list ...` is invalid today — the
    //    exact command the error suggests fails with an arg-parse error.
    let suggested = Command::new(binary())
        .args(["detectors", "list", "--detectors"])
        .arg(&empty_detectors)
        .output()
        .expect("spawn keyhog detectors list");
    let suggested_stderr = String::from_utf8_lossy(&suggested.stderr);

    // The defect manifests as clap rejecting the `list` positional. This assert
    // FAILS today (the message contains "unexpected argument 'list' found")
    // and PASSES once the suggested command is corrected to a real one.
    assert!(
        !suggested_stderr.contains("unexpected argument 'list'"),
        "VECTOR-10/12 COHERENCE DEFECT: keyhog's zero-detectors error suggests \
         `keyhog detectors list --detectors <DIR>`, but `list` is not a valid \
         subcommand — running the suggested fix errors with:\n{suggested_stderr}"
    );

    // 3) And the error text itself must not name the bogus `detectors list`
    //    subcommand. Ties the suggestion string back to the broken command so a
    //    fix to one without the other still leaves this red.
    assert!(
        !scan_stderr.contains("detectors list"),
        "VECTOR-10/12 COHERENCE DEFECT: the zero-detectors error tells the user \
         to run `keyhog detectors list ...`, but no such subcommand exists \
         (usage is `keyhog detectors [OPTIONS]`, dir via -d/--detectors). \
         Suggested fix must be a runnable command. stderr was:\n{scan_stderr}"
    );
}
