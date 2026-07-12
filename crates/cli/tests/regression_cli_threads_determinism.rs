//! Regression: `--threads` is a *performance* knob, never a *result* knob.
//!
//! Concurrency must not change what keyhog finds. Scanning the SAME
//! multi-file corpus with `--threads 1` and `--threads 4` (and every
//! other worker count) must yield the byte-identical, order-independent
//! finding set and the same exit code — otherwise the scan is racy and a
//! CI gate would flap on core count. These tests drive the REAL shipped
//! `keyhog` binary (`env!("CARGO_BIN_EXE_keyhog")`) over a `TempDir`
//! corpus planted OUTSIDE the workspace (so repo `.gitignore`/test-path
//! suppression rules can't interfere), on the explicit `cpu` backend so
//! the assertions are HOST-INDEPENDENT (no accelerator assumed; the CPU
//! path is forced regardless of any GPU/env state).
//!
//! Detector ids asserted here (`github`-family, `aws-bedrock-api-key`,
//! `aws-access-key`/`hot-aws_key`) are the same concrete ids the shipped
//! `e2e_binary.rs` contract already pins for these literal fixtures.

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

/// Forced CPU backend keeps every assertion host-independent: the result
/// set cannot silently degrade onto an accelerator path.
const CPU_BACKEND: &str = "cpu";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// Plant a fixed 4-file corpus: three files each carry a distinct,
/// well-known detectable credential (split-literal so THIS test file is
/// not itself a planted-secret tripwire when keyhog scans its own repo),
/// one file is clean. At least three findings are expected.
fn build_corpus(dir: &Path) {
    // AWS long-term access key id -> `aws-access-key` (or the
    // `hot-aws_key` simdsieve fast path); same literal as e2e_binary.rs.
    std::fs::write(
        dir.join("a_aws.env"),
        concat!("AWS_ACCESS_KEY_ID = \"AKIA", "QYLPMN5HFIQR7XYA\"\n"),
    )
    .expect("write a_aws.env");

    // GitHub PAT -> a github-family detector; valid-checksum literal
    // reused from e2e_binary.rs so the checksum wiring accepts it.
    std::fs::write(
        dir.join("b_github.env"),
        concat!(
            "GH_TOKEN = \"ghp_",
            "aBcD1234EFgh5678ijkl9012MNop343hK7n2\"\n"
        ),
    )
    .expect("write b_github.env");

    // AWS Bedrock long-term API key -> `aws-bedrock-api-key`.
    std::fs::write(
        dir.join("c_bedrock.env"),
        concat!(
            "AWS_BEARER_TOKEN_BEDROCK=\"ABSKQmVkcm9ja0FQSUtleS",
            "y2J0fajDUXD1efoRCtqKODGGBi8UWr7UJsq2tkhFhx8ZEDEd9hnKHivse0YHShMdeCAbPEOXOxyhkg5cqNGHA1grwAyKC3Y8HDD62wLdl37iKN\"\n",
        ),
    )
    .expect("write c_bedrock.env");

    // Clean file: no credential, contributes zero findings.
    std::fs::write(dir.join("d_clean.txt"), "fn main() { println!(\"hi\"); }\n")
        .expect("write d_clean.txt");
}

/// Run `keyhog scan --backend cpu --format json --threads <n> <dir>` and
/// return (stdout, stderr, exit-code). `threads` is passed verbatim so
/// invalid values can be exercised too.
fn run_scan(dir: &Path, threads: &str) -> (String, String, Option<i32>) {
    let output = Command::new(binary())
        .arg("scan")
        .arg("--daemon=off")
        .args(["--backend", CPU_BACKEND])
        .args(["--threads", threads])
        .args(["--format", "json"])
        .arg(dir)
        .env_remove("KEYHOG_BACKEND")
        .output()
        .expect("spawn keyhog scan");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.code(),
    )
}

/// Parse the JSON finding array from a successful scan's stdout.
fn parse_findings(stdout: &str) -> Vec<serde_json::Value> {
    let value: serde_json::Value = serde_json::from_str(stdout)
        .unwrap_or_else(|error| panic!("stdout is not valid JSON: {error}\n{stdout}"));
    value
        .as_array()
        .unwrap_or_else(|| panic!("findings JSON must be an array, got {value}"))
        .clone()
}

/// Stable, order-independent key for one finding: identity is
/// (detector_id, file_path, line, offset, credential_hash). The same
/// corpus dir is scanned by every run, so `file_path` is identical
/// across runs.
fn finding_key(f: &serde_json::Value) -> String {
    let det = f
        .get("detector_id")
        .and_then(|v| v.as_str())
        .unwrap_or("<no-detector>");
    let loc = f.get("location");
    let file = loc
        .and_then(|l| l.get("file_path"))
        .and_then(|v| v.as_str())
        .unwrap_or("<no-path>");
    let line = loc
        .and_then(|l| l.get("line"))
        .and_then(|v| v.as_u64())
        .unwrap_or(u64::MAX);
    let offset = loc
        .and_then(|l| l.get("offset"))
        .and_then(|v| v.as_u64())
        .unwrap_or(u64::MAX);
    let hash = f
        .get("credential_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("<no-hash>");
    format!("{det}|{file}|{line}|{offset}|{hash}")
}

/// Sorted vector of finding keys (order-independent finding SET).
fn sorted_keys(findings: &[serde_json::Value]) -> Vec<String> {
    let mut keys: Vec<String> = findings.iter().map(finding_key).collect();
    keys.sort();
    keys
}

/// Sorted vector of detector ids WITH duplicates (order-independent
/// detector MULTISET).
fn sorted_detector_ids(findings: &[serde_json::Value]) -> Vec<String> {
    let mut ids: Vec<String> = findings
        .iter()
        .map(|f| {
            f.get("detector_id")
                .and_then(|v| v.as_str())
                .unwrap_or("<no-detector>")
                .to_owned()
        })
        .collect();
    ids.sort();
    ids
}

/// Sorted, de-duplicated credential hashes present in a finding set.
fn sorted_unique_hashes(findings: &[serde_json::Value]) -> Vec<String> {
    let mut hashes: Vec<String> = findings
        .iter()
        .filter_map(|f| f.get("credential_hash").and_then(|v| v.as_str()))
        .map(str::to_owned)
        .collect();
    hashes.sort();
    hashes.dedup();
    hashes
}

/// True if the finding set contains a github-family detection
/// (`detector_id` or `service` mentions github).
fn has_github(findings: &[serde_json::Value]) -> bool {
    findings.iter().any(|f| {
        let det = f.get("detector_id").and_then(|v| v.as_str()).unwrap_or("");
        let svc = f.get("service").and_then(|v| v.as_str()).unwrap_or("");
        det.contains("github") || svc.contains("github")
    })
}

fn has_detector(findings: &[serde_json::Value], wanted: &[&str]) -> bool {
    findings.iter().any(|f| {
        f.get("detector_id")
            .and_then(|v| v.as_str())
            .is_some_and(|d| wanted.contains(&d))
    })
}

// ---------------------------------------------------------------------------
// Core determinism: --threads 1 vs --threads 4 on the same corpus.
// ---------------------------------------------------------------------------

#[test]
fn threads_1_matches_threads_4_finding_keys() {
    let dir = TempDir::new().expect("tempdir");
    build_corpus(dir.path());

    let (out1, _err1, code1) = run_scan(dir.path(), "1");
    let (out4, _err4, code4) = run_scan(dir.path(), "4");

    assert_eq!(code1, Some(1), "single-thread scan must exit 1 (findings)");
    assert_eq!(code4, Some(1), "four-thread scan must exit 1 (findings)");

    let keys1 = sorted_keys(&parse_findings(&out1));
    let keys4 = sorted_keys(&parse_findings(&out4));

    // The load-bearing determinism contract: concurrency does not change
    // the finding SET. Byte-identical after sorting.
    assert_eq!(
        keys1, keys4,
        "--threads 1 and --threads 4 must produce the identical finding set;\n1={keys1:#?}\n4={keys4:#?}"
    );
}

#[test]
fn threads_1_matches_threads_4_exit_code_is_1() {
    let dir = TempDir::new().expect("tempdir");
    build_corpus(dir.path());

    let (_o1, _e1, code1) = run_scan(dir.path(), "1");
    let (_o4, _e4, code4) = run_scan(dir.path(), "4");

    assert_eq!(code1, Some(1), "1 thread: exit code");
    assert_eq!(code4, Some(1), "4 threads: exit code");
    assert_eq!(code1, code4, "exit code must not depend on thread count");
}

#[test]
fn threads_1_matches_threads_4_finding_count() {
    let dir = TempDir::new().expect("tempdir");
    build_corpus(dir.path());

    let n1 = parse_findings(&run_scan(dir.path(), "1").0).len();
    let n4 = parse_findings(&run_scan(dir.path(), "4").0).len();

    assert_eq!(n1, n4, "finding COUNT must not depend on thread count");
    // Three distinct planted credentials -> at least three findings; a
    // zero/one count would mean the corpus silently stopped detecting.
    assert!(
        n1 >= 3,
        "expected >=3 findings from a 3-credential corpus, got {n1}"
    );
}

#[test]
fn threads_2_matches_baseline_threads_1() {
    let dir = TempDir::new().expect("tempdir");
    build_corpus(dir.path());

    let base = sorted_keys(&parse_findings(&run_scan(dir.path(), "1").0));
    let two = sorted_keys(&parse_findings(&run_scan(dir.path(), "2").0));

    assert_eq!(
        base, two,
        "--threads 2 must match the single-thread baseline set"
    );
}

#[test]
fn threads_8_matches_baseline_threads_1() {
    let dir = TempDir::new().expect("tempdir");
    build_corpus(dir.path());

    let base = sorted_keys(&parse_findings(&run_scan(dir.path(), "1").0));
    let eight = sorted_keys(&parse_findings(&run_scan(dir.path(), "8").0));

    assert_eq!(
        base, eight,
        "--threads 8 (over-subscribed vs corpus size) must match the single-thread baseline set"
    );
}

#[test]
fn credential_hash_set_identical_across_thread_counts() {
    let dir = TempDir::new().expect("tempdir");
    build_corpus(dir.path());

    let base = sorted_unique_hashes(&parse_findings(&run_scan(dir.path(), "1").0));
    // A single-thread scan of a 3-credential corpus yields 3 distinct
    // credential hashes at minimum.
    assert!(
        base.len() >= 3,
        "expected >=3 distinct credential hashes, got {}: {base:?}",
        base.len()
    );

    for threads in ["3", "4", "7"] {
        let other = sorted_unique_hashes(&parse_findings(&run_scan(dir.path(), threads).0));
        assert_eq!(
            base, other,
            "credential-hash set must be identical at --threads {threads}"
        );
    }
}

#[test]
fn detector_id_multiset_identical_across_thread_counts() {
    let dir = TempDir::new().expect("tempdir");
    build_corpus(dir.path());

    let base = sorted_detector_ids(&parse_findings(&run_scan(dir.path(), "1").0));
    let multi = sorted_detector_ids(&parse_findings(&run_scan(dir.path(), "4").0));

    // Multiset (duplicates preserved) — catches a thread count that drops
    // or duplicates a detection without changing the unique-hash set.
    assert_eq!(
        base, multi,
        "detector-id multiset must be identical across thread counts"
    );
}

// ---------------------------------------------------------------------------
// The corpus really fires its expected detectors under BOTH thread counts,
// so the equality tests above are not passing vacuously over empty sets.
// ---------------------------------------------------------------------------

#[test]
fn corpus_fires_github_detector_under_both_thread_counts() {
    let dir = TempDir::new().expect("tempdir");
    build_corpus(dir.path());

    let f1 = parse_findings(&run_scan(dir.path(), "1").0);
    let f4 = parse_findings(&run_scan(dir.path(), "4").0);

    assert!(
        has_github(&f1),
        "single-thread scan must fire a github detector; got {f1:#?}"
    );
    assert!(
        has_github(&f4),
        "four-thread scan must fire a github detector; got {f4:#?}"
    );
}

#[test]
fn corpus_fires_aws_bedrock_detector_under_both_thread_counts() {
    let dir = TempDir::new().expect("tempdir");
    build_corpus(dir.path());

    let f1 = parse_findings(&run_scan(dir.path(), "1").0);
    let f4 = parse_findings(&run_scan(dir.path(), "4").0);

    assert!(
        has_detector(&f1, &["aws-bedrock-api-key"]),
        "single-thread scan must fire aws-bedrock-api-key; got {f1:#?}"
    );
    assert!(
        has_detector(&f4, &["aws-bedrock-api-key"]),
        "four-thread scan must fire aws-bedrock-api-key; got {f4:#?}"
    );
}

#[test]
fn corpus_fires_aws_access_key_detector_under_both_thread_counts() {
    let dir = TempDir::new().expect("tempdir");
    build_corpus(dir.path());

    let f1 = parse_findings(&run_scan(dir.path(), "1").0);
    let f4 = parse_findings(&run_scan(dir.path(), "4").0);

    // AKIA is caught by the named detector or the simdsieve fast path;
    // either is a correct AWS-access-key detection (see e2e_binary.rs).
    assert!(
        has_detector(&f1, &["aws-access-key", "hot-aws_key"]),
        "single-thread scan must fire an AWS access-key detector; got {f1:#?}"
    );
    assert!(
        has_detector(&f4, &["aws-access-key", "hot-aws_key"]),
        "four-thread scan must fire an AWS access-key detector; got {f4:#?}"
    );
}

// ---------------------------------------------------------------------------
// Stability: repeating the SAME thread count is idempotent.
// ---------------------------------------------------------------------------

#[test]
fn repeated_threads_4_runs_are_stable() {
    let dir = TempDir::new().expect("tempdir");
    build_corpus(dir.path());

    let a = sorted_keys(&parse_findings(&run_scan(dir.path(), "4").0));
    let b = sorted_keys(&parse_findings(&run_scan(dir.path(), "4").0));

    assert_eq!(
        a, b,
        "two --threads 4 runs of the same corpus must be identical (no run-to-run nondeterminism)"
    );
}

// ---------------------------------------------------------------------------
// Invalid --threads values are USER errors -> exit 2, with a message that
// is itself the fix (per value_parsers.rs).
// ---------------------------------------------------------------------------

#[test]
fn threads_zero_is_user_error_exit_2() {
    let dir = TempDir::new().expect("tempdir");
    build_corpus(dir.path());

    let (_out, err, code) = run_scan(dir.path(), "0");

    assert_eq!(
        code,
        Some(2),
        "--threads 0 is a usage error -> exit 2, never 1/3; stderr={err}"
    );
    assert!(
        err.contains("--threads must be >= 1"),
        "stderr must state the lower-bound fix; got {err}"
    );
}

#[test]
fn threads_non_integer_is_user_error_exit_2() {
    let dir = TempDir::new().expect("tempdir");
    build_corpus(dir.path());

    let (_out, err, code) = run_scan(dir.path(), "abc");

    assert_eq!(
        code,
        Some(2),
        "--threads abc is a usage error -> exit 2; stderr={err}"
    );
    assert!(
        err.contains("not a valid integer"),
        "stderr must name the parse failure; got {err}"
    );
}

#[test]
fn threads_negative_is_user_error_exit_2() {
    let dir = TempDir::new().expect("tempdir");
    build_corpus(dir.path());

    // `--threads=-3`: the `=` form binds "-3" as the value (a bare
    // `--threads -3` would let clap reject "-3" as an unexpected flag
    // before the value parser runs). usize parse fails -> unparseable.
    let output = Command::new(binary())
        .arg("scan")
        .arg("--daemon=off")
        .args(["--backend", CPU_BACKEND])
        .arg("--threads=-3")
        .args(["--format", "json"])
        .arg(dir.path())
        .env_remove("KEYHOG_BACKEND")
        .output()
        .expect("spawn keyhog scan");
    let err = String::from_utf8_lossy(&output.stderr).into_owned();
    let code = output.status.code();

    assert_eq!(
        code,
        Some(2),
        "--threads=-3 is a usage error -> exit 2; stderr={err}"
    );
    assert!(
        err.contains("not a valid integer"),
        "stderr must name the parse failure for a negative count; got {err}"
    );
}
