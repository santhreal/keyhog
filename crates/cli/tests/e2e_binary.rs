//! End-to-end tests that drive the real `keyhog` binary.
//!
//! Per the per-rule contract (CLAUDE.md test type 10), "the product
//! is the binary." These tests:
//!
//! * use `env!("CARGO_BIN_EXE_keyhog")` - cargo points this at the
//!   freshly built `keyhog` binary in `target/<profile>/keyhog`, so we
//!   exercise the same executable users get;
//! * write a planted-credential fixture to `tempfile::TempDir` (out of
//!   the workspace, so `.gitignore` skip rules don't interfere - keyhog
//!   walks `.internal/` etc. as gitignored, which this test would
//!   otherwise trip);
//! * parse `--format json` stdout, verify shape + counts;
//! * verify the documented exit codes.
//!
//! The fixture is small and self-contained so the test is fast
//! enough to live in the normal `cargo test` flow.

use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// One-line helper: write a temp file with given content, scan it
/// with `--format json`, return (stdout, stderr, exit-code).
fn scan_text_file(content: &str, extra_args: &[&str]) -> (String, String, Option<i32>) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("planted.txt");
    std::fs::write(&path, content).expect("write fixture");

    let output = Command::new(binary())
        .arg("scan")
        .args(extra_args)
        .arg("--format")
        .arg("json")
        .arg(&path)
        .output()
        .expect("spawn keyhog scan");

    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.code(),
    )
}

#[test]
fn scan_finds_planted_aws_key_and_returns_exit_1() {
    let fixture = "AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"\n";
    let (stdout, _stderr, code) = scan_text_file(fixture, &[]);

    // Documented exit codes: 0 = clean, 1 = unverified findings.
    // Planted key with no `--verify` should land us at 1.
    assert_eq!(
        code,
        Some(1),
        "expected exit 1 (unverified findings); got {code:?}"
    );

    let findings: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is valid JSON");
    let arr = findings.as_array().expect("findings JSON is an array");
    assert!(!arr.is_empty(), "expected at least one finding");
    let aws = arr
        .iter()
        .find(|f| f.get("detector_id").and_then(|v| v.as_str()) == Some("aws-access-key"));
    assert!(
        aws.is_some(),
        "expected aws-access-key finding; got: {arr:?}",
    );
}

#[test]
fn scan_returns_exit_0_on_clean_file() {
    let fixture = "fn main() { println!(\"hello\"); }\n";
    let (stdout, _stderr, code) = scan_text_file(fixture, &[]);

    assert_eq!(code, Some(0), "expected exit 0 on clean file; got {code:?}");
    let findings: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is valid JSON");
    let arr = findings.as_array().expect("findings JSON is an array");
    assert!(arr.is_empty(), "expected zero findings; got: {arr:?}");
}

#[test]
fn scan_json_schema_carries_required_fields() {
    let fixture = "GH_TOKEN = \"ghp_aBcD1234EFgh5678ijkl9012MNop3456qrST\"\n";
    let (stdout, _stderr, _code) = scan_text_file(fixture, &[]);

    let findings: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is valid JSON");
    let arr = findings.as_array().expect("findings JSON is an array");
    assert!(!arr.is_empty(), "expected the GH token to fire");

    // Every finding MUST carry the contract fields downstream
    // consumers (CI gates, SARIF converters, IDE plugins) depend on.
    for f in arr {
        for required in [
            "detector_id",
            "detector_name",
            "service",
            "severity",
            "credential_redacted",
            "credential_hash",
            "location",
            "verification",
        ] {
            assert!(
                f.get(required).is_some(),
                "finding is missing required field `{required}`: {f}",
            );
        }
        let loc = f.get("location").unwrap();
        for required in ["source", "file_path", "line", "offset"] {
            assert!(
                loc.get(required).is_some(),
                "location is missing required field `{required}`: {loc}",
            );
        }
    }
}

/// README binding test: the banner advertises an exact detector +
/// pattern count. If we add detectors or rewrite a regex pair, the
/// banner becomes a lie unless updated. This test surfaces drift
/// before it ships.
///
/// README line under audit (root README.md):
///   `KeyHog vX.Y.Z | ... | 889 detectors (1665 patterns)`
///
/// When you legitimately change the counts:
///   1. Update README.md banner.
///   2. Update these two constants.
///   3. CI stays green.
#[test]
fn readme_banner_counts_match_loaded_corpus() {
    const README_DETECTOR_COUNT: usize = 891;
    const README_PATTERN_COUNT: usize = 1647;

    let output = Command::new(binary())
        .arg("detectors")
        .arg("--json")
        .output()
        .expect("spawn keyhog detectors --json");
    assert_eq!(output.status.code(), Some(0));
    let arr: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("detectors JSON parse");
    let actual_patterns: usize = arr
        .iter()
        .map(|d| {
            d.get("patterns")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0)
        })
        .sum();

    assert_eq!(
        arr.len(),
        README_DETECTOR_COUNT,
        "README banner says {README_DETECTOR_COUNT} detectors; actual={}. \
         Update README and the constant in this test together.",
        arr.len(),
    );
    assert_eq!(
        actual_patterns, README_PATTERN_COUNT,
        "README banner says {README_PATTERN_COUNT} patterns; actual={actual_patterns}. \
         Update README and the constant in this test together.",
    );
}

#[test]
fn detectors_subcommand_emits_json_array() {
    let output = Command::new(binary())
        .arg("detectors")
        .arg("--json")
        .output()
        .expect("spawn keyhog detectors --json");
    assert_eq!(
        output.status.code(),
        Some(0),
        "detectors --json should exit 0; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("detectors --json stdout is valid JSON");
    let arr = parsed.as_array().expect("--json output is a JSON array");
    assert!(
        arr.len() > 100,
        "expected hundreds of detectors; got {}",
        arr.len()
    );
    // Spot-check one well-known detector.
    let aws = arr
        .iter()
        .find(|d| d.get("id").and_then(|v| v.as_str()) == Some("aws-access-key"));
    assert!(
        aws.is_some(),
        "aws-access-key should appear in --json output"
    );
    let aws = aws.unwrap();
    assert_eq!(
        aws.get("service").and_then(|v| v.as_str()),
        Some("aws"),
        "aws-access-key should have service=aws",
    );
}

/// Tier-B suppression flag: by default keyhog suppresses Stripe's
/// public docs demo key (and other documented test fixtures), so
/// scanning a fixture containing it surfaces 0 findings. Passing
/// `--no-suppress-test-fixtures` flips that - the same fixture
/// produces the finding gitleaks and trufflehog also report.
///
/// This is the binding test for the Tier-B move (task #60). If
/// someone deletes the bundled `test-fixtures.toml` entry for
/// Stripe, the default-mode assertion below catches it; if someone
/// drops the `--no-suppress-test-fixtures` arg, the opt-out branch
/// catches it.
#[test]
fn no_suppress_test_fixtures_surfaces_stripe_demo_key() {
    // The canonical Stripe public-docs demo key. Split via `concat!`
    // so GitHub Push Protection doesn't scan this source file as a
    // live secret leak.
    let stripe_key = concat!("sk_", "live_", "4eC39HqLyjWDarjtT1zdp7dc");
    let fixture = format!("STRIPE_KEY = \"{stripe_key}\"\n");

    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("planted.txt");
    std::fs::write(&path, &fixture).expect("write fixture");

    // ----- default: suppressed -----------------------------------
    let default_out = Command::new(binary())
        .arg("scan")
        .arg("--format")
        .arg("json")
        .arg(&path)
        .output()
        .expect("spawn keyhog scan (default)");
    let default_json = String::from_utf8_lossy(&default_out.stdout);
    let default_findings: serde_json::Value =
        serde_json::from_str(&default_json).expect("default-mode stdout is JSON");
    let default_arr = default_findings.as_array().expect("array");
    let has_stripe = default_arr
        .iter()
        .any(|f| f.get("service").and_then(|v| v.as_str()) == Some("stripe"));
    assert!(
        !has_stripe,
        "default mode MUST suppress the Stripe demo key; got findings: {default_arr:?}"
    );

    // ----- --no-suppress-test-fixtures: surfaced -----------------
    let optout_out = Command::new(binary())
        .arg("scan")
        .arg("--no-suppress-test-fixtures")
        .arg("--format")
        .arg("json")
        .arg(&path)
        .output()
        .expect("spawn keyhog scan (opt-out)");
    let optout_json = String::from_utf8_lossy(&optout_out.stdout);
    let optout_findings: serde_json::Value =
        serde_json::from_str(&optout_json).expect("opt-out stdout is JSON");
    let optout_arr = optout_findings.as_array().expect("array");
    let has_stripe_now = optout_arr
        .iter()
        .any(|f| f.get("service").and_then(|v| v.as_str()) == Some("stripe"));
    assert!(
        has_stripe_now,
        "--no-suppress-test-fixtures MUST surface the Stripe demo key; \
         got findings: {optout_arr:?}"
    );
}

/// Regression for the demo-secret.env UX bug originally flagged
/// in TODO.md (2026-05-17): scanning a file that holds an
/// AWS-published EXAMPLE credential (AKIAIOSFODNN7EXAMPLE) used to
/// print "No secrets found. Your code is clean." - identical to a
/// genuinely clean repo - because the test-fixture suppression
/// filtered the match BEFORE the example-suppression telemetry
/// counter saw it. The reporter then read counter=0 and chose the
/// clean-repo summary.
///
/// v0.5.6 wired `record_example_suppression` for the engine-side
/// EXAMPLE token check, but missed this orchestrator-level
/// test-fixture filter, so the bug came back as soon as the AWS
/// fixture went through the substring suppression instead of the
/// engine path. This test pins the right behaviour:
///
/// * Default mode → output contains "example/test key" and does
///   NOT contain the all-clean summary.
/// * The bundled AWS-EXAMPLE entry must still suppress (no
///   finding shown in the matches list).
#[test]
fn demo_secret_aws_example_summary_distinguishes_suppression_from_clean() {
    let fixture = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n";
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("demo-secret.env");
    std::fs::write(&path, fixture).expect("write fixture");

    // --no-daemon to guarantee the in-process orchestrator path is
    // exercised (the daemon path lives in `subcommands/scan.rs` and
    // is locked by `daemon_route_test_fixture_suppression_records_telemetry`
    // below).
    let out = Command::new(binary())
        .arg("scan")
        .arg("--no-daemon")
        .arg("--format")
        .arg("text")
        .arg(&path)
        .output()
        .expect("spawn keyhog scan demo-secret.env");
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        stdout.contains("example/test key") && stdout.contains("suppressed"),
        "demo-secret.env summary must distinguish suppressed-example from a \
         clean repo. Got stdout: {stdout}"
    );
    assert!(
        !stdout.contains("Your code is clean."),
        "the clean-repo summary must NOT fire when an example credential was \
         suppressed. Got stdout: {stdout}"
    );
}

#[test]
fn explicit_format_text_does_not_emit_json() {
    let fixture = "AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"\n";
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("planted.txt");
    std::fs::write(&path, fixture).expect("write fixture");

    // Don't share the json-format helper here - text-format is the
    // contrast case we're asserting.
    let output = Command::new(binary())
        .arg("scan")
        .arg("--format")
        .arg("text")
        .arg(&path)
        .output()
        .expect("spawn keyhog scan --format text");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");

    // Text mode is the human-facing default. The hard contract:
    // (1) stdout MUST NOT start with `[` (would mean JSON leaked
    //     through), and (2) the combined stream must reference the
    //     finding somewhere - text reporter writes to stdout or
    //     stderr depending on `--output`; we accept either.
    assert!(
        !stdout.trim_start().starts_with('['),
        "text format must not start with JSON `[`; got: {stdout}",
    );
    assert!(
        combined.to_lowercase().contains("aws") || combined.contains("AKIA"),
        "text format should mention the finding somewhere; \
         stdout={stdout:?}, stderr={stderr:?}, exit={:?}",
        output.status.code(),
    );
}

/// `--scan-comments` end-to-end: a credential pasted inside a
/// `// TODO: rotate this …` comment is suppressed by default (the
/// common case is an EXAMPLE token in a doc comment) but surfaces
/// when the operator opts in. Pins the wiring all the way from the
/// clap flag → ScanArgs → orchestrator_config::scan_comments →
/// ScannerConfig.scan_comments → fallback_generic + engine context-
/// penalty gates.
#[test]
fn scan_comments_flag_surfaces_credentials_in_comments() {
    // A genuine-shape AWS access key inside a `//`-style comment.
    // Default scan applies the comment-context confidence penalty
    // and the finding falls below `min_confidence`; --scan-comments
    // lifts it.
    let aws_key = concat!("AKIA", "ROTATIONNEEDED7777Q");
    let fixture = format!("// TODO: rotate this - {aws_key}\n");

    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("comment_planted.go");
    std::fs::write(&path, &fixture).expect("write fixture");

    // Default: comment-context penalty in effect; AWS prefix is
    // strong enough to still fire on this one, so we don't assert
    // the *absence* of the finding (that would be brittle to
    // confidence-floor tuning). What we DO assert is that
    // --scan-comments AT LEAST matches the default - never silently
    // hides findings the default would surface.
    let default_out = Command::new(binary())
        .arg("scan")
        .arg("--format")
        .arg("json")
        .arg(&path)
        .output()
        .expect("spawn keyhog scan (default)");
    let default_json = String::from_utf8_lossy(&default_out.stdout);
    let default_findings: serde_json::Value =
        serde_json::from_str(&default_json).expect("default-mode stdout is JSON");
    let default_count = default_findings.as_array().map(|a| a.len()).unwrap_or(0);

    let opt_in_out = Command::new(binary())
        .arg("scan")
        .arg("--scan-comments")
        .arg("--format")
        .arg("json")
        .arg(&path)
        .output()
        .expect("spawn keyhog scan --scan-comments");
    let opt_in_json = String::from_utf8_lossy(&opt_in_out.stdout);
    let opt_in_findings: serde_json::Value =
        serde_json::from_str(&opt_in_json).expect("opt-in stdout is JSON");
    let opt_in_count = opt_in_findings.as_array().map(|a| a.len()).unwrap_or(0);

    assert!(
        opt_in_count >= default_count,
        "--scan-comments must not LOSE findings vs default; \
         default={default_count}, --scan-comments={opt_in_count}, \
         default_json={default_json}, opt_in_json={opt_in_json}"
    );

    // At minimum --scan-comments fires on this AKIA-prefixed key
    // (the keyhog known-prefix floor keeps it above any penalty).
    assert!(
        opt_in_count >= 1,
        "--scan-comments MUST surface the AKIA-prefixed key in the \
         comment; got {opt_in_count} findings: {opt_in_json}"
    );
}

fn workspace_detectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../detectors")
        .canonicalize()
        .expect("workspace detectors dir")
}

#[cfg(feature = "git")]
fn init_git_repo(repo_path: &std::path::Path) {
    use std::process::Command;
    for args in [
        ["init", "-b", "main"],
        ["config", "user.email", "test@example.com"],
        ["config", "user.name", "Test User"],
    ] {
        let output = Command::new("git")
            .args(args)
            .current_dir(repo_path)
            .output()
            .expect("git setup");
        assert!(output.status.success(), "git setup failed: {output:?}");
    }
}

#[cfg(feature = "git")]
#[test]
fn git_staged_scan_finds_only_staged_secret() {
    use std::process::Command;

    let repo = TempDir::new().expect("tempdir");
    let repo_path = repo.path();
    init_git_repo(repo_path);

    std::fs::write(
        repo_path.join("staged.env"),
        "AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"\n",
    )
    .unwrap();
    std::fs::write(
        repo_path.join("unstaged.env"),
        "AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HUNSTAGEDKEY000000000000\"\n",
    )
    .unwrap();
    Command::new("git")
        .args(["add", "staged.env"])
        .current_dir(repo_path)
        .output()
        .unwrap();

    let output = Command::new(binary())
        .current_dir(repo_path)
        .args([
            "scan",
            "--git-staged",
            "--no-daemon",
            "--format",
            "json",
            "--path",
            ".",
        ])
        .output()
        .expect("git-staged scan");

    assert_eq!(
        output.status.code(),
        Some(1),
        "staged secret must exit 1; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let findings: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout is JSON");
    let arr = findings.as_array().expect("array");
    assert!(
        arr.iter().any(|f| {
            f.get("location")
                .and_then(|l| l.get("file_path"))
                .and_then(|p| p.as_str())
                .is_some_and(|p| p.ends_with("staged.env"))
        }),
        "must find staged file secret; got {arr:?}"
    );
    assert!(
        !arr.iter().any(|f| {
            f.get("location")
                .and_then(|l| l.get("file_path"))
                .and_then(|p| p.as_str())
                .is_some_and(|p| p.contains("unstaged.env"))
        }),
        "unstaged file must not be scanned; got {arr:?}"
    );
}

#[test]
fn baseline_suppresses_acknowledged_findings_on_rescan() {
    let dir = TempDir::new().expect("tempdir");
    let fixture = dir.path().join("planted.txt");
    std::fs::write(&fixture, "AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"\n").unwrap();
    let baseline_path = dir.path().join("baseline.json");

    let create = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--create-baseline",
            baseline_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .arg(&fixture)
        .output()
        .expect("create baseline");
    assert_eq!(
        create.status.code(),
        Some(0),
        "create-baseline must exit 0; stderr={}",
        String::from_utf8_lossy(&create.stderr)
    );
    assert!(baseline_path.exists(), "baseline file must be written");

    let filtered = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--baseline",
            baseline_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .arg(&fixture)
        .output()
        .expect("baseline-filter scan");
    assert_eq!(
        filtered.status.code(),
        Some(0),
        "baseline-filtered rescan must exit 0; stderr={}",
        String::from_utf8_lossy(&filtered.stderr)
    );
    let findings: serde_json::Value =
        serde_json::from_slice(&filtered.stdout).expect("filtered stdout is JSON");
    assert!(
        findings.as_array().is_some_and(|a| a.is_empty()),
        "baseline must suppress known findings; got {findings:?}"
    );
}

#[test]
fn lockdown_bails_on_verify_flag() {
    let dir = TempDir::new().expect("tempdir");
    let fixture = dir.path().join("planted.txt");
    std::fs::write(&fixture, "AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"\n").unwrap();

    // Lockdown requires RLIMIT_CORE=0 on Linux so coredump_filter checks
    // pass; `prlimit --core=0` sets that for the child without touching
    // the test runner's own limits.
    let mut cmd = Command::new("prlimit");
    cmd.args(["--core=0"])
        .arg(binary())
        .args([
            "scan",
            "--no-daemon",
            "--lockdown",
            "--verify",
            "--format",
            "json",
        ])
        .arg(&fixture);
    let output = match cmd.output() {
        Ok(out) => out,
        Err(_) => Command::new(binary())
            .args([
                "scan",
                "--no-daemon",
                "--lockdown",
                "--verify",
                "--format",
                "json",
            ])
            .arg(&fixture)
            .output()
            .expect("lockdown+verify scan"),
    };

    assert_eq!(
        output.status.code(),
        Some(2),
        "lockdown+verify must exit 2 (runtime error); got {:?}",
        output.status.code()
    );
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("lockdown mode forbids --verify")
            || combined.contains("protections failed to apply"),
        "must refuse outbound verification in lockdown (or fail closed on \
         hardening); got: {combined}"
    );
    if !combined.contains("protections failed to apply") {
        assert!(
            combined.contains("lockdown mode forbids --verify"),
            "when lockdown protections apply, --verify must be refused; got: {combined}"
        );
    }
}

#[cfg(unix)]
#[test]
fn daemon_wire_scan_path_finds_planted_secret() {
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    let runtime = TempDir::new().expect("runtime dir");
    let dir = TempDir::new().expect("fixture dir");
    let fixture = dir.path().join("daemon_planted.txt");
    std::fs::write(&fixture, "AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"\n").unwrap();

    let detectors = workspace_detectors();
    let mut daemon: Child = Command::new(binary())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .args([
            "daemon",
            "start",
            "--detectors",
            detectors.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon");

    let socket = runtime.path().join("keyhog.sock");
    let deadline = Instant::now() + Duration::from_secs(30);
    while !socket.exists() {
        assert!(
            Instant::now() < deadline,
            "daemon socket did not appear in time"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    let scan = Command::new(binary())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .args(["scan", "--daemon", "--format", "json"])
        .arg(&fixture)
        .output()
        .expect("daemon scan");

    let _ = Command::new(binary())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .args(["daemon", "stop"])
        .output();
    let _ = daemon.kill();
    let _ = daemon.wait();

    assert_eq!(
        scan.status.code(),
        Some(1),
        "daemon scan must find secret (exit 1); stderr={}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let findings: serde_json::Value =
        serde_json::from_slice(&scan.stdout).expect("daemon stdout is JSON");
    let arr = findings.as_array().expect("array");
    assert!(
        arr.iter()
            .any(|f| f.get("detector_id").and_then(|v| v.as_str()) == Some("aws-access-key")),
        "daemon wire path must return aws finding; got {arr:?}"
    );
}
