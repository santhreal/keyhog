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

fn repo_root() -> PathBuf {
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root
}

fn detector_dir() -> PathBuf {
    repo_root().join("detectors")
}

fn doc_text(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel))
        .unwrap_or_else(|error| panic!("read {rel} for doc/banner coherence contract: {error}"))
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

fn forced_simd_progress_banner() -> String {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("clean.txt");
    std::fs::write(&path, "hello world\n").expect("write fixture");

    let output = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--progress",
            "--format",
            "json",
            "--backend",
            "simd",
        ])
        .arg(&path)
        .output()
        .expect("spawn keyhog scan --progress");
    assert_eq!(
        output.status.code(),
        Some(0),
        "clean progress scan should exit 0; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    stderr
        .lines()
        .find(|line| {
            line.contains("detectors (") && line.contains("patterns)") && line.contains("backend=")
        })
        .unwrap_or_else(|| panic!("progress banner missing from stderr:\n{stderr}"))
        .to_owned()
}

fn parse_banner_counts(line: &str) -> (usize, usize) {
    let marker = " detectors (";
    let detector_end = line
        .find(marker)
        .unwrap_or_else(|| panic!("progress banner missing detector marker: {line}"));
    let detector_count = line[..detector_end]
        .split_whitespace()
        .last()
        .unwrap_or_else(|| panic!("progress banner missing detector count: {line}"))
        .parse()
        .unwrap_or_else(|error| panic!("progress banner detector count is not numeric: {error}"));
    let pattern_count = line[detector_end + marker.len()..]
        .split_whitespace()
        .next()
        .unwrap_or_else(|| panic!("progress banner missing pattern count: {line}"))
        .parse()
        .unwrap_or_else(|error| panic!("progress banner pattern count is not numeric: {error}"));
    (detector_count, pattern_count)
}

#[test]
fn scan_finds_planted_aws_key_and_returns_exit_1() {
    let fixture = concat!("AWS_ACCESS_KEY_ID = \"AKIA", "QYLPMN5HFIQR7XYA\"\n");
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
    // Non-emptiness is proven by the exact AWS-detector assert below; a bare
    // shape assert here would pass on a single junk finding.
    // An AKIA key is caught by the simdsieve fast path (`hot-aws_key`) when it
    // engages, otherwise by the named `aws-access-key` detector. Both are a
    // correct AWS detection - assert on either so the test does not break on a
    // backend/size-dependent fast-path engagement decision.
    let aws = arr.iter().find(|f| {
        matches!(
            f.get("detector_id").and_then(|v| v.as_str()),
            Some("aws-access-key" | "hot-aws_key")
        )
    });
    assert!(aws.is_some(), "expected an AWS key finding; got: {arr:?}");
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

/// G1 binary proof: a planted long-term AWS Bedrock API key surfaces through
/// the real binary under the `aws-bedrock-api-key` detector and lands exit 1
/// (findings present, none verified live). Split-literal so the test file
/// itself isn't a planted-secret tripwire.
#[test]
fn scan_finds_planted_bedrock_key_and_returns_exit_1() {
    let fixture = concat!(
        "AWS_BEARER_TOKEN_BEDROCK=\"ABSKQmVkcm9ja0FQSUtleS",
        "y2J0fajDUXD1efoRCtqKODGGBi8UWr7UJsq2tkhFhx8ZEDEd9hnKHivse0YHShMdeCAbPEOXOxyhkg5cqNGHA1grwAyKC3Y8HDD62wLdl37iKN\"\n",
    );
    let (stdout, _stderr, code) = scan_text_file(fixture, &[]);
    assert_eq!(
        code,
        Some(1),
        "planted Bedrock key should exit 1; got {code:?}"
    );
    let arr: Vec<serde_json::Value> = serde_json::from_str(&stdout).expect("stdout is valid JSON");
    let bedrock = arr
        .iter()
        .find(|f| f.get("detector_id").and_then(|v| v.as_str()) == Some("aws-bedrock-api-key"));
    assert!(
        bedrock.is_some(),
        "expected an aws-bedrock-api-key finding; got: {arr:?}",
    );
    assert_eq!(
        bedrock.unwrap().get("severity").and_then(|v| v.as_str()),
        Some("critical"),
        "Bedrock key must be critical severity",
    );
}

/// Exit-code contract (`docs/src/reference/exit-codes.md`, row `2`): an
/// unknown CLI flag is user error → exit 2, never 1 or 3.
#[test]
fn scan_unknown_flag_exits_2() {
    let dir = TempDir::new().expect("tempdir");
    let output = Command::new(binary())
        .arg("scan")
        .arg("--this-flag-does-not-exist")
        .arg(dir.path())
        .output()
        .expect("spawn keyhog scan");
    assert_eq!(
        output.status.code(),
        Some(2),
        "unknown flag must exit 2 (user error); stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Exit-code contract: a source backend the user named that can't read its
/// input (`--git-history` on a non-git directory) is a distinct source failure
/// -> exit 13, not generic user-error 2 or system-error 3.
#[test]
fn scan_git_history_on_non_repo_exits_13() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "nothing here\n").expect("write");
    let output = Command::new(binary())
        .arg("scan")
        .arg("--git-history")
        .arg(dir.path())
        .output()
        .expect("spawn keyhog scan --git-history");
    assert_eq!(
        output.status.code(),
        Some(13),
        "--git-history on a non-git dir must exit 13 (source failed), not 2/3; stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Exit-code contract: `diff` with a baseline file the user named that does
/// not exist is user error → exit 2 (not 1 = "no new entries", not 3).
#[test]
fn diff_missing_baseline_exits_2() {
    let dir = TempDir::new().expect("tempdir");
    let output = Command::new(binary())
        .arg("diff")
        .arg(dir.path().join("before.json"))
        .arg(dir.path().join("after.json"))
        .output()
        .expect("spawn keyhog diff");
    assert_eq!(
        output.status.code(),
        Some(2),
        "diff with a missing baseline must exit 2 (user error); stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn scan_json_schema_carries_required_fields() {
    let fixture = "GH_TOKEN = \"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\"\n";
    let (stdout, _stderr, _code) = scan_text_file(fixture, &[]);

    let findings: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is valid JSON");
    let arr = findings.as_array().expect("findings JSON is an array");
    // Truth assert (not "some finding"): the planted ghp_ token fired a GitHub
    // detector on line 1 — otherwise the field-presence loop below would pass
    // vacuously over an empty array.
    let gh = arr.iter().find(|f| {
        let det = f.get("detector_id").and_then(|v| v.as_str()).unwrap_or("");
        let svc = f.get("service").and_then(|v| v.as_str()).unwrap_or("");
        (det.contains("github") || svc.contains("github"))
            && f.pointer("/location/line").and_then(|v| v.as_u64()) == Some(1)
    });
    assert!(
        gh.is_some(),
        "expected the planted ghp_ token to fire a GitHub detector on line 1; got {arr:?}"
    );

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

/// Shipped-artifact binding test: the binary must advertise exactly the
/// detector + pattern corpus it was built from. Both expected counts are
/// DERIVED from `keyhog_core::load_detectors` over the on-disk `detectors/`
/// tree — the same set `build.rs` embeds — so adding/removing a detector
/// never requires editing a literal here (the count is single-sourced from
/// the loader; the README headline is pinned separately in
/// `scanner/tests/readme_claims.rs`).
#[test]
fn readme_banner_counts_match_loaded_corpus() {
    let detector_dir = detector_dir();
    let specs = keyhog_core::load_detectors(&detector_dir).expect("load detectors/ corpus");
    let expected_detectors = specs.len();
    let expected_patterns: usize = specs.iter().map(|d| d.patterns.len()).sum();

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
        expected_detectors,
        "binary advertises {} detectors but the on-disk corpus has {expected_detectors}. \
         The shipped binary embeds a stale set — rebuild, or a detector silently failed \
         to embed.",
        arr.len(),
    );
    assert_eq!(
        actual_patterns, expected_patterns,
        "binary advertises {actual_patterns} patterns but the on-disk corpus has \
         {expected_patterns}. Binary/corpus pattern drift.",
    );
}

#[test]
fn docs_scan_banners_match_live_binary_banner_contract() {
    let detector_dir = detector_dir();
    let specs = keyhog_core::load_detectors(&detector_dir).expect("load detectors/ corpus");
    let expected_detectors = specs.len();

    let version_output = Command::new(binary())
        .arg("--version")
        .output()
        .expect("spawn keyhog --version");
    assert_eq!(
        version_output.status.code(),
        Some(0),
        "--version must exit 0; stderr={}",
        String::from_utf8_lossy(&version_output.stderr)
    );
    let version_stdout = String::from_utf8_lossy(&version_output.stdout);
    assert!(
        version_stdout.contains(env!("CARGO_PKG_VERSION")),
        "--version output must expose the workspace version {}; got {version_stdout}",
        env!("CARGO_PKG_VERSION")
    );

    let progress_banner = forced_simd_progress_banner();
    let (banner_detectors, banner_patterns) = parse_banner_counts(&progress_banner);
    assert_eq!(
        banner_detectors, expected_detectors,
        "live progress banner detector count drifted from loaded corpus; banner={progress_banner}"
    );
    assert!(
        banner_patterns >= banner_detectors,
        "compiled pattern count must not be smaller than detector count; banner={progress_banner}"
    );

    let version_fragment = format!(
        "v{} · secret scanner · {expected_detectors} detectors",
        env!("CARGO_PKG_VERSION")
    );
    let compiled_count_fragment =
        format!("{expected_detectors} detectors ({banner_patterns} patterns)");
    for rel in ["docs/src/introduction.md", "docs/src/first-scan.md"] {
        let doc = doc_text(rel);
        assert!(
            doc.contains("K E Y H O G") && doc.contains("by santh"),
            "{rel} must show the real multi-line KeyHog banner"
        );
        assert!(
            doc.contains(&version_fragment),
            "{rel} must use the live --version/detector banner `{version_fragment}`"
        );
        assert!(
            doc.contains(&compiled_count_fragment),
            "{rel} must pin the live compiled scanner pattern count `{compiled_count_fragment}`"
        );
        assert!(
            doc.contains("backend=") && doc.contains("gpu="),
            "{rel} must show operator-visible backend/gpu decision fields"
        );
        assert!(
            !doc.contains("AVX-512 + Hyperscan + CUDA") && !doc.contains("1666 patterns"),
            "{rel} still contains the stale one-line fabricated banner"
        );
    }
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

#[test]
fn no_suppress_test_fixtures_surfaces_test_path_findings() {
    let fixture = "DATABASE_URL=postgres://admin:S3cr3tP4ssw0rd@db.example.com:5432/prod\n";

    let dir = TempDir::new().expect("tempdir");
    let fixture_dir = dir.path().join("tests").join("fixtures");
    std::fs::create_dir_all(&fixture_dir).expect("create fixture dir");
    let path = fixture_dir.join("planted.env");
    std::fs::write(&path, fixture).expect("write fixture");

    let default_out = Command::new(binary())
        .arg("scan")
        .arg("--no-daemon")
        .arg("--format")
        .arg("json")
        .arg("--min-confidence")
        .arg("0.0")
        .arg(&path)
        .output()
        .expect("spawn keyhog scan (default)");
    let default_json = String::from_utf8_lossy(&default_out.stdout);
    let default_findings: serde_json::Value =
        serde_json::from_str(&default_json).expect("default-mode stdout is JSON");
    assert_eq!(
        default_findings.as_array().map(Vec::len),
        Some(0),
        "default mode should suppress low-confidence test-path findings; got {default_json}"
    );

    let optout_out = Command::new(binary())
        .arg("scan")
        .arg("--no-daemon")
        .arg("--no-suppress-test-fixtures")
        .arg("--format")
        .arg("json")
        .arg("--min-confidence")
        .arg("0.0")
        .arg(&path)
        .output()
        .expect("spawn keyhog scan (opt-out)");
    let optout_json = String::from_utf8_lossy(&optout_out.stdout);
    let optout_findings: serde_json::Value =
        serde_json::from_str(&optout_json).expect("opt-out stdout is JSON");
    let optout_arr = optout_findings.as_array().expect("array");
    let surfaced = optout_arr.iter().find(|f| {
        f.get("detector_id").and_then(|v| v.as_str()) == Some("generic-password")
            && f.pointer("/location/line").and_then(|v| v.as_u64()) == Some(1)
            && f.pointer("/location/file_path")
                .and_then(|v| v.as_str())
                .is_some_and(|p| p.contains("/tests/fixtures/"))
    });
    assert!(
        surfaced.is_some(),
        "--no-suppress-test-fixtures must surface test-path findings; got {optout_json}"
    );
    let confidence = surfaced
        .and_then(|f| f.get("confidence"))
        .and_then(|v| v.as_f64())
        .unwrap_or_default();
    assert!(
        confidence >= 0.69,
        "fixture opt-out must bypass pre-ML test-path down-weighting; got {confidence}"
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
    let fixture = concat!("AWS_ACCESS_KEY_ID = \"AKIA", "QYLPMN5HFIQR7XYA\"\n");
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

/// `--scan-comments` end-to-end: pins the wiring all the way from the
/// clap flag → ScanArgs → orchestrator_config::scan_comments →
/// ScannerConfig.scan_comments → fallback_generic + engine context-
/// penalty gates. The invariant under test is that `--scan-comments`
/// never loses findings versus the default and surfaces a credential
/// planted in a `// TODO: rotate this …` comment. (A strong known-prefix
/// key like AWS clears the comment-context penalty in both modes; a
/// weaker token would be the one the opt-in lifts above the floor.)
#[test]
fn scan_comments_flag_surfaces_credentials_in_comments() {
    // A genuine-shape AWS access key — exactly 20 chars (`AKIA` + 16) —
    // inside a `//`-style comment. The length is load-bearing: the
    // aws-access-key detector requires the canonical 20-char form, so a
    // longer `AKIA…` string is correctly rejected as malformed and would
    // never reach the comment-context path this test exercises.
    let aws_key = concat!("AKIA", "ROTATIONNEEDED77");
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
        concat!("AWS_ACCESS_KEY_ID = \"AKIA", "QYLPMN5HFIQR7XYA\"\n"),
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
            "--backend",
            "simd",
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
    std::fs::write(
        &fixture,
        concat!("AWS_ACCESS_KEY_ID = \"AKIA", "QYLPMN5HFIQR7XYA\"\n"),
    )
    .unwrap();
    let baseline_path = dir.path().join("baseline.json");

    let create = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--backend",
            "simd",
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
            "--backend",
            "simd",
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
    std::fs::write(
        &fixture,
        concat!("AWS_ACCESS_KEY_ID = \"AKIA", "QYLPMN5HFIQR7XYA\"\n"),
    )
    .unwrap();

    // Lockdown requires RLIMIT_CORE=0 on Linux so coredump_filter checks
    // pass; `prlimit --core=0` sets that for the child without touching
    // the test runner's own limits.
    let mut cmd = Command::new("prlimit");
    cmd.args(["--core=0"])
        .arg(binary())
        .args([
            "scan",
            "--no-daemon",
            "--backend",
            "simd",
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
                "--backend",
                "simd",
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
        "lockdown+verify must exit 2 (user error); got {:?}",
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

/// Start a real `keyhog daemon` over a Unix socket in a throwaway
/// `XDG_RUNTIME_DIR`, blocking until the socket binds (or panicking on
/// a 30s timeout). Returns the runtime `TempDir` (its `keyhog.sock`
/// lives at `<runtime>/keyhog.sock`) plus the daemon `Child` so the
/// caller can `XDG_RUNTIME_DIR`-pin its scan client to the same socket
/// and tear the daemon down with `stop_daemon` afterwards.
///
/// Factored out of the per-route daemon e2e tests so the start/wait
/// boilerplate isn't copy-pasted (NO DUPLICATION): the ScanPath,
/// ScanText/stdin, example-suppression-wire, and `daemon status`
/// tests all drive the same real listener through this one helper.
#[cfg(unix)]
fn start_daemon() -> (TempDir, std::process::Child) {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let runtime = TempDir::new().expect("runtime dir");
    let detectors = workspace_detectors();
    let daemon = Command::new(binary())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .args([
            "daemon",
            "start",
            "--backend",
            "simd",
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
    (runtime, daemon)
}

/// Tear down a daemon started by `start_daemon`: ask it to stop over
/// the socket, then make sure the child is reaped.
#[cfg(unix)]
fn stop_daemon(runtime: &TempDir, daemon: &mut std::process::Child) {
    use std::process::Command;
    let _ = Command::new(binary())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .args(["daemon", "stop"])
        .output();
    let _ = daemon.kill();
    let _ = daemon.wait();
}

#[cfg(unix)]
#[test]
fn daemon_wire_scan_path_finds_planted_secret() {
    use std::process::Command;

    let dir = TempDir::new().expect("fixture dir");
    let fixture = dir.path().join("daemon_planted.txt");
    std::fs::write(
        &fixture,
        concat!("AWS_ACCESS_KEY_ID = \"AKIA", "QYLPMN5HFIQR7XYA\"\n"),
    )
    .unwrap();

    let (runtime, mut daemon) = start_daemon();

    let scan = Command::new(binary())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .args(["scan", "--daemon", "--backend", "simd", "--format", "json"])
        .arg(&fixture)
        .output()
        .expect("daemon scan");

    stop_daemon(&runtime, &mut daemon);

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
        arr.iter().any(|f| matches!(
            f.get("detector_id").and_then(|v| v.as_str()),
            Some("aws-access-key" | "hot-aws_key")
        )),
        "daemon wire path must return an AWS finding; got {arr:?}"
    );
}

/// ScanText twin of `daemon_wire_scan_path_finds_planted_secret`.
///
/// `keyhog scan --daemon` has two client routes (subcommands/scan.rs
/// `run_via_daemon`): `--stdin` sends `Request::ScanText`, a single
/// file path sends `Request::ScanPath`. The path route is covered by
/// the test above; this drives the stdin/ScanText route - the
/// pre-commit / IDE-save fast path the daemon exists for (see the
/// `daemon/protocol.rs` ScanText doc) - over a REAL bound socket
/// rather than the in-memory `tokio::io::duplex` mock the unit test
/// uses. Pipes a planted AWS key into `keyhog scan --daemon --stdin
/// --format json` and asserts exit 1 + the AWS finding came back over
/// the wire.
#[cfg(unix)]
#[test]
fn daemon_wire_scan_stdin_finds_planted_secret() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let (runtime, mut daemon) = start_daemon();

    let fixture = concat!("AWS_ACCESS_KEY_ID = \"AKIA", "QYLPMN5HFIQR7XYA\"\n");
    let mut child = Command::new(binary())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .args(["scan", "--daemon", "--stdin", "--format", "json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn daemon stdin scan");
    child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(fixture.as_bytes())
        .expect("pipe fixture to stdin");
    let scan = child.wait_with_output().expect("daemon stdin scan output");

    stop_daemon(&runtime, &mut daemon);

    assert_eq!(
        scan.status.code(),
        Some(1),
        "daemon --stdin scan must find secret (exit 1); stderr={}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let findings: serde_json::Value =
        serde_json::from_slice(&scan.stdout).expect("daemon stdin stdout is JSON");
    let arr = findings.as_array().expect("array");
    assert_eq!(
        arr.len(),
        1,
        "daemon ScanText/stdin must resolve the planted AWS key to one finding; got {arr:?}"
    );
    assert!(
        matches!(
            arr[0].get("detector_id").and_then(|v| v.as_str()),
            Some("aws-access-key" | "hot-aws_key")
        ),
        "daemon ScanText/stdin wire path must return the named AWS finding, not a generic entropy duplicate; got {arr:?}"
    );
}

/// Wire-v2 telemetry over the real socket on the ScanText/stdin route.
///
/// `daemon/protocol.rs` bumped the wire to v2 specifically so
/// `ScanResults` could carry `engine_example_suppressions` (and
/// `dogfood_events`) back to the client - the suppressed-example
/// counter that drives the reporter's "matched + suppressed N as known
/// examples" summary. That field was previously only round-tripped in
/// the `tokio::io::duplex` unit test (`unit/daemon_wire.rs`), never
/// asserted end-to-end. Here we pipe an AWS-published EXAMPLE token
/// (suppressed by the bundled test-fixture entry on the daemon side)
/// into `keyhog scan --daemon --stdin --format text`, and assert the
/// client reporter distinguishes suppressed-example from a clean repo -
/// which is only possible if the daemon's `engine_example_suppressions`
/// count survived the wire and was merged into the client's telemetry
/// (`run_via_daemon` -> `unwrap_scan_results` -> `add_example_suppressions`).
#[cfg(unix)]
#[test]
fn daemon_wire_stdin_example_suppression_summary_propagates() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let (runtime, mut daemon) = start_daemon();

    // AWS-published EXAMPLE credential: matched then suppressed as a
    // known example on the daemon side, so the wire-v2 suppression
    // count - not a finding - is what must reach the client.
    let fixture = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n";
    let mut child = Command::new(binary())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .args(["scan", "--daemon", "--stdin", "--format", "text"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn daemon stdin example scan");
    child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(fixture.as_bytes())
        .expect("pipe example fixture to stdin");
    let scan = child
        .wait_with_output()
        .expect("daemon stdin example scan output");

    stop_daemon(&runtime, &mut daemon);

    let stdout = String::from_utf8_lossy(&scan.stdout);
    assert!(
        stdout.contains("example/test key") && stdout.contains("suppressed"),
        "wire-v2 engine_example_suppressions must propagate over the real \
         socket so the daemon client distinguishes suppressed-example from a \
         clean repo. Got stdout: {stdout}"
    );
    assert!(
        !stdout.contains("Your code is clean."),
        "the clean-repo summary must NOT fire when the daemon suppressed an \
         example credential and reported a non-zero wire-v2 count. \
         Got stdout: {stdout}"
    );
}

/// `keyhog daemon status` against a RUNNING daemon over the real
/// socket. The previously-covered daemon e2e only drove start ->
/// `--daemon` scan -> stop; the documented Status payload (args.rs:
/// "uptime, scans served, active scans, and detector count") was only
/// exercised by orphaned adversarial tests for the *absent*-daemon
/// error path. Here we start a daemon, issue one real scan over the
/// socket (so scans-served increments off zero), then run `keyhog
/// daemon status` against the live socket and assert exit 0 + the
/// payload reports scans-served and a real detector count.
#[cfg(unix)]
#[test]
fn daemon_status_reports_payload_after_live_scan() {
    use std::process::Command;

    let dir = TempDir::new().expect("fixture dir");
    let fixture = dir.path().join("daemon_status_planted.txt");
    std::fs::write(
        &fixture,
        concat!("AWS_ACCESS_KEY_ID = \"AKIA", "QYLPMN5HFIQR7XYA\"\n"),
    )
    .unwrap();

    let (runtime, mut daemon) = start_daemon();

    // One real scan over the socket so the served counter is provably
    // non-zero in the status payload below.
    let scan = Command::new(binary())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .args(["scan", "--daemon", "--backend", "simd", "--format", "json"])
        .arg(&fixture)
        .output()
        .expect("daemon scan before status");
    assert_eq!(
        scan.status.code(),
        Some(1),
        "pre-status daemon scan must find the planted key; stderr={}",
        String::from_utf8_lossy(&scan.stderr)
    );

    let status = Command::new(binary())
        .env("XDG_RUNTIME_DIR", runtime.path())
        .args(["daemon", "status"])
        .output()
        .expect("daemon status");

    stop_daemon(&runtime, &mut daemon);

    assert_eq!(
        status.status.code(),
        Some(0),
        "`daemon status` against a live daemon must exit 0; stderr={}",
        String::from_utf8_lossy(&status.stderr)
    );
    let out = String::from_utf8_lossy(&status.stdout);
    assert!(
        out.contains("scans served"),
        "status payload must report scans-served; got: {out}"
    );
    assert!(
        out.contains("detectors"),
        "status payload must report the detector count; got: {out}"
    );
    // The served counter must reflect the real scan we issued, not a
    // hardcoded zero: "0 scans served" would mean the live Health
    // payload didn't see our request.
    assert!(
        !out.contains("0 scans served"),
        "status must report the scan we issued (non-zero scans-served); got: {out}"
    );
}

#[test]
fn doctor_reports_corpus_and_passes_scan_self_test() {
    // `keyhog doctor` is the install health check. On a healthy host it must
    // exit 0, report the real embedded detector corpus (not 0), and PASS the
    // end-to-end scan self-test (plant -> scan -> match). Asserting the
    // displayed count equals the binary's own embedded count proves the
    // report reflects reality, not a hardcoded banner number.
    let output = Command::new(binary())
        .arg("doctor")
        .output()
        .expect("run keyhog doctor");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(
        output.status.code(),
        Some(0),
        "doctor must exit 0 on a healthy host (PATH warning is non-fatal); stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("self-test"),
        "doctor must run a self-test section; got:\n{stdout}"
    );
    assert!(
        stdout.contains("PASS"),
        "the scan-engine self-test must PASS; got:\n{stdout}"
    );
    let corpus = keyhog_core::embedded_detector_count();
    assert!(corpus > 0, "binary must embed a detector corpus");
    assert!(
        stdout.contains(&corpus.to_string()),
        "doctor must display the real embedded corpus count ({corpus}); got:\n{stdout}"
    );
}

#[test]
fn update_subcommand_is_wired_with_its_flags() {
    // `keyhog update`'s download/replace path is network-bound (it queries the
    // GitHub releases API), so it can't be a deterministic offline snapshot -
    // its pure logic (asset selection, semver compare, executable-magic guard)
    // is unit-tested in subcommands::update. This e2e confirms the subcommand
    // and its flags are actually registered in the CLI (a wiring regression
    // would otherwise only surface when a user runs it).
    let output = Command::new(binary())
        .arg("update")
        .arg("--help")
        .output()
        .expect("run keyhog update --help");
    assert!(
        output.status.success(),
        "`keyhog update --help` must succeed; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let help = String::from_utf8_lossy(&output.stdout);
    for flag in ["--check", "--version", "--variant"] {
        assert!(
            help.contains(flag),
            "`keyhog update --help` must document {flag}; got:\n{help}"
        );
    }
}

#[test]
fn repair_subcommand_is_wired_with_its_flags() {
    // Like `update`, `repair`'s download/reinstall path is network-bound; its
    // shared logic is unit-tested in crate::installer. This confirms the
    // subcommand + flags are registered.
    let output = Command::new(binary())
        .arg("repair")
        .arg("--help")
        .output()
        .expect("run keyhog repair --help");
    assert!(
        output.status.success(),
        "`keyhog repair --help` must succeed; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let help = String::from_utf8_lossy(&output.stdout);
    for flag in ["--force", "--version", "--variant"] {
        assert!(
            help.contains(flag),
            "`keyhog repair --help` must document {flag}; got:\n{help}"
        );
    }
}

#[test]
fn uninstall_dry_run_does_not_remove_the_binary() {
    // Safety contract: `keyhog uninstall` without `--yes` must be a no-op dry
    // run - it must NOT delete the binary. (Running it against the test binary
    // is safe precisely because of this guarantee; a regression here would
    // delete the test runner's own binary.)
    let bin = binary();
    let output = Command::new(&bin)
        .arg("uninstall")
        .output()
        .expect("run keyhog uninstall");
    assert!(
        output.status.success(),
        "dry-run uninstall must exit 0; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let out = String::from_utf8_lossy(&output.stdout).to_lowercase();
    assert!(
        out.contains("dry run"),
        "uninstall without --yes must announce it's a dry run; got:\n{out}"
    );
    assert!(
        bin.exists(),
        "dry-run uninstall MUST NOT delete the binary at {}",
        bin.display()
    );
}

/// Write `content` + a `.keyhog.toml` of `config` into a temp dir, scan the
/// dir, return (stdout, stderr, exit-code). Exercises the real config-load
/// path (`.keyhog.toml` discovery + `apply_config_file`).
fn scan_dir_with_config(
    content: &str,
    config: &str,
    extra: &[&str],
) -> (String, String, Option<i32>) {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("planted.txt"), content).expect("write fixture");
    std::fs::write(dir.path().join(".keyhog.toml"), config).expect("write config");
    let output = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--backend",
            "simd",
            "--format",
            "json",
        ])
        .args(extra)
        .arg(dir.path())
        .output()
        .expect("spawn keyhog scan");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.code(),
    )
}

#[test]
fn config_detector_disable_drops_findings() {
    // `[detector.<id>] enabled = false` must actually drop the detector. This
    // README-documented toggle was parsed and SILENTLY IGNORED before being
    // wired, so a user disabling a noisy detector kept seeing it fire. The
    // hot-pattern fast path (`hot-aws_key`) shadows the TOML `aws-access-key`
    // detector, so both must be disabled to fully silence the AWS key.
    let aws = concat!("AWS_ACCESS_KEY_ID = \"AKIA", "QYLPMN5HFIQR7XYA\"\n");
    let (_o, _e, before) = scan_dir_with_config(aws, "", &[]);
    assert_eq!(before, Some(1), "baseline: the AWS key must be found");
    let (out, _e, code) = scan_dir_with_config(
        aws,
        "[detector.hot-aws_key]\nenabled = false\n[detector.aws-access-key]\nenabled = false\n",
        &[],
    );
    assert_eq!(
        code,
        Some(0),
        "disabling the AWS detectors via .keyhog.toml must yield zero findings; stdout={out}"
    );
}

#[test]
fn config_detector_min_confidence_floor_drops_findings() {
    // `[detector.<id>] min_confidence = <f>` is a per-detector confidence
    // floor: a finding from that detector below the floor is dropped, taking
    // precedence over the global --min-confidence. README-documented but
    // parsed-and-silently-ignored before this wiring (it was decoded into
    // DetectorSection.min_confidence and never consumed).
    //
    // The AWS key fires under both the hot-pattern fast path (`hot-aws_key`)
    // and the TOML `aws-access-key` detector, so the floor must be set on both
    // to fully suppress it - same shadowing as the disable test.
    let aws = concat!("AWS_ACCESS_KEY_ID = \"AKIA", "QYLPMN5HFIQR7XYA\"\n");

    // Baseline: the key is found.
    let (_o, _e, before) = scan_dir_with_config(aws, "", &[]);
    assert_eq!(before, Some(1), "baseline: the AWS key must be found");

    // A floor of 1.0 is unreachable by any real confidence (scores are < 1.0),
    // so it must drop every finding from these detectors -> exit 0.
    let (out_hi, _e, code_hi) = scan_dir_with_config(
        aws,
        "[detector.hot-aws_key]\nmin_confidence = 1.0\n\
         [detector.aws-access-key]\nmin_confidence = 1.0\n",
        &[],
    );
    assert_eq!(
        code_hi,
        Some(0),
        "a per-detector min_confidence floor of 1.0 must suppress the finding; stdout={out_hi}"
    );

    // A floor of 0.0 is below any confidence, so the finding survives - proving
    // the floor value (not merely the table's presence) is what drives the drop.
    let (_o, _e, code_lo) = scan_dir_with_config(
        aws,
        "[detector.hot-aws_key]\nmin_confidence = 0.0\n\
         [detector.aws-access-key]\nmin_confidence = 0.0\n",
        &[],
    );
    assert_eq!(
        code_lo,
        Some(1),
        "a per-detector min_confidence floor of 0.0 must keep the finding"
    );
}

#[test]
fn config_lockdown_require_refuses_without_flag() {
    // `[lockdown] require = true` is a fail-closed security control: refuse to
    // run unless --lockdown is passed (README: "refuse to run without
    // --lockdown"). It was parsed and silently ignored, so a repo that believed
    // it mandated lockdown ran unprotected. The refusal must be explicit.
    let (_o, err, code) =
        scan_dir_with_config("ordinary content\n", "[lockdown]\nrequire = true\n", &[]);
    assert_ne!(
        code,
        Some(0),
        "a repo whose .keyhog.toml requires lockdown must NOT run without --lockdown"
    );
    assert!(
        err.to_lowercase().contains("lockdown"),
        "the refusal must name lockdown so the operator knows why; stderr={err}"
    );
}

/// `--precision` is a high-precision mass-scan preset: it must keep genuine
/// high-confidence secrets while dropping weaker (sub-0.85) findings that the
/// default floor admits. The AWS secret key scores far higher than the bare
/// access-key id, so precision keeps the former and drops the latter.
#[test]
fn precision_mode_keeps_strong_drops_weak() {
    let fixture = concat!(
        "aws_access_key_id = \"AKIA",
        "QYLPMN5HGT3KZ7WB\"\n",
        "aws_secret_access_key = \"kP8xQ2mNvR7tZ4wL9bYsH3jD6fG1cA0eXuViK5oT\"\n",
    );
    let parse = |s: &str| -> Vec<String> {
        serde_json::from_str::<serde_json::Value>(s)
            .ok()
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default()
            .iter()
            .filter_map(|f| {
                f.get("detector_id")
                    .and_then(|d| d.as_str())
                    .map(String::from)
            })
            .collect()
    };
    let (def_out, _e, _c) = scan_text_file(fixture, &[]);
    let (prec_out, _e2, _c2) = scan_text_file(fixture, &["--precision"]);
    let def = parse(&def_out);
    let prec = parse(&prec_out);

    assert!(
        def.len() >= 2,
        "default mode should surface both the access-key id and the secret key; got {def:?}"
    );
    assert!(
        def.iter().any(|d| d == "aws-secret-access-key"),
        "default must find the secret key; got {def:?}"
    );
    assert!(
        prec.iter().any(|d| d == "aws-secret-access-key"),
        "precision must KEEP the high-confidence secret key; got {prec:?}"
    );
    assert!(
        prec.len() < def.len(),
        "precision must be strictly tighter than default; default={def:?} precision={prec:?}"
    );
    assert!(
        !prec
            .iter()
            .any(|d| d == "aws-access-key" || d == "hot-aws_key"),
        "precision must drop the weaker access-key-id finding (below the 0.85 bar); got {prec:?}"
    );
}

/// The scan modes are mutually exclusive: clap must reject `--precision --fast`
/// rather than silently letting one win.
#[test]
fn precision_mode_conflicts_with_fast() {
    let (_o, err, code) = scan_text_file("ordinary content\n", &["--precision", "--fast"]);
    assert_eq!(
        code,
        Some(2),
        "clap usage error (exit 2) expected for conflicting --precision --fast; got {code:?}"
    );
    assert!(
        err.contains("cannot be used with") || err.to_lowercase().contains("precision"),
        "the usage error must name the conflict; stderr={err}"
    );
}
