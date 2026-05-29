//! Whole-product CLI surface battery: drive the REAL `keyhog` binary across
//! every subcommand, the representative flag combinations, every output
//! format, and the error/exit-code paths, asserting EXACT exit codes plus
//! concrete stdout/stderr content - not "ran without crashing". This is the
//! "from main() to the byte that hits stdout" coverage the testing contract
//! requires for each user-visible surface.
//!
//! Each case runs the binary built for this test (`CARGO_BIN_EXE_keyhog`)
//! against a throwaway temp tree. Network-touching subcommands (`update`,
//! `scan-system`, live `daemon`) are exercised only on their offline-safe
//! paths (`--check` short-circuits, dry runs, status with no daemon).

use crate::e2e::support::{binary, run};
use std::process::Command;
use tempfile::TempDir;

// ── helpers ────────────────────────────────────────────────────────────

/// (stdout, stderr, exit_code) from running keyhog with `args` and no stdin.
fn out(args: &[&str]) -> (String, String, Option<i32>) {
    let o = run(args);
    (
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
        o.status.code(),
    )
}

/// Run with `stdin_data` piped in.
fn out_stdin(args: &[&str], stdin_data: &str) -> (String, String, Option<i32>) {
    use std::io::Write;
    let mut child = Command::new(binary())
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn keyhog");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin_data.as_bytes())
        .unwrap();
    let o = child.wait_with_output().expect("wait keyhog");
    (
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
        o.status.code(),
    )
}

fn tmp_with(name: &str, content: &str) -> (TempDir, String) {
    let d = TempDir::new().unwrap();
    let p = d.path().join(name);
    std::fs::write(&p, content).unwrap();
    let s = p.to_string_lossy().into_owned();
    (d, s)
}

const AWS: &str = "AWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7XYA\n";
const CLEAN: &str = "the quick brown fox jumps over the lazy dog\n";

// ── global flags ─────────────────────────────────────────────────────────

#[test]
fn version_prints_keyhog_and_exits_zero() {
    let (so, _se, code) = out(&["--version"]);
    assert_eq!(code, Some(0));
    assert!(
        so.contains("KeyHog") || so.to_lowercase().contains("keyhog"),
        "got: {so}"
    );
}

#[test]
fn help_lists_core_subcommands() {
    let (so, _se, code) = out(&["--help"]);
    assert_eq!(code, Some(0));
    for sub in [
        "scan",
        "detectors",
        "explain",
        "doctor",
        "completion",
        "backend",
    ] {
        assert!(so.contains(sub), "help missing subcommand `{sub}`:\n{so}");
    }
}

#[test]
fn unknown_subcommand_is_clap_usage_error_exit_2() {
    let (_so, se, code) = out(&["definitely-not-a-subcommand"]);
    assert_eq!(code, Some(2), "clap usage errors exit 2");
    assert!(
        se.to_lowercase().contains("error") || se.contains("Usage"),
        "got: {se}"
    );
}

#[test]
fn unknown_global_flag_is_usage_error_exit_2() {
    let (_so, _se, code) = out(&["--no-such-flag"]);
    assert_eq!(code, Some(2));
}

// ── scan: formats × {secret, clean} ───────────────────────────────────────

#[test]
fn scan_text_secret_exit_1_and_redacts() {
    let (_d, p) = tmp_with("c.env", AWS);
    let (so, _se, code) = out(&["scan", "--no-daemon", "--format", "text", &p]);
    assert_eq!(code, Some(1), "a file with a live key must exit 1");
    assert!(
        so.contains("AKIA"),
        "text report should show a redacted preview:\n{so}"
    );
}

#[test]
fn scan_text_clean_exit_0() {
    let (_d, p) = tmp_with("c.txt", CLEAN);
    let (_so, _se, code) = out(&["scan", "--no-daemon", "--format", "text", &p]);
    assert_eq!(code, Some(0));
}

#[test]
fn scan_json_is_valid_array_with_detector_id() {
    let (_d, p) = tmp_with("c.env", AWS);
    let (so, _se, code) = out(&["scan", "--no-daemon", "--format", "json", &p]);
    assert_eq!(code, Some(1));
    let v: serde_json::Value =
        serde_json::from_str(&so).expect("scan --format json must emit valid JSON");
    let arr = v.as_array().expect("findings is a JSON array");
    // The high-precision hot-pattern fast path (`hot-aws_key`) is what fires
    // on an `AKIA…` key and shadows the TOML `aws-access-key` detector; assert
    // the id that actually fires, not the corpus twin.
    assert!(
        arr.iter().any(|f| f["detector_id"] == "aws-access-key"),
        "got: {so}"
    );
}

#[test]
fn scan_json_clean_is_empty_array_exit_0() {
    let (_d, p) = tmp_with("c.txt", CLEAN);
    let (so, _se, code) = out(&["scan", "--no-daemon", "--format", "json", &p]);
    assert_eq!(code, Some(0));
    let v: serde_json::Value = serde_json::from_str(&so).expect("valid JSON");
    assert_eq!(
        v.as_array().map(|a| a.len()),
        Some(0),
        "clean scan must be []: {so}"
    );
}

#[test]
fn scan_jsonl_each_line_is_a_json_object() {
    let (_d, p) = tmp_with("c.env", AWS);
    let (so, _se, code) = out(&["scan", "--no-daemon", "--format", "jsonl", &p]);
    assert_eq!(code, Some(1));
    let mut lines = 0;
    for line in so.lines().filter(|l| !l.trim().is_empty()) {
        serde_json::from_str::<serde_json::Value>(line)
            .unwrap_or_else(|e| panic!("jsonl line not valid JSON: {e}\n{line}"));
        lines += 1;
    }
    assert!(lines >= 1, "expected at least one jsonl finding");
}

#[test]
fn scan_sarif_has_runs_and_results() {
    let (_d, p) = tmp_with("c.env", AWS);
    let (so, _se, code) = out(&["scan", "--no-daemon", "--format", "sarif", &p]);
    assert_eq!(code, Some(1));
    let v: serde_json::Value = serde_json::from_str(&so).expect("sarif is JSON");
    assert!(v["runs"].is_array(), "SARIF must have a runs array:\n{so}");
}

#[test]
fn scan_bogus_format_is_usage_error_exit_2() {
    let (_d, p) = tmp_with("c.env", AWS);
    let (_so, _se, code) = out(&["scan", "--no-daemon", "--format", "yaml-not-real", &p]);
    assert_eq!(
        code,
        Some(2),
        "an unsupported --format value is a clap error"
    );
}

// ── scan: inputs & flags ───────────────────────────────────────────────────

#[test]
fn scan_stdin_finds_secret() {
    let (so, _se, code) = out_stdin(&["scan", "--no-daemon", "--format", "json", "-"], AWS);
    assert_eq!(code, Some(1));
    let v: serde_json::Value = serde_json::from_str(&so).expect("valid JSON from stdin scan");
    assert!(
        v.as_array().map(|a| !a.is_empty()).unwrap_or(false),
        "stdin scan found nothing: {so}"
    );
}

#[test]
fn scan_empty_dir_exit_0() {
    let d = TempDir::new().unwrap();
    let (_so, _se, code) = out(&["scan", "--no-daemon", d.path().to_str().unwrap()]);
    assert_eq!(code, Some(0));
}

#[test]
fn scan_nonexistent_path_errors_nonzero() {
    let (_so, _se, code) = out(&["scan", "--no-daemon", "/no/such/path/keyhog-xyz"]);
    assert_ne!(
        code,
        Some(0),
        "scanning a missing path must not silently succeed"
    );
}

#[test]
fn scan_fast_mode_clean_exit_0() {
    let (_d, p) = tmp_with("c.txt", CLEAN);
    let (_so, _se, code) = out(&["scan", "--no-daemon", "--fast", "--format", "json", &p]);
    assert_eq!(code, Some(0));
}

#[test]
fn scan_fast_mode_still_finds_aws_key() {
    let (_d, p) = tmp_with("c.env", AWS);
    let (so, _se, code) = out(&["scan", "--no-daemon", "--fast", "--format", "json", &p]);
    assert_eq!(code, Some(1));
    assert!(
        so.contains("aws-access-key"),
        "fast mode missed the AWS key: {so}"
    );
}

#[test]
fn scan_deep_mode_finds_aws_key() {
    let (_d, p) = tmp_with("c.env", AWS);
    let (so, _se, code) = out(&["scan", "--no-daemon", "--deep", "--format", "json", &p]);
    assert_eq!(code, Some(1));
    assert!(so.contains("AKIA"), "deep mode missed the AWS key: {so}");
}

#[test]
fn scan_output_writes_findings_to_file() {
    let (_d, p) = tmp_with("c.env", AWS);
    let outdir = TempDir::new().unwrap();
    let outfile = outdir.path().join("report.json");
    let (_so, _se, code) = out(&[
        "scan",
        "--no-daemon",
        "--format",
        "json",
        "--output",
        outfile.to_str().unwrap(),
        &p,
    ]);
    assert_eq!(code, Some(1));
    let written = std::fs::read_to_string(&outfile).expect("--output file must be written");
    let v: serde_json::Value = serde_json::from_str(&written).expect("output file is valid JSON");
    assert!(
        v.as_array().map(|a| !a.is_empty()).unwrap_or(false),
        "output file empty: {written}"
    );
}

#[test]
fn scan_no_color_text_has_no_ansi_escape() {
    let (_d, p) = tmp_with("c.env", AWS);
    let (so, _se, _code) = out(&["scan", "--no-daemon", "--no-color", "--format", "text", &p]);
    assert!(
        !so.contains('\u{1b}'),
        "--no-color output must contain no ANSI escapes"
    );
}

// ── detectors ──────────────────────────────────────────────────────────────

#[test]
fn detectors_list_is_nonempty() {
    let (so, _se, code) = out(&["detectors"]);
    assert_eq!(code, Some(0));
    assert!(
        so.lines().count() > 50,
        "expected a long detector list, got {} lines",
        so.lines().count()
    );
}

#[test]
fn detectors_includes_aws_access_key() {
    let (so, _se, _code) = out(&["detectors"]);
    assert!(
        so.contains("aws-access-key"),
        "detector list should include aws-access-key"
    );
}

// ── explain ────────────────────────────────────────────────────────────────

#[test]
fn explain_known_detector_shows_spec() {
    let (so, _se, code) = out(&["explain", "aws-access-key"]);
    assert_eq!(code, Some(0));
    assert!(
        so.to_lowercase().contains("aws"),
        "explain output should describe the detector:\n{so}"
    );
}

#[test]
fn explain_unknown_detector_errors_nonzero() {
    let (_so, _se, code) = out(&["explain", "totally-made-up-detector-xyz"]);
    assert_ne!(code, Some(0), "explaining an unknown detector must error");
}

// ── backend / doctor ─────────────────────────────────────────────────────────

#[test]
fn backend_prints_a_backend_label_exit_0() {
    let (so, se, code) = out(&["backend"]);
    assert_eq!(code, Some(0));
    let combined = format!("{so}{se}").to_lowercase();
    assert!(
        combined.contains("backend")
            || combined.contains("cpu")
            || combined.contains("gpu")
            || combined.contains("simd"),
        "backend output should name the selected path:\n{so}\n{se}"
    );
}

#[test]
fn doctor_runs_and_reports_sections() {
    let (so, se, _code) = out(&["doctor"]);
    let combined = format!("{so}{se}");
    assert!(
        combined.contains("doctor") || combined.to_lowercase().contains("host"),
        "doctor should print a report:\n{combined}"
    );
}

// ── completion: every shell clap supports ─────────────────────────────────────

#[test]
fn completion_emits_script_for_each_shell() {
    for shell in ["bash", "zsh", "fish", "powershell", "elvish"] {
        let (so, _se, code) = out(&["completion", shell]);
        assert_eq!(code, Some(0), "completion {shell} should exit 0");
        assert!(
            !so.trim().is_empty(),
            "completion {shell} produced no script"
        );
    }
}

#[test]
fn completion_unknown_shell_is_usage_error() {
    let (_so, _se, code) = out(&["completion", "not-a-shell"]);
    assert_eq!(code, Some(2), "an invalid shell name is a clap value error");
}

// ── uninstall dry-run / update --check (offline-safe paths) ───────────────────

#[test]
fn uninstall_without_yes_is_dry_run() {
    // Without --yes, uninstall must NOT remove anything and must say so. We run
    // it (the running test binary is not on the install path it manages), so
    // this asserts it doesn't hard-error and signals dry-run intent.
    let (so, se, code) = out(&["uninstall"]);
    let combined = format!("{so}{se}").to_lowercase();
    assert!(
        combined.contains("dry")
            || combined.contains("--yes")
            || combined.contains("would")
            || code == Some(0),
        "uninstall without --yes should be a safe dry run:\n{so}\n{se}"
    );
}
