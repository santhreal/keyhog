#![cfg(unix)]

//! WHY: Row 163 contract: fail-closed scan document contract on stdin/source failure.
//!
//! What it closes:
//! Closes the false-clean defect where unversioned / bare JSON output (`--format json`)
//! emitted `[]` on total source failure (e.g. oversized stdin or unreadable source)
//! with no findings, misleading automated consumers and CI pipelines into concluding
//! that a failed/unscanned target was clean with 0 secrets.
//! Also enforces that structured envelope formats (`json-envelope`, `jsonl-envelope`,
//! `sarif`, `csv`, `gitlab-sast`) unambiguously report `scan_status: "failed"` and
//! document the source failure coverage gap.
//!
//! What it does not catch / boundary limits:
//! Does not catch kernel memory corruption or process SIGKILL before process exit.

use keyhog::exit_codes::{EXIT_FINDINGS, EXIT_SOURCE_FAILED, EXIT_SUCCESS};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::LazyLock;

static PREPARED_INSTALLATION: LazyLock<(tempfile::TempDir, PathBuf, PathBuf, PathBuf)> =
    LazyLock::new(|| {
        let directory = tempfile::Builder::new()
            .prefix("keyhog-row163-test-")
            .tempdir_in(if std::path::Path::new("/var/tmp").exists() {
                "/var/tmp"
            } else {
                "/tmp"
            })
            .expect("temporary install root");
        let binary_path = directory.path().join("keyhog-test-bin");
        fs::copy(env!("CARGO_BIN_EXE_keyhog"), &binary_path).expect("copy test binary");
        fs::set_permissions(&binary_path, fs::Permissions::from_mode(0o755))
            .expect("make binary executable");

        let cache_home = directory.path().join("cache");
        let pack_root = cache_home.join("keyhog/execution-packs");
        fs::create_dir_all(&pack_root).expect("execution-pack root");
        let key_path = pack_root.join("signing.key");
        let key_bytes = [0x5cu8; 32];
        fs::write(&key_path, key_bytes).expect("write signing key");
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
            .expect("protect signing key");
        let output = pack_root.join("current");

        let result = Command::new(&binary_path)
            .arg("compile-execution-packs")
            .arg("--output-dir")
            .arg(&output)
            .arg("--signing-key")
            .arg(&key_path)
            .env("XDG_CACHE_HOME", &cache_home)
            .env("HOME", directory.path())
            .output()
            .expect("run install pack compiler");
        assert!(
            result.status.success(),
            "install pack compiler failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        (directory, pack_root, output, binary_path)
    });

fn binary() -> PathBuf {
    PREPARED_INSTALLATION.3.clone()
}

fn run_stdin_scan(input: &[u8], args: &[&str]) -> (Option<i32>, String, String) {
    let (temp, _pack_root, _output, _bin) = &*PREPARED_INSTALLATION;
    let cache_home = temp.path().join("cache");
    let mut child = Command::new(binary())
        .args(args)
        .env("XDG_CACHE_HOME", &cache_home)
        .env_remove("KEYHOG_BACKEND")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn keyhog scan");
    child
        .stdin
        .take()
        .expect("stdin handle")
        .write_all(input)
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait keyhog scan");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn raw_json_format_on_oversized_stdin_emits_empty_stdout_and_fails_closed_exit_13() {
    let big = vec![b'x'; 256];
    let (code, stdout, stderr) = run_stdin_scan(
        &big,
        &[
            "scan",
            "--daemon=off",
            "--backend",
            "cpu",
            "--stdin",
            "--limit-stdin-bytes",
            "16B",
            "--format",
            "json",
        ],
    );
    assert_eq!(
        code,
        Some(i32::from(EXIT_SOURCE_FAILED)),
        "oversized stdin must fail closed with exit 13 (EXIT_SOURCE_FAILED)"
    );
    assert_eq!(
        stdout.trim_end(),
        "",
        "raw JSON format must not emit `[]` on total source failure; stdout must be empty"
    );
    assert!(
        stderr.contains("stdin exceeds 16 byte limit"),
        "stderr must identify byte limit failure; got:\n{stderr}"
    );
    assert!(
        stderr.contains("Not reporting \"clean\""),
        "stderr must refuse to report clean; got:\n{stderr}"
    );
}

#[test]
fn raw_json_format_with_output_file_on_oversized_stdin_leaves_no_false_clean_array() {
    let big = vec![b'x'; 256];
    let out_dir = tempfile::Builder::new()
        .prefix("keyhog-row163-file-")
        .tempdir_in(if std::path::Path::new("/var/tmp").exists() {
            "/var/tmp"
        } else {
            "/tmp"
        })
        .expect("tempdir");
    let out_file = out_dir.path().join("report.json");
    let (code, stdout, stderr) = run_stdin_scan(
        &big,
        &[
            "scan",
            "--daemon=off",
            "--backend",
            "cpu",
            "--stdin",
            "--limit-stdin-bytes",
            "16B",
            "--format",
            "json",
            "--output",
            out_file.to_str().expect("utf-8 path"),
        ],
    );
    assert_eq!(code, Some(i32::from(EXIT_SOURCE_FAILED)));
    assert_eq!(stdout.trim_end(), "");
    let file_content = fs::read_to_string(&out_file).unwrap_or_default();
    assert_eq!(
        file_content.trim_end(),
        "",
        "output file must not contain `[]` on total source failure"
    );
    assert!(stderr.contains("stdin exceeds 16 byte limit"));
}

#[test]
fn json_envelope_format_on_oversized_stdin_emits_failed_scan_status() {
    let big = vec![b'x'; 256];
    let (code, stdout, stderr) = run_stdin_scan(
        &big,
        &[
            "scan",
            "--daemon=off",
            "--backend",
            "cpu",
            "--stdin",
            "--limit-stdin-bytes",
            "16B",
            "--format",
            "json-envelope",
        ],
    );
    assert_eq!(code, Some(i32::from(EXIT_SOURCE_FAILED)));
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("valid JSON envelope output");
    assert_eq!(
        parsed["scan_status"], "failed",
        "json-envelope scan_status must be 'failed' on total source failure"
    );
    assert_eq!(
        parsed["findings"].as_array().map(Vec::len),
        Some(0),
        "no findings produced on failed source"
    );
    assert!(
        stderr.contains("stdin exceeds 16 byte limit"),
        "stderr must contain inner reason"
    );
}

#[test]
fn sarif_format_on_oversized_stdin_emits_failed_scan_status_and_exit_13() {
    let big = vec![b'x'; 256];
    let (code, stdout, _stderr) = run_stdin_scan(
        &big,
        &[
            "scan",
            "--daemon=off",
            "--backend",
            "cpu",
            "--stdin",
            "--limit-stdin-bytes",
            "16B",
            "--format",
            "sarif",
        ],
    );
    assert_eq!(code, Some(i32::from(EXIT_SOURCE_FAILED)));
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid SARIF output");
    assert_eq!(
        parsed["runs"][0]["properties"]["keyhog.scan.status"], "failed",
        "SARIF property keyhog.scan.status must be 'failed'"
    );
}

#[test]
fn csv_format_on_oversized_stdin_emits_failed_scan_status_in_metadata_header() {
    let big = vec![b'x'; 256];
    let (code, stdout, _stderr) = run_stdin_scan(
        &big,
        &[
            "scan",
            "--daemon=off",
            "--backend",
            "cpu",
            "--stdin",
            "--limit-stdin-bytes",
            "16B",
            "--format",
            "csv",
        ],
    );
    assert_eq!(code, Some(i32::from(EXIT_SOURCE_FAILED)));
    let first_line = stdout.lines().next().unwrap_or("");
    assert!(
        first_line.starts_with("# keyhog.scan.metadata="),
        "CSV must emit metadata header line; got:\n{stdout}"
    );
    assert!(
        first_line.contains("\"scan_status\":\"failed\""),
        "CSV metadata header must contain scan_status failed; got:\n{first_line}"
    );
}

#[test]
fn clean_under_cap_stdin_emits_empty_array_and_exits_zero() {
    let (code, stdout, _stderr) = run_stdin_scan(
        b"clean plain text within byte cap\n",
        &[
            "scan",
            "--daemon=off",
            "--backend",
            "cpu",
            "--stdin",
            "--limit-stdin-bytes",
            "100B",
            "--format",
            "json",
        ],
    );
    assert_eq!(code, Some(i32::from(EXIT_SUCCESS)));
    assert_eq!(stdout.trim_end(), "[]");
}

#[test]
fn secret_bearing_stdin_emits_findings_array_and_exits_one() {
    let secret =
        b"SLACK_BOT_TOKEN = \"xoxb-1234567890123-1234567890123-abcdefghijklmnopqrstuvwx\"\n";
    let (code, stdout, _stderr) = run_stdin_scan(
        secret,
        &[
            "scan",
            "--daemon=off",
            "--backend",
            "cpu",
            "--stdin",
            "--limit-stdin-bytes",
            "1K",
            "--no-suppress-test-fixtures",
            "--format",
            "json",
        ],
    );
    assert_eq!(code, Some(i32::from(EXIT_FINDINGS)));
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON findings");
    let arr = parsed.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["detector_id"], "slack-bot-token");
}
