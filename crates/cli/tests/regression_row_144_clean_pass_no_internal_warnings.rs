#![cfg(unix)]

//! WHY: Row 144 contract: clean scan passes must execute without noisy internal
//! execution-pack fallback warnings (`WARN no installed execution-pack generation; parsing embedded detectors`),
//! raw ISO-timestamped tracing lines, or stdout/stderr pollution.
//!
//! What it closes:
//! Closes the noisy log pollution defect where missing or fallback execution-pack
//! diagnostics leaked into stderr during normal scans. Enforces that standard clean scans
//! execute with pure, structured output without emitting noisy warnings when falling back
//! to embedded detectors, and that structured output formats (`--format json`, `--format sarif`) remain unpolluted.
//!
//! What it does not catch / boundary limits:
//! Does not catch hardware-level hardware faults during kernel execution.
//! Does not catch kernel OOM killer terminations during massive scan workloads.

use keyhog::exit_codes::{EXIT_SUCCESS, EXIT_USER_ERROR};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;

fn safe_tempdir(prefix: &str) -> tempfile::TempDir {
    let base_tmp = PathBuf::from("/mnt/FlareTraining/santh-archive/tmp");
    if base_tmp.exists() {
        tempfile::Builder::new()
            .prefix(prefix)
            .tempdir_in(&base_tmp)
            .expect("tempdir in base_tmp")
    } else {
        tempfile::Builder::new()
            .prefix(prefix)
            .tempdir()
            .expect("tempdir")
    }
}

static PREPARED_INSTALLATION: LazyLock<(tempfile::TempDir, PathBuf, PathBuf, PathBuf)> =
    LazyLock::new(|| {
        let directory = safe_tempdir("keyhog-row144-install-");
        let binary = directory.path().join("keyhog");
        fs::copy(env!("CARGO_BIN_EXE_keyhog"), &binary).expect("copy test binary");
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).expect("set binary perms");

        let cache_home = directory.path().join("cache");
        let pack_root = cache_home.join("keyhog/execution-packs");
        fs::create_dir_all(&pack_root).expect("execution-pack root");
        let key_path = pack_root.join("signing.key");
        let key_bytes = [0x5cu8; 32];
        fs::write(&key_path, key_bytes).expect("write signing key");
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
            .expect("protect signing key");
        let output = pack_root.join("current");

        let result = Command::new(&binary)
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
        (directory, binary, pack_root, output)
    });

fn copy_dir_all(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("create dst dir");
    for entry in fs::read_dir(src).expect("read src dir") {
        let entry = entry.expect("entry");
        let path = entry.path();
        let dest_path = dst.join(entry.file_name());
        if path.is_dir() {
            copy_dir_all(&path, &dest_path);
        } else if fs::hard_link(&path, &dest_path).is_err() {
            fs::copy(&path, &dest_path).expect("copy file");
        }
    }
}

fn clone_prepared_installation(cache_home: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let (_temp, binary, source_pack_root, _output) = &*PREPARED_INSTALLATION;
    let pack_root = cache_home.join("keyhog/execution-packs");
    copy_dir_all(source_pack_root, &pack_root);
    let output = pack_root.join("current");
    (binary.clone(), pack_root, output)
}

fn assert_no_internal_execution_pack_warnings(stderr: &str) {
    assert!(
        !stderr.contains("WARN no installed execution-pack generation; parsing embedded detectors"),
        "stderr must not contain raw internal execution-pack fallback warning: {stderr}"
    );
    assert!(
        !stderr.contains("parsing embedded detectors"),
        "stderr must not contain 'parsing embedded detectors': {stderr}"
    );

    // Assert absence of raw ISO-8601 timestamps typically emitted by unconfigured tracing formatters
    let contains_raw_iso_timestamp = stderr.lines().any(|line| {
        line.contains("Z  WARN") || line.contains("Z  INFO") || line.contains("Z  ERROR")
    });
    assert!(
        !contains_raw_iso_timestamp,
        "stderr must not contain raw ISO-timestamped tracing lines: {stderr}"
    );
}

#[test]
fn clean_pass_file_scan_has_no_internal_warnings() {
    let temp_dir = safe_tempdir("keyhog-row144-scan-");
    let cache_home = temp_dir.path().join("cache");
    let (binary, _pack_root, _output_dir) = clone_prepared_installation(&cache_home);

    let clean_file = temp_dir.path().join("clean_file.txt");
    fs::write(&clean_file, "clean content with no secrets\n").expect("write clean file");

    let scan_output = Command::new(&binary)
        .arg("scan")
        .arg("--daemon=off")
        .arg(&clean_file)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", temp_dir.path())
        .output()
        .expect("run scan command");

    let stdout = String::from_utf8_lossy(&scan_output.stdout);
    let stderr = String::from_utf8_lossy(&scan_output.stderr);
    assert_eq!(
        scan_output.status.code(),
        Some(i32::from(EXIT_SUCCESS)),
        "clean scan must exit with SUCCESS (0), stderr: {stderr}"
    );

    assert!(
        stdout.contains("No secrets detected") || stdout.contains("PASS"),
        "clean scan stdout must report clean status: {stdout}"
    );

    assert_no_internal_execution_pack_warnings(&stderr);
}

#[test]
fn clean_pass_directory_scan_has_no_internal_warnings() {
    let temp_dir = safe_tempdir("keyhog-row144-dir-");
    let cache_home = temp_dir.path().join("cache");
    let (binary, _pack_root, _output_dir) = clone_prepared_installation(&cache_home);

    let scan_dir = temp_dir.path().join("scandir");
    fs::create_dir_all(&scan_dir).expect("create scan dir");
    fs::write(scan_dir.join("file1.txt"), "hello world\n").expect("write file1");
    fs::write(scan_dir.join("file2.rs"), "fn main() {}\n").expect("write file2");

    let scan_output = Command::new(&binary)
        .arg("scan")
        .arg("--daemon=off")
        .arg(&scan_dir)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", temp_dir.path())
        .output()
        .expect("run scan command");

    let stdout = String::from_utf8_lossy(&scan_output.stdout);
    let stderr = String::from_utf8_lossy(&scan_output.stderr);
    assert_eq!(
        scan_output.status.code(),
        Some(i32::from(EXIT_SUCCESS)),
        "clean directory scan must exit with SUCCESS (0), stderr: {stderr}"
    );

    assert!(
        stdout.contains("No secrets detected") || stdout.contains("PASS"),
        "clean directory scan stdout must report clean status: {stdout}"
    );

    assert_no_internal_execution_pack_warnings(&stderr);
}

#[test]
fn clean_pass_json_and_sarif_formats_are_unpolluted() {
    let temp_dir = safe_tempdir("keyhog-row144-json-");
    let cache_home = temp_dir.path().join("cache");
    let (binary, _pack_root, _output_dir) = clone_prepared_installation(&cache_home);

    let clean_file = temp_dir.path().join("clean.txt");
    fs::write(&clean_file, "plain clean text\n").expect("write clean file");

    for format in ["json", "sarif"] {
        let scan_output = Command::new(&binary)
            .arg("scan")
            .arg("--daemon=off")
            .arg("--format")
            .arg(format)
            .arg(&clean_file)
            .env("XDG_CACHE_HOME", &cache_home)
            .env("HOME", temp_dir.path())
            .output()
            .expect("run scan command");

        let stderr = String::from_utf8_lossy(&scan_output.stderr);
        assert_eq!(
            scan_output.status.code(),
            Some(i32::from(EXIT_SUCCESS)),
            "clean {format} scan must exit with SUCCESS (0), stderr: {stderr}"
        );
        // Verify that stdout parses cleanly as valid JSON without leading/trailing garbage
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
        assert!(
            parsed.is_ok(),
            "clean {format} scan stdout must be valid JSON: {stdout}"
        );

        assert_no_internal_execution_pack_warnings(&stderr);
    }
}

#[test]
fn mutation_gate_catches_synthetic_warning_pollution() {
    // MUTATION GATE: Verify that our test assertion `assert_no_internal_execution_pack_warnings`
    // fails if noisy internal execution-pack fallback logs are present.
    let synthetic_legacy_warning =
        "2026-05-29T14:23:45.123456Z  WARN no installed execution-pack generation; parsing embedded detectors error=missing manifest\n";
    let caught_legacy = std::panic::catch_unwind(|| {
        assert_no_internal_execution_pack_warnings(synthetic_legacy_warning);
    });
    assert!(
        caught_legacy.is_err(),
        "mutation gate must catch synthetic legacy execution-pack warning"
    );

    let synthetic_iso_log = "2026-08-19T10:00:00Z  WARN internal diagnostic message\n";
    let caught_iso = std::panic::catch_unwind(|| {
        assert_no_internal_execution_pack_warnings(synthetic_iso_log);
    });
    assert!(
        caught_iso.is_err(),
        "mutation gate must catch synthetic ISO-timestamped log lines"
    );
}

#[test]
fn missing_execution_pack_runs_cleanly_without_noisy_fallback_warnings() {
    // Contract: When execution packs are not installed, scan falls back to embedded
    // detectors cleanly with EXIT_SUCCESS (0) and without emitting any noisy WARN logs on stderr.
    let temp_dir = safe_tempdir("keyhog-row144-missing-");
    let cache_home = temp_dir.path().join("empty_cache");
    fs::create_dir_all(&cache_home).expect("create empty cache");

    let clean_file = temp_dir.path().join("clean.txt");
    fs::write(&clean_file, "plain clean text\n").expect("write clean file");

    let scan_output = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .arg("scan")
        .arg("--daemon=off")
        .arg(&clean_file)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", temp_dir.path())
        .output()
        .expect("run scan command");

    let stdout = String::from_utf8_lossy(&scan_output.stdout);
    let stderr = String::from_utf8_lossy(&scan_output.stderr);
    assert_eq!(
        scan_output.status.code(),
        Some(i32::from(EXIT_SUCCESS)),
        "clean scan without installed packs must succeed with EXIT_SUCCESS (0), stderr: {stderr}"
    );

    assert!(
        stdout.contains("No secrets detected") || stdout.contains("PASS"),
        "clean scan stdout must report clean status: {stdout}"
    );

    assert_no_internal_execution_pack_warnings(&stderr);
}

#[test]
fn stale_or_corrupted_execution_pack_fails_closed_with_actionable_error_and_exit_code_2() {
    // Contract: If an execution-pack generation is present but stale/corrupted, scan fails closed
    // with actionable message and EXIT_USER_ERROR = 2.
    let temp_dir = safe_tempdir("keyhog-row144-stale-");
    let cache_home = temp_dir.path().join("cache");
    let pack_dir = cache_home.join("keyhog/execution-packs/current");
    fs::create_dir_all(&pack_dir).expect("create pack dir");
    // Write an invalid manifest so verification fails
    fs::write(
        pack_dir.join("manifest.json"),
        "{\"invalid\":\"manifest\"}\n",
    )
    .expect("write invalid manifest");

    let clean_file = temp_dir.path().join("clean.txt");
    fs::write(&clean_file, "plain clean text\n").expect("write clean file");

    let scan_output = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .arg("scan")
        .arg("--daemon=off")
        .arg(&clean_file)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", temp_dir.path())
        .output()
        .expect("run scan command");

    assert_eq!(
        scan_output.status.code(),
        Some(i32::from(EXIT_USER_ERROR)),
        "stale/corrupted execution packs must fail closed with EXIT_USER_ERROR (2)"
    );

    let stderr = String::from_utf8_lossy(&scan_output.stderr);
    assert!(
        stderr.contains("keyhog install") || stderr.contains("keyhog update") || stderr.contains("compile-execution-packs"),
        "stderr must contain actionable fix guidance mentioning 'keyhog install' or 'keyhog compile-execution-packs': {stderr}"
    );
}

#[test]
fn developer_escape_hatch_self_identifies_cleanly() {
    // Contract: Under `--developer-compile-embedded-detectors`, developer mode is explicitly announced.
    let temp_dir = safe_tempdir("keyhog-row144-dev-");
    let cache_home = temp_dir.path().join("empty_cache");
    fs::create_dir_all(&cache_home).expect("create empty cache");

    let clean_file = temp_dir.path().join("clean.txt");
    fs::write(&clean_file, "plain clean text\n").expect("write clean file");

    let scan_output = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .arg("scan")
        .arg("--daemon=off")
        .arg("--developer-compile-embedded-detectors")
        .arg(&clean_file)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", temp_dir.path())
        .output()
        .expect("run scan command");

    assert_eq!(
        scan_output.status.code(),
        Some(i32::from(EXIT_SUCCESS)),
        "developer compile escape hatch on clean scan must exit with SUCCESS (0)"
    );

    let stderr = String::from_utf8_lossy(&scan_output.stderr);
    assert!(
        stderr.contains("developer mode active: in-process detector compilation"),
        "stderr must state developer mode is active: {stderr}"
    );
    assert!(
        !stderr.contains("WARN no installed execution-pack generation; parsing embedded detectors"),
        "developer escape hatch must not emit legacy unhandled fallback warning: {stderr}"
    );
}
