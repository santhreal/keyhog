#![cfg(unix)]

//! WHY: Row 127 contract: artifact cache load-only scan execution and zero compilation fallback.
//!
//! What it closes:
//! Closes the in-process compilation fallback defect by enforcing that the scan path performs
//! only loads from prepared execution-pack artifacts, with load failures failing closed with
//! `EXIT_USER_ERROR = 2` rather than falling back to in-process compilation. Also enforces that
//! disabling the developer matcher artifact cache (`--matcher-cache off`) has zero effect on standard scans.
//!
//! What it does not catch / boundary limits:
//! Does not catch hardware GPU adapter hardware failures occurring during kernel execution.
//! Does not catch external OS signal terminations (SIGKILL) mid-scan.

use keyhog::exit_codes::{EXIT_SUCCESS, EXIT_USER_ERROR};
use keyhog_scanner::{
    MatcherArtifactCacheDisableReason, MatcherArtifactCacheOutcome,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;

static PREPARED_INSTALLATION: LazyLock<(tempfile::TempDir, PathBuf, PathBuf)> =
    LazyLock::new(|| {
        let base_tmp = PathBuf::from("/mnt/FlareTraining/santh-archive/tmp");
        let directory = if base_tmp.exists() {
            tempfile::Builder::new()
                .prefix("keyhog-row127-prepared-")
                .tempdir_in(&base_tmp)
                .expect("tempdir in base_tmp")
        } else {
            tempfile::tempdir().expect("temporary install root")
        };

        let cache_home = directory.path().join("cache");
        let pack_root = cache_home.join("keyhog/execution-packs");
        fs::create_dir_all(&pack_root).expect("execution-pack root");
        let key_path = pack_root.join("signing.key");
        let key_bytes = [0x5cu8; 32];
        fs::write(&key_path, key_bytes).expect("write signing key");
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
            .expect("protect signing key");
        let output = pack_root.join("current");

        let result = Command::new(env!("CARGO_BIN_EXE_keyhog"))
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
        (directory, pack_root, output)
    });

fn copy_dir_all(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("create dst dir");
    for entry in fs::read_dir(src).expect("read src dir") {
        let entry = entry.expect("entry");
        let path = entry.path();
        let dest_path = dst.join(entry.file_name());
        if path.is_dir() {
            copy_dir_all(&path, &dest_path);
        } else {
            fs::copy(&path, &dest_path).expect("copy file");
        }
    }
}

fn clone_prepared_installation(cache_home: &Path) -> (PathBuf, PathBuf) {
    let (_temp, source_pack_root, _output) = &*PREPARED_INSTALLATION;
    let pack_root = cache_home.join("keyhog/execution-packs");
    copy_dir_all(source_pack_root, &pack_root);
    let output = pack_root.join("current");
    (pack_root, output)
}

#[test]
fn warm_scan_performs_only_loads_and_zero_compiles() {
    let base_tmp = PathBuf::from("/mnt/FlareTraining/santh-archive/tmp");
    let temp_dir = if base_tmp.exists() {
        tempfile::Builder::new()
            .prefix("keyhog-row127-warm-")
            .tempdir_in(&base_tmp)
            .expect("tempdir in base_tmp")
    } else {
        tempfile::tempdir().expect("tempdir")
    };

    let cache_home = temp_dir.path().join("cache");
    let (_pack_root, _output_dir) = clone_prepared_installation(&cache_home);

    let scan_file = temp_dir.path().join("sample.txt");
    fs::write(&scan_file, "sample payload for load only scan\n").expect("write scan file");
    let profile_output_path = temp_dir.path().join("profile.json");

    let scan_output = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .arg("scan")
        .arg("--daemon=off")
        .arg(&scan_file)
        .arg("--profile-out")
        .arg(&profile_output_path)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", temp_dir.path())
        .output()
        .expect("run scan command");

    assert_eq!(
        scan_output.status.code(),
        Some(EXIT_SUCCESS as i32),
        "scan must exit 0 on clean sample file; stderr:\n{}",
        String::from_utf8_lossy(&scan_output.stderr)
    );

    assert!(profile_output_path.exists(), "profile JSON must exist");
    let profile_content = fs::read_to_string(&profile_output_path).expect("read profile json");
    let profile_json: serde_json::Value =
        serde_json::from_str(&profile_content).expect("parse profile json");

    if let Some(compile_records) = profile_json.get("compile_surfaces").and_then(|v| v.as_array()) {
        for record in compile_records {
            let phase = record.get("phase").and_then(|p| p.as_str()).unwrap_or_default();
            let surface = record.get("surface").and_then(|s| s.as_str()).unwrap_or_default();
            let count = record.get("invocation_count").and_then(|c| c.as_u64()).unwrap_or(0);
            assert_ne!(
                phase, "Scan",
                "Scan phase must perform ZERO runtime compilations for surface {surface}; found {count}"
            );
        }
    }
}

#[test]
fn disabling_matcher_cache_cannot_change_normal_scan_behavior() {
    // Contract: disabling the matcher artifact cache (--matcher-cache off) produces zero behavioral
    // difference on a normal scan with prepared execution-pack artifacts.
    let base_tmp = PathBuf::from("/mnt/FlareTraining/santh-archive/tmp");
    let temp_dir = if base_tmp.exists() {
        tempfile::Builder::new()
            .prefix("keyhog-row127-mcache-")
            .tempdir_in(&base_tmp)
            .expect("tempdir in base_tmp")
    } else {
        tempfile::tempdir().expect("tempdir")
    };

    let cache_home = temp_dir.path().join("cache");
    let (_pack_root, _output_dir) = clone_prepared_installation(&cache_home);

    let scan_file = temp_dir.path().join("test_creds.txt");
    fs::write(
        &scan_file,
        "AKIAIOSFODNN7EXAMPLE\nwJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
    )
    .expect("write test creds");

    // 1. Scan with default matcher cache settings
    let output_default = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .arg("scan")
        .arg("--daemon=off")
        .arg(&scan_file)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", temp_dir.path())
        .output()
        .expect("run scan with default cache");

    // 2. Scan with matcher cache explicitly disabled
    let output_disabled = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .arg("scan")
        .arg("--daemon=off")
        .arg("--matcher-cache")
        .arg("off")
        .arg(&scan_file)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", temp_dir.path())
        .output()
        .expect("run scan with disabled matcher cache");

    // Findings, status codes, and outputs must match
    assert_eq!(
        output_default.status.code(),
        output_disabled.status.code(),
        "exit status codes must be identical with or without --matcher-cache off"
    );

    assert_eq!(
        output_default.stdout, output_disabled.stdout,
        "stdout finding reports must be identical with or without --matcher-cache off"
    );
}

#[test]
fn load_failure_is_fail_closed_error_rather_than_compilation_fallback() {
    // Contract: corruption or deletion of execution pack fails closed with EXIT_USER_ERROR = 2
    // and actionable repair guidance, rather than falling back to compiling in process.
    let base_tmp = PathBuf::from("/mnt/FlareTraining/santh-archive/tmp");
    let temp_dir = if base_tmp.exists() {
        tempfile::Builder::new()
            .prefix("keyhog-row127-failclose-")
            .tempdir_in(&base_tmp)
            .expect("tempdir in base_tmp")
    } else {
        tempfile::tempdir().expect("tempdir")
    };

    let cache_home = temp_dir.path().join("cache");
    let (_pack_root, output_dir) = clone_prepared_installation(&cache_home);

    // Corrupt manifest
    let manifest_path = output_dir.join("manifest.json");
    fs::write(&manifest_path, b"corrupted manifest content\n").expect("corrupt manifest");

    let scan_file = temp_dir.path().join("sample.txt");
    fs::write(&scan_file, "sample clean file\n").expect("write sample");

    let scan_output = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .arg("scan")
        .arg("--daemon=off")
        .arg(&scan_file)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", temp_dir.path())
        .output()
        .expect("run scan command");

    assert_eq!(
        scan_output.status.code(),
        Some(EXIT_USER_ERROR as i32),
        "scan must fail closed with EXIT_USER_ERROR (2) on corrupted artifact; got exit {:?}, stderr:\n{}",
        scan_output.status.code(),
        String::from_utf8_lossy(&scan_output.stderr)
    );

    let stderr = String::from_utf8_lossy(&scan_output.stderr);
    assert!(
        stderr.contains("keyhog install"),
        "stderr must direct the user to repair via `keyhog install`; got stderr:\n{stderr}"
    );
}

#[test]
fn developer_flow_reports_cache_disable_reasons_explicitly() {
    // Derive all disable reasons at runtime
    for &reason in MatcherArtifactCacheDisableReason::ALL {
        let label = reason.as_str();
        assert!(!label.trim().is_empty(), "reason label must be non-empty");

        let explanation = reason.operator_explanation();
        assert!(
            !explanation.trim().is_empty(),
            "operator explanation for {:?} must be non-empty and descriptive",
            reason
        );

        let outcome = MatcherArtifactCacheOutcome::Disabled { reason };
        assert_eq!(outcome.as_str(), "disabled");
        assert_eq!(outcome.disable_reason(), Some(reason));
    }
}
