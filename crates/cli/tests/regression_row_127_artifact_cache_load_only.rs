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

use keyhog::exit_codes::{EXIT_FINDINGS, EXIT_SUCCESS, EXIT_USER_ERROR};
use keyhog_scanner::{MatcherArtifactCacheDisableReason, MatcherArtifactCacheOutcome};
use std::fs;
use std::process::Command;

#[path = "support/installed_generation.rs"]
mod installed_generation;
use installed_generation::clone_prepared_installation;

#[test]
fn warm_scan_performs_only_loads_and_zero_compiles() {
    let temp_dir = tempfile::tempdir().expect("tempdir");

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

    let compile_records = profile_json
        .get("compile_surfaces")
        .and_then(|v| v.as_array())
        .expect("compile_surfaces array must exist in profile JSON");
    assert!(
        !compile_records.is_empty(),
        "compile_surfaces must not be empty"
    );
    for record in compile_records {
        let surface = record
            .get("name")
            .or_else(|| record.get("surface"))
            .and_then(|s| s.as_str())
            .unwrap_or_default();
        let runtime_compiles = record
            .get("runtime_compiles")
            .and_then(|c| c.as_u64())
            .unwrap_or(0);
        assert_eq!(
            runtime_compiles, 0,
            "Scan phase must perform ZERO runtime compilations for surface {surface}; found runtime_compiles={runtime_compiles}"
        );
    }
}

#[test]
fn disabling_matcher_cache_cannot_change_normal_scan_behavior() {
    // Contract: disabling the matcher artifact cache (--matcher-cache off) produces zero behavioral
    // difference on a normal scan with prepared execution-pack artifacts.
    let temp_dir = tempfile::tempdir().expect("tempdir");

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
    let temp_dir = tempfile::tempdir().expect("tempdir");

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

#[test]
fn disabled_detector_and_its_dependent_produce_no_findings_under_prepared_pack() {
    let temp_dir = tempfile::tempdir().expect("tempdir");

    let cache_home = temp_dir.path().join("cache");
    let (_pack_root, _output_dir) = clone_prepared_installation(&cache_home);

    // A dotenv file is a supported assignment context, so the planted pair is
    // `likely` evidence and blocks. In a `.txt` file the same pair is
    // `review` (`unsupported-context`) and exits 0, which would test the
    // evidence policy instead of detector dependency silencing.
    let scan_file = temp_dir.path().join(".env");
    fs::write(
        &scan_file,
        "RAZORPAY_KEY_ID=rzp_test_Kp4Qx7Rm2Sn5Tb\nRAZORPAY_KEY_SECRET=Vk9Bn3Lp7Qm2Rs5Tw8Vk9Bn3\n",
    )
    .expect("write razorpay creds");

    // Detector ids, not rendered display names: the text report prints
    // "Razorpay Key Secret" and a `razorpay_key_secret=` companion line, so a
    // substring check against the text output cannot fail on this defect.
    let detector_ids = |stdout: &str| -> Vec<String> {
        serde_json::from_str::<serde_json::Value>(stdout)
            .expect("scan must emit a JSON document")
            .as_array()
            .expect("JSON report is an array")
            .iter()
            .filter_map(|finding| {
                finding
                    .get("detector_id")
                    .and_then(|id| id.as_str())
                    .map(str::to_string)
            })
            .collect()
    };

    let output_enabled = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .arg("scan")
        .arg("--daemon=off")
        .arg("--format")
        .arg("json")
        .arg(&scan_file)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", temp_dir.path())
        .output()
        .expect("run scan with detectors enabled");

    assert_eq!(
        output_enabled.status.code(),
        Some(EXIT_FINDINGS as i32),
        "a scan that finds the planted razorpay pair exits with the findings code; stderr:\n{}",
        String::from_utf8_lossy(&output_enabled.stderr)
    );
    let stdout_enabled = String::from_utf8_lossy(&output_enabled.stdout);
    let enabled_ids = detector_ids(&stdout_enabled);
    assert!(
        enabled_ids.iter().any(|id| id == "razorpay-key-secret"),
        "normal scan must detect the razorpay secret; ids={enabled_ids:?} stderr:\n{}",
        String::from_utf8_lossy(&output_enabled.stderr)
    );
    assert!(
        enabled_ids.iter().any(|id| id == "razorpay-key-id"),
        "normal scan must detect the dependent razorpay key id; ids={enabled_ids:?}"
    );

    // Disable `razorpay-key-secret`: its dependent must go silent with it.
    let config_path = temp_dir.path().join(".keyhog.toml");
    fs::write(
        &config_path,
        "[detector.razorpay-key-secret]\nenabled = false\n",
    )
    .expect("write .keyhog.toml");

    let output_disabled = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .arg("scan")
        .arg("--daemon=off")
        .arg("--format")
        .arg("json")
        .arg("--config")
        .arg(&config_path)
        .arg(&scan_file)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", temp_dir.path())
        .output()
        .expect("run scan with disabled detector config");

    assert_eq!(
        output_disabled.status.code(),
        Some(EXIT_SUCCESS as i32),
        "silencing the only planted pair leaves a clean scan; stderr:\n{}",
        String::from_utf8_lossy(&output_disabled.stderr)
    );
    let disabled_ids = detector_ids(&String::from_utf8_lossy(&output_disabled.stdout));
    assert!(
        !disabled_ids
            .iter()
            .any(|id| id == "razorpay-key-secret" || id == "razorpay-key-id"),
        "disabling required detector `razorpay-key-secret` must silence both it and its \
         dependent `razorpay-key-id`; ids={disabled_ids:?}"
    );
}

#[test]
fn scan_succeeds_when_local_detectors_folder_exists_by_loading_prepared_pack() {
    let temp_dir = tempfile::tempdir().expect("tempdir");

    let cache_home = temp_dir.path().join("cache");
    let (_pack_root, _output_dir) = clone_prepared_installation(&cache_home);

    // A `detectors/` directory in the working directory replaces the corpus, so
    // the prepared pack only stays usable while that directory carries the same
    // corpus the generation was built from. Copy the workspace corpus, which is
    // exactly what the binary embedded.
    let detectors_dir = temp_dir.path().join("detectors");
    installed_generation::copy_dir_all(
        &std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../detectors"),
        &detectors_dir,
    );

    let scan_file = temp_dir.path().join("sample.txt");
    fs::write(&scan_file, "sample payload for load only scan\n").expect("write scan file");

    let scan_output = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .current_dir(temp_dir.path())
        .arg("scan")
        .arg("--daemon=off")
        .arg(&scan_file)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", temp_dir.path())
        .output()
        .expect("run scan command");

    assert_eq!(
        scan_output.status.code(),
        Some(EXIT_SUCCESS as i32),
        "scan must succeed when local detectors folder exists by using prepared pack; stderr:\n{}",
        String::from_utf8_lossy(&scan_output.stderr)
    );

    let stderr = String::from_utf8_lossy(&scan_output.stderr);
    assert!(
        stderr.contains("cache detector-plans: hit"),
        "cache summary for detector-plans must report 'hit' under prepared pack; stderr:\n{stderr}"
    );
}

/// The other half of the contract above: pack reuse is decided by corpus
/// identity, so a `detectors/` directory that is NOT the installed generation
/// gets neither the pack nor its calibrated routing. It has no measured
/// decision of its own, so the scan fails closed and names the mismatch
/// instead of scanning with evidence for another corpus.
#[test]
fn edited_local_detectors_folder_compiles_instead_of_reusing_the_pack() {
    let temp_dir = tempfile::tempdir().expect("tempdir");

    let cache_home = temp_dir.path().join("cache");
    let (_pack_root, _output_dir) = clone_prepared_installation(&cache_home);

    let detectors_dir = temp_dir.path().join("detectors");
    installed_generation::copy_dir_all(
        &std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../detectors"),
        &detectors_dir,
    );
    // A corpus missing one detector is a different corpus.
    fs::remove_file(detectors_dir.join("aws-bedrock-api-key.toml"))
        .expect("remove one detector from the copied corpus");

    let scan_file = temp_dir.path().join("sample.txt");
    fs::write(&scan_file, "sample payload for edited corpus scan\n").expect("write scan file");

    let scan_output = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .current_dir(temp_dir.path())
        .arg("scan")
        .arg("--daemon=off")
        .arg(&scan_file)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", temp_dir.path())
        .output()
        .expect("run scan command");

    let stderr = String::from_utf8_lossy(&scan_output.stderr);
    assert_eq!(
        scan_output.status.code(),
        Some(EXIT_USER_ERROR as i32),
        "an edited corpus has no calibrated route and must fail closed; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("detector digest mismatch"),
        "the refusal must name the corpus identity that did not match; stderr:\n{stderr}"
    );
    assert!(
        scan_output.stdout.is_empty(),
        "a run that never routed emits no report document; stdout:\n{}",
        String::from_utf8_lossy(&scan_output.stdout)
    );
}
