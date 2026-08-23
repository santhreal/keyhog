#![cfg(unix)]

//! WHY: Row 124 contract: the scan path must not compile detector artifacts in-process.
//! Absence or mismatch of any execution-pack artifact class must fail closed with a named error,
//! the identity input that mismatched, the exact repair command, and distinct exit code (EXIT_USER_ERROR = 2).
//! In-process compilation is permitted ONLY behind `--developer-compile-embedded-detectors`, which is hidden
//! from help and self-identifying in results and profile artifacts.

use keyhog::exit_codes::EXIT_USER_ERROR;
use keyhog::testing::execution_pack_install::{
    InstalledArtifactClass, PERMITTED_DETECTOR_COMPILATION_ENTRY_POINTS,
};
use std::fs;
use std::process::Command;

#[path = "support/installed_generation.rs"]
mod installed_generation;
use installed_generation::clone_prepared_installation;

#[test]
fn permitted_compilation_entry_points_is_exact() {
    // Contract (a): the set of program entry points permitted to compile a detector artifact
    // is exactly {install, update}, and that set is declared in one place.
    assert_eq!(
        PERMITTED_DETECTOR_COMPILATION_ENTRY_POINTS,
        &["install", "update"],
        "permitted detector compilation entry points must be declared in one place and be exactly {{install, update}}"
    );
}

#[test]
fn removing_each_artifact_class_from_prepared_installation_refuses_scan_fail_closed() {
    // Contract (d): removing each artifact class from a prepared installation produces a refusal
    // that names the class, the exact repair command, and distinct exit code (EXIT_USER_ERROR = 2).
    // Class list is enumerated at run time from InstalledArtifactClass::EXECUTION_PACK_CLASSES.
    let target_classes = InstalledArtifactClass::EXECUTION_PACK_CLASSES;
    assert!(
        !target_classes.is_empty(),
        "InstalledArtifactClass::EXECUTION_PACK_CLASSES must not be empty"
    );

    for &class in target_classes {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let cache_home = temp_dir.path().join("cache");
        let dummy_scan_file = temp_dir.path().join("clean.txt");
        fs::write(&dummy_scan_file, "hello world clean file\n").expect("write dummy file");

        let (_pack_root, output_dir) = clone_prepared_installation(&cache_home);

        // Remove the specific artifact class
        match class {
            InstalledArtifactClass::Manifest => {
                let manifest = output_dir.join("manifest.json");
                if manifest.exists() {
                    fs::remove_file(manifest).expect("remove manifest");
                }
            }
            InstalledArtifactClass::VerificationKey => {
                let key = output_dir.parent().unwrap().join("signing.key");
                if key.exists() {
                    fs::remove_file(key).expect("remove signing key");
                }
            }
            InstalledArtifactClass::ExecutionPack => {
                for entry in fs::read_dir(&output_dir).expect("read output dir") {
                    let entry = entry.expect("entry");
                    let ext = entry
                        .path()
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .map(str::to_string);
                    if ext == Some("khpack".to_string()) || ext == Some("pack".to_string()) {
                        fs::remove_file(entry.path()).expect("remove pack file");
                    }
                }
            }
            InstalledArtifactClass::Signature => {
                for entry in fs::read_dir(&output_dir).expect("read output dir") {
                    let entry = entry.expect("entry");
                    let ext = entry
                        .path()
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .map(str::to_string);
                    if ext == Some("sig".to_string()) || ext == Some("khsig".to_string()) {
                        fs::remove_file(entry.path()).expect("remove sig file");
                    }
                }
            }
            InstalledArtifactClass::GpuLiteralArtifact => {
                let gpu_dir = cache_home.join("keyhog/gpu_literals");
                if gpu_dir.exists() {
                    let _ = fs::remove_dir_all(gpu_dir);
                }
            }
            InstalledArtifactClass::AutorouteCalibration => {
                let autoroute = cache_home.join("keyhog/autoroute.json");
                if autoroute.exists() {
                    let _ = fs::remove_file(autoroute);
                }
            }
        }

        // Run scan without developer flag
        let output = Command::new(env!("CARGO_BIN_EXE_keyhog"))
            .arg("scan")
            .arg("--daemon=off")
            .arg(&dummy_scan_file)
            .env("XDG_CACHE_HOME", &cache_home)
            .env("HOME", temp_dir.path())
            .output()
            .expect("run scan command");

        let exit_code = output.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert_eq!(
            exit_code as u8, EXIT_USER_ERROR,
            "scan must fail with EXIT_USER_ERROR (2) when artifact class {:?} ({}) is missing; got exit {exit_code}, stderr:\n{stderr}",
            class,
            class.name()
        );

        assert!(
            stderr.contains(class.name()),
            "stderr must name the missing artifact class {:?} ('{}'); got stderr:\n{stderr}",
            class,
            class.name()
        );

        assert!(
            stderr.contains("keyhog install"),
            "stderr must provide the exact repair command ('keyhog install'); got stderr:\n{stderr}"
        );
    }
}

#[test]
fn stale_identity_in_manifest_refuses_scan_with_mismatched_input_and_repair() {
    // Contract (d): a stale identity input in manifest produces a refusal carrying
    // the class name ('execution-pack manifest'), the mismatched identity input name ('binary'),
    // the exact repair command ('keyhog install'), and exit code 2.
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let cache_home = temp_dir.path().join("cache");
    let dummy_scan_file = temp_dir.path().join("clean.txt");
    fs::write(&dummy_scan_file, "hello world clean file\n").expect("write dummy file");

    let (_pack_root, output_dir) = clone_prepared_installation(&cache_home);

    // Corrupt the binary digest in manifest.json
    let manifest_path = output_dir.join("manifest.json");
    let manifest_bytes = fs::read(&manifest_path).expect("read manifest");
    let mut manifest_json: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).expect("parse manifest");
    manifest_json["binary_digest"] = serde_json::Value::String(
        "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
    );
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest_json).unwrap(),
    )
    .expect("write modified manifest");

    let output = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .arg("scan")
        .arg("--daemon=off")
        .arg(&dummy_scan_file)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", temp_dir.path())
        .output()
        .expect("run scan command");

    let exit_code = output.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        exit_code as u8, EXIT_USER_ERROR,
        "scan must fail with exit code 2 on stale manifest identity; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("execution-pack manifest"),
        "stderr must name the class 'execution-pack manifest'; got:\n{stderr}"
    );
    assert!(
        stderr.contains("binary"),
        "stderr must name the mismatched input 'binary'; got:\n{stderr}"
    );
    assert!(
        stderr.contains("keyhog install"),
        "stderr must contain the repair command 'keyhog install'; got:\n{stderr}"
    );
}

#[test]
fn developer_escape_hatch_is_hidden_from_help_and_marks_profile() {
    // Contract (c): developer escape hatch is a named flag, is absent from default help,
    // and marks its run in both result and profile artifact so measurements are self-identifying.
    let help_output = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .arg("scan")
        .arg("--help")
        .output()
        .expect("run scan --help");
    let help_text = String::from_utf8_lossy(&help_output.stdout);
    assert!(
        !help_text.contains("developer-compile-embedded-detectors"),
        "--developer-compile-embedded-detectors must be hidden from default --help output"
    );

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let dummy_scan_file = temp_dir.path().join("clean.txt");
    fs::write(&dummy_scan_file, "hello world clean file\n").expect("write dummy file");
    let profile_out = temp_dir.path().join("profile.json");
    let empty_cache = temp_dir.path().join("empty_cache");
    fs::create_dir_all(&empty_cache).expect("empty cache dir");

    // The hatch governs where detector artifacts come from, not routing: an
    // empty cache has no autoroute decision and `auto` refuses to guess one, so
    // this run carries an explicit diagnostic backend.
    let output = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .arg("scan")
        .arg("--daemon=off")
        .arg("--backend")
        .arg("cpu")
        .arg("--developer-compile-embedded-detectors")
        .arg("--profile-out")
        .arg(&profile_out)
        .arg(&dummy_scan_file)
        .env("XDG_CACHE_HOME", &empty_cache)
        .env("HOME", temp_dir.path())
        .output()
        .expect("run scan with developer flag");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "scan with --developer-compile-embedded-detectors must succeed; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("developer mode active")
            || stderr.contains("developer escape hatch active")
            || stderr.contains("developer-compile-embedded-detectors"),
        "stderr must indicate developer mode was active; got:\n{stderr}"
    );

    assert!(profile_out.exists(), "profile JSON must be written");
    let profile_bytes = fs::read(&profile_out).expect("read profile JSON");
    let profile_str = String::from_utf8_lossy(&profile_bytes);
    assert!(
        profile_str.contains("developer")
            || profile_str.contains("Compiled")
            || profile_str.contains("matcher-artifact"),
        "profile artifact must be self-identifying for developer compile mode; got:\n{profile_str}"
    );
}
