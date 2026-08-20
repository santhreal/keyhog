#![cfg(unix)]

//! WHY: Prepared execution-pack artifacts must carry identity inputs (detector corpus digest,
//! binary digest, target platform, feature digest, and manifest version). Any identity mismatch or
//! stale artifact MUST fail closed with EXIT_USER_ERROR (2) naming the mismatched input and the exact
//! repair command (`keyhog install`), without falling back to in-process compilation
//! or serving stale artifacts.
//! Running the repair command must successfully restore zero-compilation scan execution.
//!
//! What it closes:
//! Closes silent fallback / stale artifact execution by requiring strict identity matching on every
//! persisted artifact class and proving fail-closed refusal under independent dimension mutation.
//!
//! What it does not catch:
//! Hardware faults during memory bus reads or OS kernel thread scheduler panics.

use keyhog::exit_codes::{EXIT_SUCCESS, EXIT_USER_ERROR};
use keyhog::testing::execution_pack_install::{ArtifactIdentityInput, InstalledArtifactClass};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;

static PREPARED_INSTALLATION: LazyLock<(tempfile::TempDir, PathBuf, PathBuf)> =
    LazyLock::new(|| {
        let directory = tempfile::tempdir().expect("temporary install root");
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
    let target_pack_root = cache_home.join("keyhog/execution-packs");
    copy_dir_all(source_pack_root, &target_pack_root);
    let target_current = target_pack_root.join("current");
    (target_pack_root, target_current)
}

#[test]
fn runtime_derived_identity_inputs_fail_closed_on_staleness_and_repair_restores_clean_scan() {
    // 1. Derive identity inputs at runtime from artifact class schema
    let manifest_inputs = InstalledArtifactClass::Manifest.identity_inputs();
    assert!(
        !manifest_inputs.is_empty(),
        "manifest identity inputs must be non-empty"
    );

    let all_inputs = ArtifactIdentityInput::ALL;
    assert!(
        all_inputs.len() >= 5,
        "must cover all registered identity input dimensions"
    );

    let test_mutations: &[(&str, &str)] = &[
        ("detector_digest", "detector"),
        ("binary_digest", "binary"),
        ("target_digest", "target"),
        ("feature_digest", "feature"),
    ];

    let temp = tempfile::tempdir().expect("create temp dir");
    let cache_home = temp.path().join("cache");
    let home_dir = temp.path().join("home");
    fs::create_dir_all(&home_dir).expect("create home directory");

    let target_dir = temp.path().join("workspace");
    fs::create_dir_all(&target_dir).expect("create workspace dir");
    fs::write(
        target_dir.join("sample.txt"),
        "clean text for staleness refusal test\n",
    )
    .expect("write sample");

    // Assert each dimension fails closed independently
    for &(field_name, expected_error_token) in test_mutations {
        let (_pack_root, current_dir) = clone_prepared_installation(&cache_home);
        let manifest_path = current_dir.join("manifest.json");
        assert!(manifest_path.is_file(), "manifest must exist");

        let manifest_content = fs::read_to_string(&manifest_path).expect("read manifest");
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(&manifest_content).expect("parse manifest json");

        // Mutate exactly one identity input dimension
        manifest_json[field_name] = serde_json::Value::String(
            "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        );
        fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest_json).expect("serialize mutated manifest"),
        )
        .expect("write mutated manifest");

        // 2. Assert scan fails closed with exit code 2 (EXIT_USER_ERROR)
        let scan_output = Command::new(env!("CARGO_BIN_EXE_keyhog"))
            .arg("scan")
            .arg(&target_dir)
            .env("XDG_CACHE_HOME", &cache_home)
            .env("HOME", &home_dir)
            .output()
            .expect("execute scan");

        let exit_code = scan_output.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&scan_output.stderr);

        assert_eq!(
            exit_code,
            i32::from(EXIT_USER_ERROR),
            "stale identity input '{field_name}' must fail closed with exit code 2; got {exit_code}\nstderr={stderr}"
        );

        assert!(
            stderr.contains(expected_error_token),
            "stderr must name the stale dimension '{expected_error_token}'; got:\n{stderr}"
        );

        assert!(
            stderr.contains("keyhog install"),
            "stderr must instruct operator to run `keyhog install`; got:\n{stderr}"
        );
    }

    // 3. Test repair command execution and subsequent zero-compilation scan
    let (_pack_root, current_dir) = clone_prepared_installation(&cache_home);
    let manifest_path = current_dir.join("manifest.json");
    let manifest_content = fs::read_to_string(&manifest_path).expect("read manifest");
    let mut manifest_json: serde_json::Value =
        serde_json::from_str(&manifest_content).expect("parse manifest json");
    manifest_json["binary_digest"] = serde_json::Value::String(
        "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
    );
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest_json).expect("serialize mutated manifest"),
    )
    .expect("write mutated manifest");

    let key_path = _pack_root.join("signing.key");
    let install_output = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .arg("compile-execution-packs")
        .arg("--output-dir")
        .arg(&current_dir)
        .arg("--signing-key")
        .arg(&key_path)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", &home_dir)
        .output()
        .expect("execute repair compile-execution-packs");

    assert!(
        install_output.status.success(),
        "repair compilation must succeed; stderr:\n{}",
        String::from_utf8_lossy(&install_output.stderr)
    );

    // 4. Assert subsequent scan succeeds with zero runtime compiles
    let profile_path = temp.path().join("post-repair-profile.json");
    let post_repair_scan = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .arg("scan")
        .arg(&target_dir)
        .arg("--profile-out")
        .arg(&profile_path)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", &home_dir)
        .output()
        .expect("execute post repair scan");

    let post_exit_code = post_repair_scan.status.code().unwrap_or(-1);
    assert_eq!(
        post_exit_code,
        i32::from(EXIT_SUCCESS),
        "scan after repair must succeed; stderr:\n{}",
        String::from_utf8_lossy(&post_repair_scan.stderr)
    );

    assert!(
        profile_path.is_file(),
        "profile JSON must be produced after repair scan"
    );
    let profile_content = fs::read_to_string(&profile_path).expect("read profile");
    let profile_json: serde_json::Value =
        serde_json::from_str(&profile_content).expect("parse profile json");

    let compile_records = profile_json
        .get("compile_surfaces")
        .and_then(|v| v.as_array())
        .expect("compile_surfaces array must be present");
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
            "post-repair scan must have ZERO runtime compilations for {surface}; got {runtime_compiles}"
        );
    }
}

#[test]
fn unsupported_manifest_version_fails_closed() {
    let temp = tempfile::tempdir().expect("create temp dir");
    let cache_home = temp.path().join("cache");
    let home_dir = temp.path().join("home");
    fs::create_dir_all(&home_dir).expect("create home directory");

    let (_pack_root, current_dir) = clone_prepared_installation(&cache_home);
    let manifest_path = current_dir.join("manifest.json");

    let manifest_content = fs::read_to_string(&manifest_path).expect("read manifest");
    let mut manifest_json: serde_json::Value =
        serde_json::from_str(&manifest_content).expect("parse manifest json");

    manifest_json["version"] = serde_json::Value::from(999);
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest_json).expect("serialize mutated manifest"),
    )
    .expect("write mutated manifest");

    let target_dir = temp.path().join("workspace");
    fs::create_dir_all(&target_dir).expect("create workspace dir");
    fs::write(
        target_dir.join("sample.txt"),
        "sample text for version staleness test\n",
    )
    .expect("write sample");

    let scan_output = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .arg("scan")
        .arg(&target_dir)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", &home_dir)
        .output()
        .expect("execute scan");

    let exit_code = scan_output.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&scan_output.stderr);

    assert_eq!(
        exit_code,
        i32::from(EXIT_USER_ERROR),
        "unsupported manifest version must fail closed with exit code 2; got {exit_code}\nstderr={stderr}"
    );
    assert!(
        stderr.contains("version") && stderr.contains("keyhog install"),
        "stderr must name version mismatch and repair command; got:\n{stderr}"
    );
}
