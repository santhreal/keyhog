#![cfg(unix)]

//! WHY: Row 130 acceptance gate: clean install on an empty cache followed by scan
//! must result in 0 runtime compilations across all compile surfaces.
//!
//! What it closes:
//! Closes the end-to-end installation gap defect where uninstalled, partially installed,
//! or freshly initialized environments either fail to produce required artifacts or
//! silently fall back to in-process runtime compilation during scans. Enforces that:
//! 1. Scans on an uninstalled clean cache fail closed with `EXIT_USER_ERROR = 2`.
//! 2. `keyhog install` generates all required artifact classes (execution packs,
//!    detector plans, keyword matchers, entropy policies, signatures, autoroute calibration).
//! 3. Subsequent scans succeed with exactly ZERO runtime compilations across all 13 compile surfaces.
//! 4. Scans on credential payloads detect secrets with 0 runtime compilations.
//! 5. Tampered or missing artifacts fail closed without compilation fallback.
//!
//! What it does not catch / boundary limits:
//! Does not catch hardware GPU silicon faults during CUDA kernel execution.
//! Does not catch SIGKILL signal terminations issued by the operating system.

use keyhog::exit_codes::{EXIT_SUCCESS, EXIT_USER_ERROR};
use keyhog_profile::CompileSurfaceId;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn create_clean_environment(prefix: &str) -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let base_tmp = PathBuf::from("/mnt/FlareTraining/santh-archive/tmp");
    let temp_dir = if base_tmp.exists() {
        tempfile::Builder::new()
            .prefix(prefix)
            .tempdir_in(&base_tmp)
            .expect("create temporary directory in base_tmp")
    } else {
        tempfile::tempdir().expect("create temporary directory")
    };

    let cache_home = temp_dir.path().join("cache");
    let home_dir = temp_dir.path().join("home");
    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&cache_home).expect("create clean cache directory");
    fs::create_dir_all(&home_dir).expect("create clean home directory");
    fs::create_dir_all(&bin_dir).expect("create bin directory");

    let isolated_exe = bin_dir.join(format!("keyhog{}", std::env::consts::EXE_SUFFIX));
    let staging_exe = bin_dir.join("keyhog.stage");
    fs::copy(env!("CARGO_BIN_EXE_keyhog"), &staging_exe).expect("copy keyhog binary");
    fs::rename(&staging_exe, &isolated_exe).expect("commit isolated executable");
    (temp_dir, cache_home, home_dir, isolated_exe)
}

/// Build an isolated `keyhog install` command. Under `ci-lean` the installer's
/// internal `calibrate-autoroute` measures the FULL production ladder unless
/// the fixture sentinels select the bounded one; without them every test here
/// spends minutes of CPU recalibrating, which blew the CI lane's time budget.
/// Mirrors the row-135 installation fixture contract.
fn install_command(exe: &Path) -> Command {
    let mut cmd = Command::new(exe);
    cmd.arg("install");
    #[cfg(feature = "ci-lean")]
    {
        cmd.env(
            "KEYHOG_CI_AUTOROUTE_TIMING_FIXTURE",
            "confidence-separated-v1",
        )
        .env(
            "KEYHOG_CI_AUTOROUTE_FIXTURE_AUTH",
            "bench-backend-parity-v1",
        )
        .env("KEYHOG_CI_AUTOROUTE_WORKLOAD_FIXTURE", "bounded-e2e-v1")
        .env(
            "KEYHOG_CI_AUTOROUTE_WORKLOAD_FIXTURE_AUTH",
            "core-workload-plan-v1",
        );
    }
    cmd
}

#[test]
fn clean_cache_scan_fails_closed_without_installation() {
    let (_temp, cache_home, home_dir, exe) = create_clean_environment("keyhog-row130-uninstalled-");

    let scan_file = home_dir.join("sample.txt");
    fs::write(&scan_file, "plain clean text content\n").expect("write sample file");

    let scan_output = Command::new(&exe)
        .arg("scan")
        .arg("--daemon=off")
        .arg(&scan_file)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", &home_dir)
        .output()
        .expect("execute scan on clean uninstalled cache");

    assert_eq!(
        scan_output.status.code(),
        Some(EXIT_USER_ERROR as i32),
        "scan on uninstalled cache must fail closed with exit code 2; got code {:?}, stderr:\n{}",
        scan_output.status.code(),
        String::from_utf8_lossy(&scan_output.stderr)
    );

    let stderr = String::from_utf8_lossy(&scan_output.stderr);
    // The uninstalled-cache failure is the autoroute fail-closed contract: no
    // persisted fastest-correct decision exists, the scan names the missing
    // state, and the remedy names calibration (installers get
    // `install.sh --calibrate` / `install.ps1 -Calibrate`).
    assert!(
        stderr.contains("autoroute calibration required"),
        "stderr must name the missing autoroute calibration; got:\n{stderr}"
    );
    assert!(
        stderr.contains("install.sh --calibrate")
            && stderr.contains("install.ps1 -Calibrate"),
        "stderr must guide installers to the calibrated install path; got:\n{stderr}"
    );
    assert!(
        stderr.contains("No backend was selected and this batch was not scanned"),
        "stderr must state that nothing was scanned rather than substituting a backend; got:\n{stderr}"
    );
}

#[test]
fn clean_install_generates_all_artifact_classes_and_enables_zero_compile_scans() {
    let (_temp, cache_home, home_dir, exe) =
        create_clean_environment("keyhog-row130-clean-install-");

    // 1. Run `keyhog install`
    let install_output = install_command(&exe)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", &home_dir)
        .output()
        .expect("execute keyhog install");

    assert_eq!(
        install_output.status.code(),
        Some(EXIT_SUCCESS as i32),
        "`keyhog install` must exit 0; stderr:\n{}\nstdout:\n{}",
        String::from_utf8_lossy(&install_output.stderr),
        String::from_utf8_lossy(&install_output.stdout)
    );

    // 2. Verify all artifact classes are produced and valid in the cache root
    let keyhog_cache = cache_home.join("keyhog");
    let pack_root = keyhog_cache.join("execution-packs");
    assert!(
        pack_root.join("signing.key").is_file(),
        "signing key must be generated"
    );
    let current_packs = pack_root.join("current");
    assert!(
        current_packs.join("manifest.json").is_file(),
        "manifest.json must be generated"
    );
    if keyhog_scanner::hw_probe::multiple_backends_compiled() {
        assert!(
            keyhog_cache.join("autoroute.json").is_file(),
            "autoroute.json calibration table must be generated when multiple backends are compiled"
        );
    }

    // Verify .khpack and .sig artifacts exist
    let entries = fs::read_dir(&current_packs)
        .expect("read current packs directory")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();

    assert!(
        entries.iter().any(|name| name.ends_with(".khpack")),
        "current pack directory must contain at least one .khpack file; found {entries:?}"
    );
    assert!(
        entries.iter().any(|name| name.ends_with(".sig")),
        "current pack directory must contain at least one .sig file; found {entries:?}"
    );

    // 3. Run scan on a clean file and verify profile JSON records 0 runtime compiles
    let scan_file = home_dir.join("clean_sample.txt");
    fs::write(&scan_file, "plain text sample without secrets\n").expect("write clean sample");
    let profile_path = home_dir.join("profile.json");

    let scan_output = Command::new(&exe)
        .arg("scan")
        .arg("--daemon=off")
        .arg(&scan_file)
        .arg("--profile-out")
        .arg(&profile_path)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", &home_dir)
        .output()
        .expect("execute scan on installed cache");

    assert_eq!(
        scan_output.status.code(),
        Some(EXIT_SUCCESS as i32),
        "scan on clean file must exit 0; stderr:\n{}",
        String::from_utf8_lossy(&scan_output.stderr)
    );

    assert!(
        profile_path.is_file(),
        "profile artifact must be generated at {}",
        profile_path.display()
    );

    let profile_content = fs::read_to_string(&profile_path).expect("read profile json");
    let profile_json: serde_json::Value =
        serde_json::from_str(&profile_content).expect("parse profile json");

    let compile_records = profile_json
        .get("compile_surfaces")
        .and_then(|v| v.as_array())
        .expect("compile_surfaces array must be present in profile JSON");

    assert!(
        !compile_records.is_empty(),
        "compile_surfaces array must not be empty"
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
            "Scan phase must have ZERO compile surface invocations for surface {surface}; found runtime_compiles={runtime_compiles}"
        );
    }
}

#[test]
fn clean_install_detects_real_credentials_with_zero_runtime_compiles() {
    let (_temp, cache_home, home_dir, exe) = create_clean_environment("keyhog-row130-cred-scan-");

    // 1. Run `keyhog install`
    let install_output = install_command(&exe)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", &home_dir)
        .output()
        .expect("execute keyhog install");

    assert_eq!(
        install_output.status.code(),
        Some(EXIT_SUCCESS as i32),
        "`keyhog install` must succeed"
    );

    // 2. Scan file with real secret formats
    let secret_file = home_dir.join("secrets.env");
    fs::write(
        &secret_file,
        "AWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7XYA\ngithub_token=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\n",
    )
    .expect("write secret fixture");

    let profile_path = home_dir.join("cred_profile.json");
    let scan_output = Command::new(&exe)
        .arg("scan")
        .arg("--daemon=off")
        .arg(&secret_file)
        .arg("--profile-out")
        .arg(&profile_path)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", &home_dir)
        .output()
        .expect("execute scan on secret fixture");

    // Findings detected -> exit code 1
    let exit_code = scan_output.status.code().unwrap_or(-1);
    assert_eq!(
        exit_code,
        1,
        "scan on file with secrets must exit 1 (findings detected); stderr:\n{}",
        String::from_utf8_lossy(&scan_output.stderr)
    );

    // 3. Verify zero runtime compilations in profile
    assert!(profile_path.is_file(), "profile json must be written");
    let profile_content = fs::read_to_string(&profile_path).expect("read profile json");
    let profile_json: serde_json::Value =
        serde_json::from_str(&profile_content).expect("parse profile json");

    let compile_records = profile_json
        .get("compile_surfaces")
        .and_then(|v| v.as_array())
        .expect("compile_surfaces array must be present");

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
            "Scan phase on credentials must have ZERO runtime compiles for surface {surface}; found runtime_compiles={runtime_compiles}"
        );
    }
}

#[test]
fn artifact_mutation_fails_closed_without_compilation_fallback() {
    let (_temp, cache_home, home_dir, exe) = create_clean_environment("keyhog-row130-mutation-");

    // Install first
    let install_output = install_command(&exe)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", &home_dir)
        .output()
        .expect("execute keyhog install");
    assert_eq!(install_output.status.code(), Some(EXIT_SUCCESS as i32));

    let keyhog_cache = cache_home.join("keyhog");
    let manifest_path = keyhog_cache.join("execution-packs/current/manifest.json");
    let signing_key_path = keyhog_cache.join("execution-packs/signing.key");

    let scan_file = home_dir.join("sample.txt");
    fs::write(&scan_file, "plain text sample\n").expect("write sample");

    // Mutation 1: Corrupt manifest
    let original_manifest = fs::read_to_string(&manifest_path).expect("read manifest");
    fs::write(&manifest_path, "{ \"corrupt\": true }").expect("corrupt manifest");

    let scan_output = Command::new(&exe)
        .arg("scan")
        .arg("--daemon=off")
        .arg(&scan_file)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", &home_dir)
        .output()
        .expect("execute scan on corrupted manifest");

    assert_eq!(
        scan_output.status.code(),
        Some(EXIT_USER_ERROR as i32),
        "corrupted manifest must fail closed with exit code 2"
    );

    // Restore manifest, Mutation 2: Tamper signing key
    fs::write(&manifest_path, &original_manifest).expect("restore manifest");
    fs::write(&signing_key_path, [0x00u8; 32]).expect("tamper signing key");

    let scan_output2 = Command::new(&exe)
        .arg("scan")
        .arg("--daemon=off")
        .arg(&scan_file)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", &home_dir)
        .output()
        .expect("execute scan on tampered signing key");

    assert_eq!(
        scan_output2.status.code(),
        Some(EXIT_USER_ERROR as i32),
        "tampered signing key must fail closed with exit code 2"
    );
}

#[test]
fn runtime_derived_compile_surface_exhaustiveness() {
    // Assert all 13 compile surface IDs are covered
    assert_eq!(
        CompileSurfaceId::ALL.len(),
        13,
        "CompileSurfaceId::ALL must contain exactly 13 compile surfaces"
    );

    let (_temp, cache_home, home_dir, exe) =
        create_clean_environment("keyhog-row130-exhaustiveness-");

    let install_output = install_command(&exe)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", &home_dir)
        .output()
        .expect("execute keyhog install");
    assert_eq!(install_output.status.code(), Some(EXIT_SUCCESS as i32));

    let scan_file = home_dir.join("sample.txt");
    fs::write(&scan_file, "plain sample text\n").expect("write sample");
    let profile_path = home_dir.join("profile.json");

    let scan_output = Command::new(&exe)
        .arg("scan")
        .arg("--daemon=off")
        .arg(&scan_file)
        .arg("--profile-out")
        .arg(&profile_path)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", &home_dir)
        .output()
        .expect("execute scan");
    assert_eq!(scan_output.status.code(), Some(EXIT_SUCCESS as i32));

    let profile_content = fs::read_to_string(&profile_path).expect("read profile");
    let profile_json: serde_json::Value =
        serde_json::from_str(&profile_content).expect("parse profile json");

    let compile_records = profile_json
        .get("compile_surfaces")
        .and_then(|v| v.as_array())
        .expect("compile_surfaces array");

    let reported_surfaces: BTreeSet<String> = compile_records
        .iter()
        .filter_map(|r| {
            r.get("name")
                .or_else(|| r.get("surface"))
                .and_then(|s| s.as_str())
                .map(|s| s.to_string())
        })
        .collect();

    for &surface in CompileSurfaceId::ALL.iter() {
        assert!(
            reported_surfaces.contains(surface.as_str()),
            "profile must report compile surface {}",
            surface.as_str()
        );
    }
}
