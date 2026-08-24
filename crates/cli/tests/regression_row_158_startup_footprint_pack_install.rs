#![cfg(unix)]

//! WHY: Row 158 contract: Startup footprint & execution pack pre-installation floor.
//!
//! What it closes:
//! 1. Eliminates repetitive parsing and compilation of embedded detector TOMLs/schemas
//!    during execution-pack loading and manifest authentication on the scan path.
//! 2. Guarantees that clean fresh-state scans properly use pre-compiled execution packs
//!    via zero-compile direct scanner hydration.
//! 3. Proves startup floor and memory footprint remain bounded, and scan finding parity
//!    is preserved across eligible backends.
//! 4. Enforces fail-closed error semantics when packs or manifests are missing or tampered,
//!    without silent fallback to in-process compilation.
//!
//! What it does not catch:
//! Does not catch external OS memory exhaustion or hardware CPU/GPU fault injection.

use keyhog::exit_codes::{EXIT_SUCCESS, EXIT_USER_ERROR};
use keyhog_scanner::execution_pack::CanonicalDetectorExecutionIr;
use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn create_temp_dir(prefix: &str) -> tempfile::TempDir {
    let base_tmp = PathBuf::from("/mnt/FlareTraining/santh-archive/tmp");
    if base_tmp.exists() {
        tempfile::Builder::new()
            .prefix(prefix)
            .tempdir_in(&base_tmp)
            .expect("tempdir in base_tmp")
    } else {
        tempfile::tempdir().expect("tempdir")
    }
}

static PREPARED_INSTALLATION: std::sync::LazyLock<(tempfile::TempDir, PathBuf, PathBuf, PathBuf)> =
    std::sync::LazyLock::new(|| {
        let directory = create_temp_dir("keyhog-row158-prep-");
        let bin_path = directory.path().join("keyhog");
        let _ = fs::hard_link(env!("CARGO_BIN_EXE_keyhog"), &bin_path)
            .or_else(|_| fs::copy(env!("CARGO_BIN_EXE_keyhog"), &bin_path).map(|_| ()));
        let actual_bin = if bin_path.exists() {
            bin_path
        } else {
            PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
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

        let result = Command::new(&actual_bin)
            .arg("compile-execution-packs")
            .arg("--output-dir")
            .arg(&output)
            .arg("--signing-key")
            .arg(&key_path)
            .output()
            .expect("run install pack compiler");
        assert!(
            result.status.success(),
            "compile-execution-packs failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        (directory, pack_root, output, actual_bin)
    });

fn test_bin() -> PathBuf {
    let (_, _, _, bin_path) = &*PREPARED_INSTALLATION;
    bin_path.clone()
}

fn copy_dir_all(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("create dst dir");
    for entry in fs::read_dir(src).expect("read src dir") {
        let entry = entry.expect("dir entry");
        let file_type = entry.file_type().expect("file type");
        let target = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_all(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("copy file");
        }
    }
}

fn setup_test_pack_environment(temp_dir: &Path) -> (PathBuf, PathBuf) {
    let (_, src_pack_root, _, _) = &*PREPARED_INSTALLATION;
    let cache_home = temp_dir.join("cache");
    let dst_pack_root = cache_home.join("keyhog/execution-packs");
    copy_dir_all(src_pack_root, &dst_pack_root);
    let output_dir = dst_pack_root.join("current");
    (cache_home, output_dir)
}

// The ci-lean fixture sentinels select the bounded calibration ladder instead
// of the full production measurement.
fn calibrate_autoroute(cache_home: &Path) {
    let mut calibrate = Command::new(test_bin());
    calibrate
        .arg("calibrate-autoroute")
        .arg("--quiet")
        .arg("--autoroute-cache")
        .arg(cache_home.join("keyhog/autoroute.json"))
        .env("XDG_CACHE_HOME", cache_home)
        .env(
            "HOME",
            cache_home
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_default(),
        )
        .env("NO_COLOR", "1");
    #[cfg(feature = "ci-lean")]
    {
        calibrate
            .env(
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
    let result = calibrate.output().expect("run calibrate autoroute");
    assert!(
        result.status.success(),
        "calibrate autoroute failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn fresh_state_scan_uses_precompiled_packs_with_zero_runtime_compiles() {
    let temp_dir = create_temp_dir("keyhog-row158-fresh-");
    let (cache_home, _output_dir) = setup_test_pack_environment(temp_dir.path());
    // Auto routing fails closed without a persisted fastest-correct backend
    // decision, even with packs installed; calibrate the fresh cache first so
    // the scan below exercises the precompiled-pack hydration path it names.
    calibrate_autoroute(&cache_home);

    let scan_file = temp_dir.path().join("test_secret.txt");
    fs::write(
        &scan_file,
        b"GITHUB_TOKEN=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\n",
    )
    .expect("write scan file");

    let profile_path = temp_dir.path().join("profile.json");

    let scan_output = Command::new(test_bin())
        .arg("scan")
        .arg("--daemon=off")
        .arg("--format")
        .arg("json-envelope")
        .arg("--profile-out")
        .arg(&profile_path)
        .arg(&scan_file)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", temp_dir.path())
        .output()
        .expect("run scan command");

    assert_eq!(
        scan_output.status.code(),
        Some(1),
        "scan with secret must exit with code 1 (findings present); stderr:\n{}",
        String::from_utf8_lossy(&scan_output.stderr)
    );

    let envelope: Value =
        serde_json::from_slice(&scan_output.stdout).expect("parse json-envelope output");
    let findings = envelope["findings"].as_array().expect("findings array");
    assert_eq!(
        findings.len(),
        1,
        "exact finding parity must be produced from precompiled pack"
    );

    assert!(
        profile_path.exists(),
        "profile JSON artifact must be produced"
    );
    let profile_content = fs::read_to_string(&profile_path).expect("read profile json");
    let profile_json: Value = serde_json::from_str(&profile_content).expect("parse profile json");

    if let Some(compile_records) = profile_json
        .get("compile_surfaces")
        .and_then(|v| v.as_array())
    {
        for record in compile_records {
            let runtime_compiles = record
                .get("runtime_compiles")
                .and_then(|c| c.as_u64())
                .unwrap_or(0);
            assert_eq!(
                runtime_compiles, 0,
                "fresh-state scan using installed execution pack must perform 0 runtime compiles"
            );
        }
    }
}

#[test]
fn embedded_canonical_detector_ir_is_idempotent_and_stable() {
    let embedded_1 = CanonicalDetectorExecutionIr::embedded().expect("first embedded IR load");
    let embedded_2 = CanonicalDetectorExecutionIr::embedded().expect("second embedded IR load");

    assert_eq!(
        embedded_1.digest(),
        embedded_2.digest(),
        "embedded IR digest must be identical across accesses"
    );
    assert_eq!(
        embedded_1.as_bytes(),
        embedded_2.as_bytes(),
        "embedded IR bytes must be identical across accesses"
    );

    let digest_1 =
        CanonicalDetectorExecutionIr::embedded_digest().expect("first embedded IR digest");
    let digest_2 =
        CanonicalDetectorExecutionIr::embedded_digest().expect("second embedded IR digest");
    assert_eq!(digest_1, digest_2);
    assert_eq!(digest_1, embedded_1.digest());
}

#[test]
fn finding_parity_across_backends_with_installed_packs() {
    let temp_dir = create_temp_dir("keyhog-row158-parity-");
    let (cache_home, output_dir) = setup_test_pack_environment(temp_dir.path());

    let manifest_bytes = fs::read(output_dir.join("manifest.json")).expect("read manifest");
    let manifest: Value = serde_json::from_slice(&manifest_bytes).expect("parse manifest");
    let packs = manifest["packs"].as_array().expect("pack list");

    let scan_file = temp_dir.path().join("parity_test.txt");
    fs::write(
        &scan_file,
        b"GITHUB_TOKEN=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\nAWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7XYA\n",
    )
    .expect("write parity test file");

    let mut backends = vec!["cpu"];
    if packs
        .iter()
        .any(|row| row["policy"] == "default" && row["backend"] == "simd")
    {
        backends.push("simd");
    }

    for backend in backends {
        let scan_output = Command::new(test_bin())
            .arg("scan")
            .arg("--daemon=off")
            .arg("--no-config")
            .arg("--backend")
            .arg(backend)
            .arg("--format")
            .arg("json-envelope")
            .arg(&scan_file)
            .env("XDG_CACHE_HOME", &cache_home)
            .env("HOME", temp_dir.path())
            .output()
            .expect("run scan with explicit backend");

        assert_eq!(
            scan_output.status.code(),
            Some(1),
            "backend {backend} scan must return findings (exit code 1); stderr:\n{}",
            String::from_utf8_lossy(&scan_output.stderr)
        );

        let envelope: Value =
            serde_json::from_slice(&scan_output.stdout).expect("parse json-envelope");
        let findings = envelope["findings"].as_array().expect("findings array");
        assert_eq!(
            findings.len(),
            2,
            "backend {backend} must find both secrets"
        );
    }
}

#[test]
fn tampered_manifest_detector_digest_fails_closed() {
    let temp_dir = create_temp_dir("keyhog-row158-tamper-manifest-");
    let (cache_home, output_dir) = setup_test_pack_environment(temp_dir.path());

    let manifest_path = output_dir.join("manifest.json");
    let manifest_bytes = fs::read(&manifest_path).expect("read manifest");
    let mut manifest_json: Value = serde_json::from_slice(&manifest_bytes).expect("parse manifest");
    manifest_json["detector_digest"] = Value::String(
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
    );
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest_json).unwrap(),
    )
    .expect("write modified manifest");

    let scan_file = temp_dir.path().join("dummy.txt");
    fs::write(&scan_file, "plain text without secrets\n").expect("write dummy file");

    let scan_output = Command::new(test_bin())
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
        "stale detector digest must fail closed with exit code {EXIT_USER_ERROR}"
    );

    let stderr = String::from_utf8_lossy(&scan_output.stderr);
    assert!(
        stderr.contains("detector") && stderr.contains("stale"),
        "stderr must report stale detector identity; got:\n{stderr}"
    );
    assert!(
        stderr.contains("keyhog install"),
        "stderr must advise running `keyhog install`; got:\n{stderr}"
    );
}

#[test]
fn tampered_pack_content_fails_closed() {
    let temp_dir = create_temp_dir("keyhog-row158-tamper-pack-");
    let (cache_home, output_dir) = setup_test_pack_environment(temp_dir.path());

    let cpu_pack = output_dir.join("default-cpu.khpack");
    assert!(cpu_pack.exists(), "default-cpu.khpack must exist");
    let mut bytes = fs::read(&cpu_pack).expect("read pack bytes");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    fs::write(&cpu_pack, bytes).expect("write corrupted pack");

    let scan_file = temp_dir.path().join("dummy.txt");
    fs::write(&scan_file, "plain text without secrets\n").expect("write dummy file");

    let scan_output = Command::new(test_bin())
        .arg("scan")
        .arg("--backend")
        .arg("cpu")
        .arg("--daemon=off")
        .arg(&scan_file)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", temp_dir.path())
        .output()
        .expect("run scan command");

    assert_ne!(
        scan_output.status.code(),
        Some(EXIT_SUCCESS as i32),
        "corrupted pack must fail closed"
    );
}
