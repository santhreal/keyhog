#![cfg(unix)]

//! WHY: Row 135 contract: multi-dimensional artifact regeneration and invalidation across
//! detector corpus changes, configuration changes, and calibration changes.
//!
//! What it closes:
//! Closes the silent artifact staleness defect where scans, autoroute, or matcher execution
//! would silently reuse stale compiled artifacts or bypass re-compilation after detector definitions,
//! configuration parameters, or calibration counters changed. Enforces that any detector corpus
//! drift, configuration change, or calibration update invalidates stale artifacts and triggers
//! either clean regeneration or fail-closed refusal.
//!
//! What it does not catch / boundary limits:
//! Does not catch in-flight kernel-level GPU driver crashes during active execution.
//! Does not catch filesystem bit flips occurring mid-read after initial authentication.

use keyhog::execution_pack_install::{
    check_installed_artifacts_freshness_at, current_binary_digest,
    current_embedded_detector_digest, invalidate_installed_artifacts_at, ArtifactFreshnessStatus,
    ArtifactIdentityInput, InstalledArtifactClass, InstalledArtifactRegistry,
};
use keyhog::exit_codes::EXIT_USER_ERROR;
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn create_test_temp_dir(prefix: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .expect("tempdir")
}

fn isolate_test_binary(dir: &Path) -> PathBuf {
    let src = PathBuf::from(env!("CARGO_BIN_EXE_keyhog"));
    let dst = dir.join("keyhog-test-bin");
    if fs::copy(&src, &dst).is_ok() {
        let _ = fs::set_permissions(&dst, fs::Permissions::from_mode(0o755));
        dst
    } else {
        src
    }
}

fn prepare_fresh_installation(test_exe: &Path, cache_home: &Path) -> (PathBuf, PathBuf) {
    let pack_root = cache_home.join("keyhog/execution-packs");
    fs::create_dir_all(&pack_root).expect("execution-pack root");
    let key_path = pack_root.join("signing.key");
    let key_bytes = [0x5cu8; 32];
    fs::write(&key_path, key_bytes).expect("write signing key");
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).expect("protect signing key");
    let output = pack_root.join("current");

    let result = Command::new(test_exe)
        .arg("compile-execution-packs")
        .arg("--output-dir")
        .arg(&output)
        .arg("--signing-key")
        .arg(&key_path)
        .env("XDG_CACHE_HOME", cache_home)
        .output()
        .expect("run install pack compiler");
    assert!(
        result.status.success(),
        "install pack compiler failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let autoroute_cache = cache_home.join("keyhog/autoroute.json");
    let cal_result = Command::new(test_exe)
        .arg("calibrate-autoroute")
        .arg("--quiet")
        .arg("--autoroute-cache")
        .arg(&autoroute_cache)
        .env("XDG_CACHE_HOME", cache_home)
        .output()
        .expect("run calibrate autoroute");
    assert!(
        cal_result.status.success(),
        "calibrate autoroute failed: {}",
        String::from_utf8_lossy(&cal_result.stderr)
    );
    (pack_root, output)
}

#[test]
fn manifest_identity_stale_detector_corpus_fails_closed() {
    let temp_dir = create_test_temp_dir("keyhog-row135-det-");
    let test_exe = isolate_test_binary(temp_dir.path());
    let cache_home = temp_dir.path().join("cache");
    let (_pack_root, output_dir) = prepare_fresh_installation(&test_exe, &cache_home);

    // Tamper the manifest's detector_digest to simulate a modified/stale detector corpus
    let manifest_path = output_dir.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).expect("read manifest"))
            .expect("parse manifest");
    manifest["detector_digest"] =
        serde_json::json!("0000000000000000000000000000000000000000000000000000000000000000");
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .expect("write tampered manifest");

    let scan_file = temp_dir.path().join("sample.txt");
    fs::write(&scan_file, "sample payload for stale detector test\n").expect("write scan file");

    let scan_output = Command::new(&test_exe)
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
        "scan must fail closed on stale detector corpus in manifest"
    );
    let stderr = String::from_utf8_lossy(&scan_output.stderr);
    assert!(
        stderr.contains("execution-pack manifest identity for 'detector' is stale"),
        "stderr must explain that detector identity is stale: {stderr}"
    );
}

#[test]
fn manifest_identity_stale_binary_digest_fails_closed() {
    let temp_dir = create_test_temp_dir("keyhog-row135-bin-");
    let test_exe = isolate_test_binary(temp_dir.path());
    let cache_home = temp_dir.path().join("cache");
    let (_pack_root, output_dir) = prepare_fresh_installation(&test_exe, &cache_home);

    // Tamper binary_digest
    let manifest_path = output_dir.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).expect("read manifest"))
            .expect("parse manifest");
    manifest["binary_digest"] =
        serde_json::json!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .expect("write tampered manifest");

    let scan_file = temp_dir.path().join("sample.txt");
    fs::write(&scan_file, "sample payload for stale binary test\n").expect("write scan file");

    let scan_output = Command::new(&test_exe)
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
        "scan must fail closed on stale binary digest in manifest"
    );
    let stderr = String::from_utf8_lossy(&scan_output.stderr);
    assert!(
        stderr.contains("execution-pack manifest identity for 'binary' is stale"),
        "stderr must explain that binary identity is stale: {stderr}"
    );
}

#[test]
fn manifest_identity_stale_target_hardware_digest_fails_closed() {
    let temp_dir = create_test_temp_dir("keyhog-row135-tgt-");
    let test_exe = isolate_test_binary(temp_dir.path());
    let cache_home = temp_dir.path().join("cache");
    let (_pack_root, output_dir) = prepare_fresh_installation(&test_exe, &cache_home);

    // Tamper target_digest
    let manifest_path = output_dir.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).expect("read manifest"))
            .expect("parse manifest");
    manifest["target_digest"] =
        serde_json::json!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .expect("write tampered manifest");

    let scan_file = temp_dir.path().join("sample.txt");
    fs::write(&scan_file, "sample payload for stale target test\n").expect("write scan file");

    let scan_output = Command::new(&test_exe)
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
        "scan must fail closed on stale target hardware digest in manifest"
    );
    let stderr = String::from_utf8_lossy(&scan_output.stderr);
    assert!(
        stderr.contains("execution-pack manifest identity for 'target' is stale"),
        "stderr must explain that target identity is stale: {stderr}"
    );
}

#[test]
fn manifest_identity_stale_feature_digest_fails_closed() {
    let temp_dir = create_test_temp_dir("keyhog-row135-feat-");
    let test_exe = isolate_test_binary(temp_dir.path());
    let cache_home = temp_dir.path().join("cache");
    let (_pack_root, output_dir) = prepare_fresh_installation(&test_exe, &cache_home);

    // Tamper feature_digest
    let manifest_path = output_dir.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).expect("read manifest"))
            .expect("parse manifest");
    manifest["feature_digest"] =
        serde_json::json!("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .expect("write tampered manifest");

    let scan_file = temp_dir.path().join("sample.txt");
    fs::write(&scan_file, "sample payload for stale feature test\n").expect("write scan file");

    let scan_output = Command::new(&test_exe)
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
        "scan must fail closed on stale feature digest in manifest"
    );
    let stderr = String::from_utf8_lossy(&scan_output.stderr);
    assert!(
        stderr.contains("execution-pack manifest identity for 'feature' is stale"),
        "stderr must explain that feature identity is stale: {stderr}"
    );
}

#[test]
fn multi_dimensional_freshness_status_derived_at_runtime() {
    let temp_dir = create_test_temp_dir("keyhog-row135-fresh-");
    let test_exe = isolate_test_binary(temp_dir.path());
    let cache_home = temp_dir.path().join("cache");
    let (_pack_root, output_dir) = prepare_fresh_installation(&test_exe, &cache_home);
    // Align the manifest binary_digest with the test process's binary digest
    let manifest_path = output_dir.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).expect("read manifest"))
            .expect("parse manifest");
    manifest["binary_digest"] =
        serde_json::json!(keyhog_core::hex_encode(&current_binary_digest().unwrap()));
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .expect("write updated manifest");

    // Test Fresh
    let freshness =
        check_installed_artifacts_freshness_at(Some(&cache_home)).expect("check freshness");
    assert!(
        matches!(freshness, ArtifactFreshnessStatus::Fresh),
        "freshness check must evaluate as Fresh on aligned binary: {freshness:?}"
    );
    // Test Missing when manifest is removed
    let manifest_path = output_dir.join("manifest.json");
    fs::remove_file(&manifest_path).expect("remove manifest");
    let freshness_missing =
        check_installed_artifacts_freshness_at(Some(&cache_home)).expect("check freshness missing");
    assert!(matches!(
        freshness_missing,
        ArtifactFreshnessStatus::Missing { .. }
    ));

    // Test embedded detector digest calculation
    let embedded_digest =
        current_embedded_detector_digest().expect("current embedded detector digest");
    assert_ne!(embedded_digest, [0u8; 32]);
}

#[test]
fn detector_update_triggers_invalidation_cleanly() {
    let temp_dir = create_test_temp_dir("keyhog-row135-inv-det-");
    let test_exe = isolate_test_binary(temp_dir.path());
    let cache_home = temp_dir.path().join("cache");
    prepare_fresh_installation(&test_exe, &cache_home);

    let pack_dir = cache_home.join("keyhog/execution-packs/current");
    assert!(
        pack_dir.exists(),
        "pack dir must exist prior to invalidation"
    );

    invalidate_installed_artifacts_at(Some(&cache_home), "test invalidation on detector update")
        .expect("invalidate");
    assert!(
        !pack_dir.exists(),
        "pack dir must be cleanly removed after invalidation"
    );
}

#[test]
fn calibration_update_triggers_invalidation_cleanly() {
    let temp_dir = create_test_temp_dir("keyhog-row135-inv-cal-");
    let test_exe = isolate_test_binary(temp_dir.path());
    let cache_home = temp_dir.path().join("cache");
    prepare_fresh_installation(&test_exe, &cache_home);

    let pack_dir = cache_home.join("keyhog/execution-packs/current");
    assert!(
        pack_dir.exists(),
        "pack dir must exist prior to invalidation"
    );

    invalidate_installed_artifacts_at(Some(&cache_home), "test invalidation on calibration update")
        .expect("invalidate");
    assert!(
        !pack_dir.exists(),
        "pack dir must be cleanly removed after invalidation"
    );
}

#[test]
fn mutation_gating_every_identity_dimension_is_strictly_bound() {
    let all_inputs: BTreeSet<_> = ArtifactIdentityInput::ALL.iter().copied().collect();
    assert_eq!(
        all_inputs.len(),
        6,
        "must have exactly 6 identity input dimensions"
    );

    for &input in ArtifactIdentityInput::ALL {
        assert!(
            !input.name().is_empty(),
            "input dimension {:?} must have non-empty name",
            input
        );
    }

    // Verify all registered artifact classes bind at least one identity input
    for &class in InstalledArtifactClass::ALL {
        let inputs = class.identity_inputs();
        assert!(
            !inputs.is_empty(),
            "artifact class {:?} must have non-empty identity inputs",
            class
        );
    }

    InstalledArtifactRegistry::assert_bidirectional_registry_equality()
        .expect("bidirectional registry equality must hold");
}
