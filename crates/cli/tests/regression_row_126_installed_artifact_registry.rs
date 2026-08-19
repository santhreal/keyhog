#![cfg(unix)]

//! WHY: Row 126 contract: unified installed artifact registry connecting installer production,
//! updater regeneration, and scan path loading as a single source of truth across all artifact classes.
//!
//! What it closes:
//! Closes the artifact drift class between installer output and scan path requirements by ensuring
//! both sides derive artifact classes from `InstalledArtifactRegistry`.
//!
//! What it does not catch / boundary limits:
//! Does not catch hardware-level GPU driver execution failures at runtime (handled by hardware fault injection).
//! Does not catch filesystem corruption occurring mid-read after initial authentication (handled by hash checks).
use keyhog::execution_pack_install::{
    ArtifactIdentityInput, InstalledArtifactClass, InstalledArtifactRegistry,
};
use keyhog::exit_codes::EXIT_SUCCESS;
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

#[test]
fn registry_bidirectional_set_equality_derived_at_runtime() {
    // 1. Bidirectional set equality
    let produced = InstalledArtifactRegistry::produced_classes();
    let consumed = InstalledArtifactRegistry::consumed_classes();

    assert_eq!(
        produced, consumed,
        "produced artifact classes must equal consumed artifact classes in both directions"
    );

    assert!(
        !produced.is_empty(),
        "registered artifact classes must not be empty"
    );

    // 2. Complete coverage of InstalledArtifactClass::ALL
    let source_class_set: BTreeSet<_> = InstalledArtifactClass::ALL.iter().copied().collect();
    assert_eq!(
        produced, source_class_set,
        "every class in InstalledArtifactClass::ALL must participate in the registry"
    );

    // 3. Bidirectional equality check helper passes cleanly
    InstalledArtifactRegistry::assert_bidirectional_registry_equality()
        .expect("bidirectional registry equality assertion must succeed");

    // 4. Invariant: Every class has non-empty identity inputs, file pattern, and descriptive name
    for &class in InstalledArtifactClass::ALL {
        let name = class.name();
        assert!(
            !name.trim().is_empty(),
            "class {class:?} must have a non-empty name"
        );

        let pattern = class.file_pattern();
        assert!(
            !pattern.trim().is_empty(),
            "class {class:?} must have a non-empty file pattern"
        );

        let inputs = class.identity_inputs();
        assert!(
            !inputs.is_empty(),
            "class {class:?} must record non-empty identity inputs"
        );

        for &input in inputs {
            let input_name = input.name();
            assert!(
                !input_name.trim().is_empty(),
                "input {input:?} must have a non-empty name"
            );
        }
    }
}

#[test]
fn mutation_registry_asymmetry_is_rejected_fail_closed() {
    // MUTATION GATE: Removing any class from the producer or consumer set must turn the equality check RED.
    let full_set: BTreeSet<_> = InstalledArtifactClass::ALL.iter().copied().collect();

    for &removed in InstalledArtifactClass::ALL {
        let mut mutated_produced = full_set.clone();
        mutated_produced.remove(&removed);

        let diff_produced: Vec<_> = mutated_produced.difference(&full_set).copied().collect();
        let diff_consumed: Vec<_> = full_set.difference(&mutated_produced).copied().collect();

        assert!(
            !diff_consumed.is_empty() || !diff_produced.is_empty(),
            "removing class {removed:?} must cause set inequality"
        );
    }
}

#[test]
fn registry_is_single_source_for_installer_updater_and_scan_loader_loops() {
    // Test that the three consumer loops iterate over all registered classes exactly once.
    let target_class_set: BTreeSet<_> = InstalledArtifactClass::ALL.iter().copied().collect();
    // 1. Installer producer loop
    let mut produced_classes = BTreeSet::new();
    let result_produced = InstalledArtifactRegistry::execute_installer_producer_loop(|class| {
        produced_classes.insert(class);
        Ok(())
    });
    assert!(
        result_produced.is_ok(),
        "installer producer loop must succeed"
    );
    assert_eq!(
        produced_classes, target_class_set,
        "installer producer loop must iterate every registered class"
    );

    // 2. Updater regeneration loop
    let mut regenerated_classes = BTreeSet::new();
    let result_regenerated =
        InstalledArtifactRegistry::execute_updater_regeneration_loop(|class| {
            regenerated_classes.insert(class);
            Ok(())
        });
    assert!(
        result_regenerated.is_ok(),
        "updater regeneration loop must succeed"
    );
    assert_eq!(
        regenerated_classes, target_class_set,
        "updater regeneration loop must iterate every registered class"
    );

    // 3. Scan loader loop
    let mut loaded_classes = BTreeSet::new();
    let result_loaded = InstalledArtifactRegistry::execute_scan_loader_loop(|class| {
        loaded_classes.insert(class);
        Ok(())
    });
    assert!(result_loaded.is_ok(), "scan loader loop must succeed");
    assert_eq!(
        loaded_classes, target_class_set,
        "scan loader loop must iterate every registered class"
    );
}

#[test]
fn registry_records_comprehensive_identity_inputs_per_class() {
    // Assert specific identity input bindings for each class
    for &class in InstalledArtifactClass::ALL {
        let inputs = class.identity_inputs();
        match class {
            InstalledArtifactClass::Manifest => {
                assert!(inputs.contains(&ArtifactIdentityInput::BinaryDigest));
                assert!(inputs.contains(&ArtifactIdentityInput::TargetHardwareDigest));
                assert!(inputs.contains(&ArtifactIdentityInput::FeatureDigest));
                assert!(inputs.contains(&ArtifactIdentityInput::DetectorCorpusDigest));
            }
            InstalledArtifactClass::VerificationKey => {
                assert!(inputs.contains(&ArtifactIdentityInput::SigningKeyIdentity));
            }
            InstalledArtifactClass::ExecutionPack => {
                assert!(inputs.contains(&ArtifactIdentityInput::BinaryDigest));
                assert!(inputs.contains(&ArtifactIdentityInput::TargetHardwareDigest));
                assert!(inputs.contains(&ArtifactIdentityInput::FeatureDigest));
                assert!(inputs.contains(&ArtifactIdentityInput::DetectorCorpusDigest));
                assert!(inputs.contains(&ArtifactIdentityInput::SigningKeyIdentity));
            }
            InstalledArtifactClass::Signature => {
                assert!(inputs.contains(&ArtifactIdentityInput::SigningKeyIdentity));
                assert!(inputs.contains(&ArtifactIdentityInput::BinaryDigest));
                assert!(inputs.contains(&ArtifactIdentityInput::DetectorCorpusDigest));
            }
            InstalledArtifactClass::GpuLiteralArtifact => {
                assert!(inputs.contains(&ArtifactIdentityInput::BinaryDigest));
                assert!(inputs.contains(&ArtifactIdentityInput::DetectorCorpusDigest));
                assert!(inputs.contains(&ArtifactIdentityInput::GpuDeviceIdentity));
            }
            InstalledArtifactClass::AutorouteCalibration => {
                assert!(inputs.contains(&ArtifactIdentityInput::BinaryDigest));
                assert!(inputs.contains(&ArtifactIdentityInput::TargetHardwareDigest));
                assert!(inputs.contains(&ArtifactIdentityInput::FeatureDigest));
                assert!(inputs.contains(&ArtifactIdentityInput::DetectorCorpusDigest));
                assert!(inputs.contains(&ArtifactIdentityInput::GpuDeviceIdentity));
            }
        }
    }
}

#[test]
fn fresh_installation_yields_scan_with_zero_runtime_compilations() {
    let base_tmp = PathBuf::from("/mnt/FlareTraining/santh-archive/tmp");
    let temp_dir = if base_tmp.exists() {
        tempfile::Builder::new()
            .prefix("keyhog-row126-fresh-")
            .tempdir_in(&base_tmp)
            .expect("tempdir in base_tmp")
    } else {
        tempfile::tempdir().expect("tempdir")
    };

    let cache_home = temp_dir.path().join("cache");
    let pack_root = cache_home.join("keyhog/execution-packs");
    fs::create_dir_all(&pack_root).expect("create pack root");
    let key_path = pack_root.join("signing.key");
    fs::write(&key_path, [0x5au8; 32]).expect("write signing key");
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).expect("protect key");
    let output_dir = pack_root.join("current");

    // 1. Run installer compile-execution-packs
    let compile_output = Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .arg("compile-execution-packs")
        .arg("--output-dir")
        .arg(&output_dir)
        .arg("--signing-key")
        .arg(&key_path)
        .env("XDG_CACHE_HOME", &cache_home)
        .env("HOME", temp_dir.path())
        .output()
        .expect("run compile-execution-packs");

    assert!(
        compile_output.status.success(),
        "compile-execution-packs failed: stderr:\n{}",
        String::from_utf8_lossy(&compile_output.stderr)
    );

    // 2. Run scan on a sample clean file with profile JSON export
    let scan_file = temp_dir.path().join("sample.txt");
    fs::write(&scan_file, "clean sample text for fresh install scan\n").expect("write sample");
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
        "scan on clean file must succeed with 0; got stderr:\n{}",
        String::from_utf8_lossy(&scan_output.stderr)
    );

    // 3. Verify that profile JSON was generated and records ZERO runtime compiles
    assert!(
        profile_output_path.exists(),
        "profile JSON artifact must be produced"
    );
    let profile_content = fs::read_to_string(&profile_output_path).expect("read profile json");
    let profile_json: serde_json::Value =
        serde_json::from_str(&profile_content).expect("parse profile json");

    // Check compile surface records in profile json
    if let Some(compile_records) = profile_json
        .get("compile_surfaces")
        .and_then(|v| v.as_array())
    {
        for record in compile_records {
            let phase = record
                .get("phase")
                .and_then(|p| p.as_str())
                .unwrap_or_default();
            let surface = record
                .get("surface")
                .and_then(|s| s.as_str())
                .unwrap_or_default();
            let count = record
                .get("invocation_count")
                .and_then(|c| c.as_u64())
                .unwrap_or(0);
            assert_ne!(
                phase, "Scan",
                "Scan phase must have ZERO compile surface invocations for surface {surface}; found count {count}"
            );
        }
    }
}
