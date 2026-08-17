//! WHY THIS TEST EXISTS:
//! Row 68 / Compiled artifact class enumeration and identity totality contract:
//! Proves that all compiled artifact classes (GPU literal set, phase-2 GPU DFA catalog,
//! Hyperscan database, detector plan, execution pack, matcher artifact) are enumerated
//! from source at run time, each registers a compile owner, and cache directory auto-tightening
//! repairs loose default directory permissions.
//!
//! WHAT IT DOES NOT CATCH:
//! Dynamic kernel driver crashes during GPU execution.

use keyhog_core::{CompiledArtifactClass, CompiledArtifactIdentity};
use std::collections::BTreeSet;
use tempfile::TempDir;

#[test]
fn compiled_artifact_classes_are_enumerable_and_have_compile_owners() {
    let classes = CompiledArtifactClass::ALL;
    assert_eq!(
        classes.len(),
        6,
        "Exactly 6 compiled artifact classes must be registered in the workspace"
    );

    let mut seen_labels = BTreeSet::new();
    for class in classes {
        let label = class.label();
        assert!(!label.is_empty(), "Class label must not be empty");
        assert!(
            seen_labels.insert(label),
            "Duplicate compiled artifact label: {label}"
        );

        let owner = class.compile_owner();
        assert!(
            !owner.is_empty(),
            "Compiled artifact class {label} must declare a compile owner"
        );
        assert!(
            owner.starts_with("keyhog-scanner::"),
            "Compiled artifact class {label} compile owner must reside in keyhog-scanner"
        );
    }
}

#[test]
fn compiled_artifact_identity_round_trips_and_validates() {
    let identity = CompiledArtifactIdentity {
        artifact_class: CompiledArtifactClass::MatcherArtifact,
        binary_digest: "a".repeat(64),
        detector_digest: "b".repeat(64),
        config_digest: "c".repeat(64),
        platform: "linux-x86_64".to_string(),
        adapter_identity: Some("cuda-device-0".to_string()),
    };

    let serialized = serde_json::to_string(&identity).expect("serialize identity");
    let deserialized: CompiledArtifactIdentity =
        serde_json::from_str(&serialized).expect("deserialize identity");

    assert_eq!(identity, deserialized);
    assert_eq!(
        deserialized.artifact_class,
        CompiledArtifactClass::MatcherArtifact
    );
}

#[test]
fn default_matcher_cache_path_tightens_permissions_when_loose() {
    let temp = TempDir::new().expect("tempdir");
    let cache_dir = temp.path().join("keyhog-matcher-artifacts");
    std::fs::create_dir(&cache_dir).expect("create cache dir");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Set mode 775 (group-writable)
        std::fs::set_permissions(&cache_dir, std::fs::Permissions::from_mode(0o775))
            .expect("set mode 775");

        // Explicit validation should reject group-writable directory
        let explicit_err = keyhog_scanner::validate_matcher_artifact_cache_dir(&cache_dir);
        assert!(
            explicit_err.is_err(),
            "Explicit validation must refuse group-writable directory"
        );

        // Validation with auto_tighten should tighten to 700 and succeed
        let tighten_res =
            keyhog_scanner::validate_and_tighten_matcher_artifact_cache_dir(&cache_dir, true);
        assert!(
            tighten_res.is_ok(),
            "Auto-tightening validation must succeed on loose default directory"
        );

        let meta = std::fs::metadata(&cache_dir).expect("read metadata");
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o700,
            "Directory permissions must be tightened to 0700"
        );
    }
}
