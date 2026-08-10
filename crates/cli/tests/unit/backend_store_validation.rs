use super::*;
use crate::orchestrator::dispatch::backend::AUTOROUTE_CACHE_VERSION;

#[test]
fn gpu_artifact_identity_v57_round_trip_rejects_older_schema() {
    let old_json = r#"{
        "version": 56,
        "binary_version": "0.5.70",
        "git_hash": "abc",
        "executable_sha256": "def",
        "build_features": {"cli_features":[],"scanner_features":[],"sources_features":[],"verifier_features":[]},
        "detector_digest": 123,
        "rules_digest": "rules",
        "configs": []
    }"#;
    let parse_res = super::super::codec::parse_autoroute_cache(old_json.as_bytes());
    assert!(matches!(
        parse_res,
        Err(super::super::codec::CacheParseError::Version { found: 56 })
    ));

    let cache = AutorouteCache {
        version: AUTOROUTE_CACHE_VERSION,
        binary_version: "0.5.70".into(),
        git_hash: "abc".into(),
        executable_sha256: "def".into(),
        build_features: AutorouteBuildFeatures::default(),
        detector_digest: 123,
        rules_digest: "rules".into(),
        gpu_artifact_binding: Some(AutorouteGpuArtifactBinding::RuntimeCompiled {
            executable_sha256: "def".into(),
            rules_digest: "rules".into(),
        }),
        execution_pack_generation: None,
        configs: vec![],
    };
    let serialized = serde_json::to_string(&cache).expect("serialize v57 cache");
    let parsed = super::super::codec::parse_autoroute_cache(serialized.as_bytes())
        .unwrap_or_else(|e| panic!("parse v57 cache: {}", e.diagnostic()));
    assert_eq!(parsed.gpu_artifact_binding, cache.gpu_artifact_binding);
}

#[test]
fn gpu_artifact_identity_mutation_coverage() {
    let mut cache = AutorouteCache {
        version: AUTOROUTE_CACHE_VERSION,
        binary_version: "0.5.70".into(),
        git_hash: "test".into(),
        executable_sha256: "test-executable".into(),
        build_features: AutorouteBuildFeatures::default(),
        detector_digest: 0,
        rules_digest: "test-rules".into(),
        gpu_artifact_binding: Some(AutorouteGpuArtifactBinding::RuntimeCompiled {
            executable_sha256: "test-executable".into(),
            rules_digest: "test-rules".into(),
        }),
        execution_pack_generation: None,
        configs: vec![],
    };

    assert!(gpu_artifact_binding_matches(&cache, None));
    assert!(
        !gpu_artifact_binding_matches(&cache, Some("installed")),
        "installing a sidecar must invalidate runtime-compiled evidence"
    );

    cache.gpu_artifact_binding = Some(AutorouteGpuArtifactBinding::RuntimeCompiled {
        executable_sha256: "different-executable".into(),
        rules_digest: "test-rules".into(),
    });
    assert!(!gpu_artifact_binding_matches(&cache, None));

    cache.gpu_artifact_binding = Some(AutorouteGpuArtifactBinding::InstalledSidecar {
        sha256: "valid-sidecar".into(),
    });
    assert!(gpu_artifact_binding_matches(&cache, Some("valid-sidecar")));
    assert!(!gpu_artifact_binding_matches(
        &cache,
        Some("different-sidecar")
    ));
    assert!(!gpu_artifact_binding_matches(&cache, None));

    cache.gpu_artifact_binding = None;
    assert!(!gpu_artifact_binding_matches(&cache, None));
}

#[test]
fn trial_counts_and_round_pairing_mutations() {
    use crate::orchestrator::dispatch::backend::evidence::{
        paired_candidate_is_faster_95, BackendTimingEvidence, ColdWarmStatisticalModel,
    };

    let t1 = vec![100, 10, 10, 10, 10, 10, 10]; // 7 trials
    let t2 = vec![200, 20, 20, 20, 20]; // 5 trials (< 7 required for cold/warm model)
    let t3 = vec![200, 20, 20, 20, 20, 20, 20, 20]; // 8 trials (7 warm vs 6 warm)

    assert!(!paired_candidate_is_faster_95(&t1, &t2));

    let ev1 = BackendTimingEvidence::from_trial_ns(t1).unwrap();
    let ev2 = BackendTimingEvidence::from_trial_ns(t2).unwrap();
    let ev3 = BackendTimingEvidence::from_trial_ns(t3).unwrap();

    assert!(ColdWarmStatisticalModel::from_timing(&ev1).is_some());
    assert!(ColdWarmStatisticalModel::from_timing(&ev2).is_none());
    assert!(ColdWarmStatisticalModel::from_timing(&ev3).is_none());
}
