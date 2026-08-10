use super::*;
use crate::orchestrator::dispatch::backend::AUTOROUTE_CACHE_VERSION;

#[test]
fn v52_serialized_cache_rejected_and_v53_round_trip_preserves_identities() {
    let v52_json = r#"{
        "version": 52,
        "binary_version": "0.5.68",
        "git_hash": "abc",
        "executable_sha256": "def",
        "build_features": {"cli_features":[],"scanner_features":[],"sources_features":[],"verifier_features":[]},
        "detector_digest": 123,
        "rules_digest": "rules",
        "configs": []
    }"#;
    let parse_res = super::super::codec::parse_autoroute_cache(v52_json.as_bytes());
    assert!(matches!(
        parse_res,
        Err(super::super::codec::CacheParseError::Version { found: 52 })
    ));

    let v53_cache = AutorouteCache {
        version: AUTOROUTE_CACHE_VERSION,
        binary_version: "0.5.68".into(),
        git_hash: "abc".into(),
        executable_sha256: "def".into(),
        build_features: AutorouteBuildFeatures::default(),
        detector_digest: 123,
        rules_digest: "rules".into(),
        gpu_sidecar_digest: Some("sidecar_digest_val".into()),
        execution_pack_generation: None,
        configs: vec![],
    };
    let serialized = serde_json::to_string(&v53_cache).expect("serialize v53 cache");
    let parsed = super::super::codec::parse_autoroute_cache(serialized.as_bytes())
        .unwrap_or_else(|e| panic!("parse v53 cache: {}", e.diagnostic()));
    assert_eq!(parsed.gpu_sidecar_digest, Some("sidecar_digest_val".into()));
}

#[test]
fn gpu_artifact_identity_mutation_coverage() {
    let mut cache = AutorouteCache {
        version: AUTOROUTE_CACHE_VERSION,
        binary_version: "0.5.68".into(),
        git_hash: "test".into(),
        executable_sha256: "test".into(),
        build_features: AutorouteBuildFeatures::default(),
        detector_digest: 0,
        rules_digest: "test".into(),
        gpu_sidecar_digest: Some("valid_sidecar".into()),
        execution_pack_generation: None,
        configs: vec![],
    };

    // Removing gpu_sidecar_digest independently -> rejected for GPU decision
    cache.gpu_sidecar_digest = None;
    assert!(!gpu_artifact_identity_matches(&cache));

    // Any identity other than the verified installed set is rejected.
    cache.gpu_sidecar_digest = Some("invalid_sidecar".into());
    assert!(!gpu_artifact_identity_matches(&cache));
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
