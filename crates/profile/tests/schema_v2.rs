use keyhog_profile::{
    CacheLayerKindV2, CausalProfileV2, CoverageStateV2, Evidence, EvidenceGap, RunIdentity,
    RunState, Session, EVENT_SCHEMA_VERSION, EXPORTER_VERSION, METRIC_REGISTRY_VERSION,
    PROFILE_SCHEMA_V2, PROFILE_SCHEMA_V2_MAJOR, PROFILE_SCHEMA_V2_MINOR,
};

fn v1_profile() -> keyhog_profile::RunProfile {
    let mut identity = RunIdentity::new(
        "0.5.49",
        "detectors-a",
        "config-a",
        "filesystem",
        "tiny-text",
        "auto",
    );
    identity.backend_selected = Some("simd".to_owned());
    identity.scanner_threads = 8;
    identity.reader_threads = Some(3);
    Session::start(identity)
        .expect("start v1 migration profile")
        .finish(RunState::Completed)
}

fn assert_legacy_gap<T: std::fmt::Debug>(evidence: &Evidence<T>) {
    assert!(matches!(
        evidence,
        Evidence::Unavailable {
            reason: EvidenceGap::LegacyV1NotRecorded
        }
    ));
}

/// The v2 envelope must declare every schema family needed to interpret persisted evidence.
#[test]
fn v2_envelope_declares_schema_metric_event_exporter_and_producer_versions() {
    let v2 = CausalProfileV2::from_v1(v1_profile());
    assert_eq!(v2.envelope.schema, PROFILE_SCHEMA_V2);
    assert_eq!(v2.envelope.schema_version.major, PROFILE_SCHEMA_V2_MAJOR);
    assert_eq!(v2.envelope.schema_version.minor, PROFILE_SCHEMA_V2_MINOR);
    assert_eq!(v2.envelope.event_schema_version, EVENT_SCHEMA_VERSION);
    assert_eq!(v2.envelope.metric_registry_version, METRIC_REGISTRY_VERSION);
    assert_eq!(v2.envelope.producer.exporter_version, EXPORTER_VERSION);
    assert_eq!(
        v2.envelope.producer.profile_crate_version,
        env!("CARGO_PKG_VERSION")
    );
}

/// V1 migration must preserve every known identity and measurement without manufacturing missing evidence.
#[test]
fn v1_migration_preserves_known_values_and_types_unknown_values() {
    let v1 = v1_profile();
    let expected_run_id = v1.identity.run_id.clone();
    let expected_wall = v1.wall_time_ns;
    let expected_resources = v1.resources.clone();
    let v2 = CausalProfileV2::from_v1(v1);

    assert_eq!(v2.identity.run_id, expected_run_id);
    assert_eq!(v2.identity.build.binary_version, "0.5.49");
    assert_eq!(v2.identity.detectors.corpus_digest, "detectors-a");
    assert_eq!(v2.identity.config.resolved_config_digest, "config-a");
    assert_eq!(v2.identity.source.adapters, vec!["filesystem"]);
    assert_eq!(v2.identity.workload.class, "tiny-text");
    assert_eq!(v2.identity.scanner_threads_requested, 8);
    assert_eq!(v2.identity.reader_threads_requested, Evidence::recorded(3));
    assert_eq!(
        v2.identity.route.selected_backend,
        Evidence::recorded("simd".to_owned())
    );
    assert_eq!(v2.wall_time_ns, expected_wall);
    assert_eq!(v2.resources, expected_resources);
    assert_eq!(
        v2.identity.host.operating_system,
        Evidence::recorded(std::env::consts::OS.to_owned())
    );
    #[cfg(feature = "build-identity")]
    assert!(matches!(
        &v2.identity.build.binary_digest,
        Evidence::Recorded { value } if value.len() == 64
    ));
    #[cfg(not(feature = "build-identity"))]
    assert!(matches!(
        &v2.identity.build.binary_digest,
        Evidence::Unavailable {
            reason: EvidenceGap::CollectorDisabled
        }
    ));
    assert_legacy_gap(&v2.identity.detectors.compiled_plan_digest);
    assert_eq!(
        v2.identity.workload.container_bytes,
        Evidence::Unavailable {
            reason: EvidenceGap::Unavailable
        }
    );
    assert_eq!(
        v2.identity.workload.derived_decoder_bytes,
        Evidence::recorded(0)
    );
    assert_eq!(
        v2.identity.workload.backend_dispatched_bytes,
        Evidence::recorded(0)
    );
    assert_legacy_gap(&v2.identity.reader_threads_resolved);
}

/// A successful v1 status must not be relabeled as complete coverage because v1 never proved coverage.
#[test]
fn v1_migration_keeps_coverage_integrity_and_event_gaps_explicit() {
    let v2 = CausalProfileV2::from_v1(v1_profile());
    assert_eq!(v2.status, RunState::Completed);
    assert_eq!(v2.identity.outcome.status, RunState::Completed);
    assert_eq!(v2.identity.outcome.coverage, CoverageStateV2::Unknown);
    assert_legacy_gap(&v2.identity.outcome.error_count);
    assert_legacy_gap(&v2.identity.outcome.findings_digest);
    assert_legacy_gap(&v2.envelope.integrity);
    assert_legacy_gap(&v2.events.availability);
    assert_eq!(v2.events.dropped_events, 0);
    assert!(v2.events.spans.is_empty());
}

/// Collapsed v1 cache state must remain labeled as a legacy aggregate instead of claiming a specific cache layer.
#[test]
fn v1_migration_labels_collapsed_cache_state_as_legacy_aggregate() {
    let v2 = CausalProfileV2::from_v1(v1_profile());
    assert_eq!(v2.identity.caches.len(), 1);
    assert_eq!(
        v2.identity.caches[0].layer,
        CacheLayerKindV2::LegacyAggregate
    );
    assert_legacy_gap(&v2.identity.caches[0].generation);
    assert_legacy_gap(&v2.identity.caches[0].digest);
}

/// Recorded zero and unavailable evidence must remain distinct through JSON serialization.
#[test]
fn evidence_json_distinguishes_measured_zero_from_unavailable() {
    let measured = Evidence::recorded(0_u64);
    let unavailable: Evidence<u64> = Evidence::unavailable(EvidenceGap::PermissionDenied);
    let measured_json = serde_json::to_string(&measured).expect("serialize measured zero");
    let unavailable_json = serde_json::to_string(&unavailable).expect("serialize unavailable");
    assert_eq!(measured_json, r#"{"status":"recorded","value":0}"#);
    assert_eq!(
        unavailable_json,
        r#"{"status":"unavailable","reason":"permission-denied"}"#
    );
    assert_ne!(measured_json, unavailable_json);
}

/// The complete v2 artifact must preserve all typed evidence through a JSON round trip.
#[test]
fn causal_profile_v2_json_round_trip_preserves_all_evidence() {
    let expected = CausalProfileV2::from_v1(v1_profile());
    let json = serde_json::to_string_pretty(&expected).expect("serialize causal profile v2");
    let decoded: CausalProfileV2 =
        serde_json::from_str(&json).expect("deserialize causal profile v2");
    assert_eq!(decoded, expected);
}
