//! Workflow-state classification and accounting unit tests. Each test locks
//! out a specific mislabeling regression: cache transitions must come from
//! the exact load evidence (never timing guesses), verification aggregates
//! must tally real outcome variants, and partition records must stay bounded
//! with explicit loss.

use super::super::workflow_state::*;
use keyhog_core::MerkleLoadStatus;
use std::path::PathBuf;

fn status_missing() -> MerkleLoadStatus {
    MerkleLoadStatus::Missing {
        path: PathBuf::from("/tmp/cache.json"),
    }
}

/// WHY: the profile must distinguish a run that rebuilt its incremental
/// cache from one that reused it; mislabeling either direction makes
/// before/after perf comparisons meaningless.
#[test]
fn merkle_load_transition_maps_every_status_to_exact_evidence() {
    use keyhog_profile::CacheLayerKindV2;

    let disabled = merkle_load_transition(None);
    assert_eq!(disabled.layer, CacheLayerKindV2::Merkle);
    assert_eq!(disabled.evidence, "merkle-not-configured");
    assert_eq!(disabled.transition, CacheTransition::Disabled);

    let missing = merkle_load_transition(Some(&status_missing()));
    assert_eq!(missing.evidence, "merkle-load-missing");
    assert_eq!(missing.transition, CacheTransition::ColdStart);

    let loaded = merkle_load_transition(Some(&MerkleLoadStatus::Loaded {
        path: PathBuf::from("/tmp/cache.json"),
        entries: 17,
    }));
    assert_eq!(loaded.evidence, "merkle-load-ok");
    assert_eq!(loaded.transition, CacheTransition::WarmLoad);

    // Every failure variant has full load evidence and rebuilds the cache,
    // so each must classify cold-start with its own evidence name.
    let failures = [
        (
            MerkleLoadStatus::ReadFailed {
                path: PathBuf::from("/tmp/cache.json"),
                error: "io".into(),
            },
            "merkle-load-read-failed",
        ),
        (
            MerkleLoadStatus::ParseFailed {
                path: PathBuf::from("/tmp/cache.json"),
                error: "json".into(),
            },
            "merkle-load-parse-failed",
        ),
        (
            MerkleLoadStatus::SchemaMismatch {
                path: PathBuf::from("/tmp/cache.json"),
                version: 1,
                expected: 2,
            },
            "merkle-load-schema-mismatch",
        ),
        (
            MerkleLoadStatus::SpecChanged {
                path: PathBuf::from("/tmp/cache.json"),
            },
            "merkle-load-spec-changed",
        ),
        (
            MerkleLoadStatus::InvalidEntryHash {
                path: PathBuf::from("/tmp/cache.json"),
                entry_path: "src/a.rs".into(),
                hash: "zz".into(),
            },
            "merkle-load-invalid-entry-hash",
        ),
    ];
    for (status, evidence) in failures {
        let record = merkle_load_transition(Some(&status));
        assert_eq!(record.evidence, evidence);
        assert_eq!(
            record.transition,
            CacheTransition::ColdStart,
            "{evidence} must cold-start: the cache is rebuilt, never `unknown`"
        );
    }
}

/// WHY: a warm load is only a steady-state repeat when the loaded generation
/// served the whole run; misreading a partial rescan as steady-state would
/// hide real scanning cost from cache-warm benchmarks.
#[test]
fn merkle_warmth_refinement_requires_zero_rescans_and_a_real_skip() {
    assert_eq!(
        refine_merkle_warmth(CacheTransition::WarmLoad, 3, 0),
        CacheTransition::SteadyState
    );
    for (skipped, scanned) in [(0_u64, 0_u64), (0, 2), (3, 1)] {
        assert_eq!(
            refine_merkle_warmth(CacheTransition::WarmLoad, skipped, scanned),
            CacheTransition::WarmLoad,
            "skipped={skipped} scanned={scanned} must stay a warm load"
        );
    }
    // Non-warm transitions pass through untouched.
    assert_eq!(
        refine_merkle_warmth(CacheTransition::ColdStart, 5, 0),
        CacheTransition::ColdStart
    );
    assert_eq!(
        refine_merkle_warmth(CacheTransition::Disabled, 5, 0),
        CacheTransition::Disabled
    );
}

/// WHY: autoroute decision reuse is a real cache layer; the transition must
/// follow the persisted decision file, not a guess.
#[test]
fn autoroute_transition_tracks_persisted_decision_presence() {
    let unconfigured = autoroute_transition(None);
    assert_eq!(unconfigured.transition, CacheTransition::Disabled);

    let dir = tempfile::TempDir::new().expect("tempdir");
    let present = dir.path().join("autoroute.json");
    std::fs::write(&present, b"{}").expect("write decision cache");
    let warm = autoroute_transition(Some(present.as_path()));
    assert_eq!(warm.evidence, "autoroute-decision-cache-present");
    assert_eq!(warm.transition, CacheTransition::WarmLoad);

    let absent = dir.path().join("missing.json");
    let cold = autoroute_transition(Some(absent.as_path()));
    assert_eq!(cold.evidence, "autoroute-decision-cache-absent");
    assert_eq!(cold.transition, CacheTransition::ColdStart);
}

/// WHY: the verifier cache starts empty in every one-shot process; only
/// recorded hit spans may warm it, or "warm" would be an unverifiable claim.
#[test]
fn verifier_transition_warms_only_on_recorded_hits() {
    let disabled = verifier_transition(false, 0);
    assert_eq!(disabled.evidence, "verifier-policy-disabled");
    assert_eq!(disabled.transition, CacheTransition::Disabled);

    let cold = verifier_transition(true, 0);
    assert_eq!(cold.evidence, "verifier-cache-empty-at-process-start");
    assert_eq!(cold.transition, CacheTransition::ColdStart);

    let warm = verifier_transition(true, 2);
    assert_eq!(warm.evidence, "verifier-cache-hit-spans");
    assert_eq!(warm.transition, CacheTransition::WarmLoad);
}

/// WHY: the verification aggregate is how operators read whether results
/// came from the network, the cache, or neither; every outcome variant must
/// land in exactly one bucket.
#[test]
fn verification_aggregate_buckets_every_outcome_variant() {
    use keyhog_core::VerificationResult;

    let results = [
        VerificationResult::Live,
        VerificationResult::Revoked,
        VerificationResult::Dead,
        VerificationResult::RateLimited,
        VerificationResult::Error("timeout".into()),
        VerificationResult::Unverifiable,
        VerificationResult::Skipped,
    ];
    let aggregate = aggregate_verification_results(true, results.iter());
    assert_eq!(aggregate.queued, 6);
    assert_eq!(aggregate.network, 5);
    assert_eq!(aggregate.cached, 0);
    assert_eq!(aggregate.unverifiable, 1);
    assert_eq!(aggregate.skipped, 1);
    assert_eq!(aggregate.state_label(), "network");

    let disabled = aggregate_verification_results(false, results.iter());
    assert_eq!(disabled.queued, 0);
    assert_eq!(disabled.network, 0);
    assert_eq!(disabled.skipped, 7);
    assert_eq!(disabled.state_label(), "disabled");
}

/// WHY: the state label precedence decides what an operator sees first; a
/// cache-served run must read `cached`, never be drowned by `queued`.
#[test]
fn verification_state_label_precedence_is_exact() {
    fn label(enabled: bool, queued: u64, network: u64, cached: u64) -> &'static str {
        VerificationAggregate {
            enabled,
            queued,
            network,
            cached,
            unverifiable: 0,
            skipped: 0,
        }
        .state_label()
    }

    assert_eq!(label(false, 0, 0, 0), "disabled");
    assert_eq!(label(false, 3, 3, 0), "disabled");
    assert_eq!(label(true, 0, 0, 0), "idle");
    assert_eq!(label(true, 2, 0, 0), "queued");
    assert_eq!(label(true, 2, 2, 0), "network");
    assert_eq!(label(true, 2, 0, 2), "cached");
    assert_eq!(label(true, 3, 1, 2), "mixed");
}

/// WHY: Merkle unchanged checks and verifier cache hits share the
/// IncrementalLookup stage; only causal ancestry under LiveVerification may
/// count as a verifier hit, or incremental scans would fake verifier warmth.
#[test]
fn verifier_cache_hits_count_only_lookup_spans_under_live_verification() {
    let identity = keyhog_profile::RunIdentity::new(
        "test",
        "detectors",
        "config",
        "filesystem",
        "filesystem",
        "cpu-fallback",
    );
    let session = keyhog_profile::Session::start(identity).expect("start session");
    let runtime = session.runtime();
    {
        let _context = runtime.enter();
        // A verifier cache hit: lookup nested inside live verification.
        let verification = keyhog_profile::span(keyhog_profile::Stage::LiveVerification);
        let hit = keyhog_profile::span(keyhog_profile::Stage::IncrementalLookup);
        drop(hit);
        drop(verification);
        // A Merkle unchanged check: same stage, no verification ancestor.
        let merkle_lookup = keyhog_profile::span(keyhog_profile::Stage::IncrementalLookup);
        drop(merkle_lookup);
    }
    let (spans, dropped) = runtime.take_session_span_records();
    assert_eq!(dropped, 0, "three spans must fit bounded storage");
    assert_eq!(spans.len(), 3);
    assert_eq!(count_verifier_cache_hits(&spans), 1);
    session.finish(keyhog_profile::RunState::Completed);
}

/// WHY: partition records back the per-source sum proof in the profile; the
/// bound must drop loudly (counted) rather than corrupt the sum silently.
#[test]
fn partition_sink_is_bounded_with_explicit_loss() {
    static PARTITION_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = PARTITION_TEST_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());

    reset_workflow_state();
    record_source_partition("filesystem", 3, 120);
    record_source_partition("git", 2, 44);
    let (records, dropped) = take_source_partitions();
    assert_eq!(dropped, 0);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].index, 0);
    assert_eq!(records[0].kind, "filesystem");
    assert_eq!(records[0].units, 3);
    assert_eq!(records[0].bytes, 120);
    assert_eq!(records[1].index, 1);
    assert_eq!(records[1].kind, "git");
    // A take drains the sink: a second take must see nothing.
    let (empty, dropped_again) = take_source_partitions();
    assert!(empty.is_empty());
    assert_eq!(dropped_again, 0);

    reset_workflow_state();
    for unit in 0..(MAX_RECORDED_PARTITIONS + 5) {
        record_source_partition("filesystem", unit as u64, 0);
    }
    let (capped, dropped) = take_source_partitions();
    assert_eq!(capped.len(), MAX_RECORDED_PARTITIONS);
    assert_eq!(dropped, 5, "over-cap records must be counted, never silent");
    reset_workflow_state();
}

/// WHY: daemon generation is parsed out of server-assigned request ids for
/// the operator surface; a bad parse must degrade to explicit unavailability
/// instead of panicking or inventing a generation.
#[test]
fn daemon_request_identity_parses_generation_and_sequence() {
    let identity = parse_daemon_request_identity(
        "4242-after-0000000000000000000018d4d3f2a1b0-0000000000000003-0000000000000007",
    )
    .expect("well-formed request id");
    assert_eq!(
        identity.generation,
        "4242-after-0000000000000000000018d4d3f2a1b0-0000000000000003"
    );
    assert_eq!(identity.sequence, 7);

    for malformed in [
        "noseparator",
        "-0000000000000007",
        "gen-",
        "gen-7",
        "gen-000000000000000zz",
    ] {
        assert_eq!(
            parse_daemon_request_identity(malformed),
            None,
            "{malformed} must not parse"
        );
    }
}

/// WHY: every registered CacheKind in keyhog_core must be represented in the profile
/// cache transition ledger so that newly registered caches cannot silently omit transition reporting.
///
/// What it does not catch: caches outside the registered CacheKind enum.
#[test]
fn cache_transition_layer_set_covers_every_registered_cache_kind() {
    use keyhog_core::CacheKind;
    use keyhog_profile::CacheLayerKindV2;

    // Dynamically derive layer mappings from all registered cache kinds
    for kind in CacheKind::ALL {
        let layer = match kind {
            CacheKind::HyperscanShards => CacheLayerKindV2::HyperscanShards,
            CacheKind::DetectorPlans => CacheLayerKindV2::Detector,
            CacheKind::GpuPrograms => CacheLayerKindV2::GpuPrograms,
            CacheKind::MatcherArtifacts => CacheLayerKindV2::MatcherArtifacts,
            CacheKind::LockFiles => CacheLayerKindV2::LockFiles,
        };
        let record = match kind {
            CacheKind::HyperscanShards => hyperscan_shard_transition(None, 0, 0),
            CacheKind::DetectorPlans => detector_transition(),
            CacheKind::GpuPrograms => gpu_program_transition(0, 0),
            CacheKind::MatcherArtifacts => matcher_artifact_transition(None),
            CacheKind::LockFiles => lock_file_transition(),
        };
        assert_eq!(
            record.layer, layer,
            "CacheKind {kind:?} must map to layer {layer:?}"
        );
    }
}

/// WHY: in-process compilation and execution-pack mapping must be represented by
/// distinct profile stages (ScannerCompile vs ExecutionPackMap) so that a run that
/// compiled in process cannot be mistaken for a warm pack load.
///
/// What it does not catch: stages outside scanner materialization.
#[test]
fn stage_identity_distinguishes_mapping_from_compiling() {
    use keyhog_profile::{MetricId, Stage};

    assert_ne!(
        Stage::ExecutionPackMap,
        Stage::ScannerCompile,
        "ExecutionPackMap and ScannerCompile must be distinct stages"
    );
    assert_ne!(
        Stage::ExecutionPackMap.metric_id(),
        Stage::ScannerCompile.metric_id(),
        "ExecutionPackMap and ScannerCompile must have distinct metric IDs"
    );
    assert_eq!(
        Stage::ExecutionPackMap.metric_id(),
        MetricId::ExecutionPackMap
    );
    assert_eq!(Stage::ScannerCompile.metric_id(), MetricId::ScannerCompile);
    assert_eq!(Stage::ExecutionPackMap.as_str(), "execution-pack-map");
    assert_eq!(Stage::ScannerCompile.as_str(), "scanner-compile");
}
