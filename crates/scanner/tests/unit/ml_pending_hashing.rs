#![cfg(feature = "ml")]

use crate::context::CodeContext;
use crate::detector_ml_policy::ActiveMlMode;
use crate::engine::finalize_pending_match_for_test;
use crate::scan_state::{
    raw_match_materialization_count_for_test, reset_raw_match_materialization_count_for_test,
    MlPendingMatch, ScanState,
};
use crate::ScannerConfig;
use keyhog_core::{Chunk, ChunkMetadata, CompanionMap, Severity};
use std::sync::Arc;

const CREDENTIAL: &str = "kh-1229-emitted-secret-7F3kQ9mP";
const EXPECTED_SHA256: &str = "d53330c0e381c1aac0a115579cbd881b63a433f07b25002749d27f557104fd47";

fn pending_candidate(offset: usize, min_confidence_floor: f64) -> MlPendingMatch {
    pending_candidate_for_pattern(offset, min_confidence_floor, 0)
}

fn pending_candidate_for_pattern(
    offset: usize,
    min_confidence_floor: f64,
    pattern_index: u32,
) -> MlPendingMatch {
    let confidence = keyhog_core::detector_spec_by_id("datadog-api-key")
        .and_then(|detector| detector.match_confidence)
        .expect("embedded Datadog confidence policy");
    let mut companions = CompanionMap::new();
    companions.insert(Arc::from("account"), "tenant-42".to_string());
    let chunk = Chunk {
        data: CREDENTIAL.into(),
        metadata: ChunkMetadata {
            source_type: Arc::from("unit"),
            path: Some(Arc::from("src/production.env")),
            commit: Some(Arc::from("deadbeef")),
            ..ChunkMetadata::default()
        },
    };
    let mut state = ScanState::default();
    let pending_raw_match = crate::pipeline::build_pending_raw_match(
        Severity::High,
        (
            Arc::from("kh-1229-regression"),
            Arc::from("KH-1229 Regression"),
            Arc::from("test"),
        ),
        &chunk,
        CREDENTIAL,
        companions,
        offset,
        9,
        4.25,
        &mut state,
        crate::candidate_provenance::CandidateProvenance::named(0, pattern_index),
        false,
    );
    MlPendingMatch::detector_candidate(
        pending_raw_match,
        0.7,
        CodeContext::Assignment,
        1.0,
        None,
        confidence.post_match,
        [0.0; crate::ml_scorer::NUM_FEATURES],
        1.0,
        min_confidence_floor,
        true,
        false,
        false,
        false,
        crate::checksum::ChecksumConfidenceDecision::not_applicable(),
        ActiveMlMode::Authoritative,
    )
}
fn enqueue_pending(state: &mut ScanState, pending: MlPendingMatch) -> bool {
    let pending_raw_match = pending.pending_raw_match;
    state.push_detector_ml_pending(
        pending_raw_match,
        pending.heuristic_conf,
        pending.code_context,
        pending.context_multiplier,
        pending.context_suppression_threshold,
        pending.post_match,
        pending.ml_features,
        pending.ml_weight,
        pending.min_confidence_floor,
        pending.is_named_detector,
        pending.is_generic_detector,
        pending.allow_canonical_hex_key,
        pending.allow_encoded_text_lift,
        pending.checksum,
        pending.ml_mode,
    )
}

/// WHY: the pending index must key the full producer provenance. A/B/A at the
/// same public identity must deduplicate the repeated A without overwriting B.
#[test]
fn pending_index_retains_two_exact_provenance_identities_across_a_b_a() {
    let mut state = ScanState::default();
    assert!(enqueue_pending(
        &mut state,
        pending_candidate_for_pattern(11, 0.4, 0),
    ));
    assert!(enqueue_pending(
        &mut state,
        pending_candidate_for_pattern(11, 0.4, 1),
    ));
    assert!(!enqueue_pending(
        &mut state,
        pending_candidate_for_pattern(11, 0.4, 0),
    ));
    assert_eq!(state.ml_pending.len(), 2);
    assert_eq!(state.accepted_ml_events, 2);
}

/// Regression KH-1229: a positive final ML verdict must materialize exactly one
/// byte-identical finding and retain the historical lowercase SHA-256 wire value.
#[test]
fn emitted_candidate_materializes_once_with_compatible_hash_and_fields() {
    reset_raw_match_materialization_count_for_test();
    let pending = pending_candidate(73, 0.2);
    assert_eq!(
        raw_match_materialization_count_for_test(),
        0,
        "queue construction must not materialize or hash"
    );
    let finding = finalize_pending_match_for_test(&ScannerConfig::default(), pending, 0.95)
        .expect("positive final verdict must emit");

    assert_eq!(raw_match_materialization_count_for_test(), 1);
    assert_eq!(finding.credential.as_ref(), CREDENTIAL);
    assert_eq!(finding.location.offset, 73);
    assert_eq!(finding.location.line, Some(9));
    assert_eq!(finding.entropy, Some(4.25));
    assert_eq!(finding.confidence, Some(0.95));
    assert_eq!(
        finding.companions.get("account").map(String::as_str),
        Some("tenant-42")
    );
    assert_eq!(
        keyhog_core::hex_encode(&finding.credential_hash),
        EXPECTED_SHA256
    );

    let wire = serde_json::to_value(finding.to_redacted())
        .expect("RedactedFinding JSON serialization should succeed");
    assert_eq!(wire["credential_hash"], EXPECTED_SHA256);
}

/// Regression KH-1229: a candidate rejected by the final ML confidence floor
/// must leave the durable-match/hash construction counter untouched.
#[test]
fn rejected_candidate_never_materializes_or_hashes() {
    reset_raw_match_materialization_count_for_test();
    let finding = finalize_pending_match_for_test(
        &ScannerConfig::default(),
        pending_candidate(73, 0.99),
        0.01,
    );

    assert!(finding.is_none());
    assert_eq!(raw_match_materialization_count_for_test(), 0);
}

/// Regression KH-1229: a dense batch of ML-negative candidates previously paid
/// one SHA-256 and durable `RawMatch` construction apiece before all were dropped.
#[test]
fn dense_rejected_candidates_construct_no_durable_matches() {
    reset_raw_match_materialization_count_for_test();
    let config = ScannerConfig::default();
    let mut emitted = 0usize;
    for offset in 0..4096 {
        emitted += finalize_pending_match_for_test(&config, pending_candidate(offset, 0.99), 0.01)
            .is_some() as usize;
    }

    assert_eq!(emitted, 0);
    assert_eq!(raw_match_materialization_count_for_test(), 0);
}

/// WHY: the accelerator returns only an integer score; the shared CPU finalizer
/// must retain exact below/at/above floor semantics without a floating tolerance.
#[test]
fn quantized_scores_keep_every_registered_floor_in_the_shared_finalizer() {
    let config = ScannerConfig::default();
    let mut floor_bits = std::collections::BTreeSet::from([
        config.min_confidence.to_bits(),
        ScannerConfig::HIGH_PRECISION_MIN_CONFIDENCE.to_bits(),
    ]);
    floor_bits.extend(
        keyhog_core::embedded_detector_specs()
            .iter()
            .filter_map(|detector| detector.min_confidence)
            .map(f64::to_bits),
    );
    let pending_at = |offset, floor| {
        let mut pending = pending_candidate(offset, floor);
        pending.post_match = keyhog_core::DetectorPostMatchConfidenceSpec {
            placeholder_multiplier: 1.0,
            minimum_byte_diversity: 0.0,
            low_diversity_multiplier: 1.0,
            maximum_repeat_ratio: 1.0,
            degenerate_run_min_length: usize::MAX,
            degenerate_repeat_multiplier: 1.0,
            data_envelope_multiplier: None,
            fixture_path_multiplier: 1.0,
            ml_context_reapply_below: 0.0,
        };
        pending.is_named_detector = false;
        pending
    };

    for (index, floor) in floor_bits.into_iter().map(f64::from_bits).enumerate() {
        let scaled = floor * f64::from(u16::MAX);
        let ceiling = scaled.ceil() as u32;
        if ceiling > 0 {
            let below = crate::confidence::quantized::QuantizedScore((ceiling - 1) as u16).as_f64();
            assert!(below < floor);
            assert!(
                finalize_pending_match_for_test(&config, pending_at(index * 3 + 1, floor), below,)
                    .is_none(),
                "registered floor {floor} accepted the nearest quantized score below it"
            );
        }
        let at_floor =
            finalize_pending_match_for_test(&config, pending_at(index * 3 + 2, floor), floor)
                .unwrap_or_else(|| panic!("registered floor {floor} rejected an exact score"));
        assert_eq!(
            at_floor.confidence,
            Some(floor),
            "registered floor {floor} changed the emitted score"
        );
        let above_units = if scaled.fract() == 0.0 {
            ceiling.saturating_add(1)
        } else {
            ceiling
        };
        if above_units <= u32::from(u16::MAX) {
            let above = crate::confidence::quantized::QuantizedScore(above_units as u16).as_f64();
            assert!(above > floor);
            let emitted = finalize_pending_match_for_test(
                &config,
                pending_at(index * 3 + 3, floor),
                above,
            )
            .unwrap_or_else(|| {
                panic!("registered floor {floor} rejected the nearest quantized score above it")
            });
            let canonical = ((above * 1_000.0).round() / 1_000.0).max(floor);
            assert_eq!(
                emitted.confidence,
                Some(canonical),
                "registered floor {floor} changed the canonical emitted score"
            );
        }
    }
}
