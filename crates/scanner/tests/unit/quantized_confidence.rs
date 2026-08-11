use crate::confidence::quantized::*;
use sha2::{Digest, Sha256};

#[test]
fn embedded_model_round_trips_and_registry_covers_every_input_and_expert() {
    let parsed = QuantizedModel::parse(MODEL_BYTES).expect("embedded model");
    assert_eq!(FEATURE_NAMES.len(), crate::ml_scorer::model_arch::INPUT_DIM);
    assert_eq!(EXPERT_IDS.len(), crate::ml_scorer::model_arch::EXPERT_COUNT);
    assert_eq!(parsed.artifact_digest(), model_artifact_digest());
}

/// WHY: every registered feature row feeds the complete fixed-point model, so
/// model, feature-order, expert-count, or arithmetic drift changes this digest.
#[test]
fn generated_feature_union_matches_integer_golden() {
    let model = model().expect("embedded model");
    let mut rows = Vec::with_capacity(FEATURE_NAMES.len() + 2);
    rows.push(QuantizedFeatureRow(
        [0; crate::ml_scorer::model_arch::INPUT_DIM],
    ));
    rows.push(QuantizedFeatureRow(
        [SCALE as i16; crate::ml_scorer::model_arch::INPUT_DIM],
    ));
    for feature in 0..FEATURE_NAMES.len() {
        let mut row = [0i16; crate::ml_scorer::model_arch::INPUT_DIM];
        row[feature] = SCALE as i16;
        rows.push(QuantizedFeatureRow(row));
    }

    let mut score_hasher = Sha256::new();
    for row in &rows {
        score_hasher.update(model.score(row).0.to_le_bytes());
    }
    assert_eq!(
        keyhog_core::hex_encode(&score_hasher.finalize()),
        "b08ec5fd96a9018cf843c9c2dda1a88aa43c5f9f394b8ed15c2283a24255c7fa"
    );
}

/// WHY: parallel CPU batches retain the scalar model's exact row order and
/// fixed-point scores across every generated feature dimension.
#[test]
fn parallel_batch_matches_scalar_scores_in_input_order() {
    let model = model().expect("embedded model");
    let row_count = crate::ml_scorer::ML_PARALLEL_BATCH_THRESHOLD * 4;
    let rows: Vec<_> = (0..row_count)
        .map(|row_index| {
            let mut features = [0i16; crate::ml_scorer::model_arch::INPUT_DIM];
            for (feature_index, value) in features.iter_mut().enumerate() {
                *value = ((row_index * 17 + feature_index * 31) % (SCALE as usize + 1)) as i16;
            }
            QuantizedFeatureRow(features)
        })
        .collect();
    let expected: Vec<_> = rows.iter().map(|row| model.score(row)).collect();
    assert_eq!(score_batch(&rows).expect("parallel batch"), expected);
}

#[test]
fn corrupt_stale_or_noncanonical_artifacts_fail_closed() {
    for offset in [0usize, 8, 10, 12, 20, 22, 24, 28, 60, MODEL_BYTES.len() - 1] {
        let mut corrupt = MODEL_BYTES.to_vec();
        corrupt[offset] ^= 1;
        assert!(QuantizedModel::parse(&corrupt).is_err(), "offset {offset}");
    }
    assert!(QuantizedModel::parse(&MODEL_BYTES[..MODEL_BYTES.len() - 1]).is_err());
}

#[test]
fn empty_max_and_over_bound_batches_are_bounded() {
    assert!(score_batch(&[]).expect("empty batch").is_empty());
    let rows = vec![
        QuantizedFeatureRow([0; crate::ml_scorer::model_arch::INPUT_DIM]);
        MAX_CANDIDATES_PER_BATCH
    ];
    assert_eq!(
        score_batch(&rows).expect("maximum batch").len(),
        MAX_CANDIDATES_PER_BATCH
    );
    let over = vec![
        QuantizedFeatureRow([0; crate::ml_scorer::model_arch::INPUT_DIM]);
        MAX_CANDIDATES_PER_BATCH + 1
    ];
    assert!(matches!(
        score_batch(&over),
        Err(QuantizedConfidenceError::BatchTooLarge { .. })
    ));
}

#[test]
fn invalid_float_feature_domain_is_rejected_without_nan_abi() {
    for invalid in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -0.01] {
        let mut features = [0.0; crate::ml_scorer::model_arch::INPUT_DIM];
        features[17] = invalid;
        assert_eq!(
            QuantizedFeatureRow::from_float(&features),
            Err(QuantizedConfidenceError::InvalidFeature { index: 17 })
        );
    }
}

#[test]
fn malformed_utf8_and_empty_candidates_remain_cpu_owned() {
    for candidate in [
        &[][..],
        &[0xff][..],
        &[0xe2, 0x82][..],
        &[b'a', 0x80, b'b'][..],
    ] {
        assert_eq!(
            candidate_score_ownership(candidate),
            CandidateScoreOwnership::Cpu
        );
    }
    assert_eq!(
        candidate_score_ownership("token-\u{10ffff}".as_bytes()),
        CandidateScoreOwnership::Accelerated
    );
    let mut maximum = vec![b'a'; crate::types::MAX_SCAN_CHUNK_BYTES];
    assert_eq!(
        candidate_score_ownership(&maximum),
        CandidateScoreOwnership::Accelerated
    );
    maximum.push(b'a');
    assert_eq!(
        candidate_score_ownership(&maximum),
        CandidateScoreOwnership::Cpu
    );
}

#[test]
fn accelerated_output_rejects_failure_cardinality_and_order_without_fallback() {
    let failure = validate_accelerated_output(
        1,
        Err(QuantizedConfidenceError::BackendFailure(
            "injected device reset".into(),
        )),
    );
    assert!(matches!(
        failure,
        Err(QuantizedConfidenceError::BackendFailure(_))
    ));
    assert!(matches!(
        validate_accelerated_output(1, Ok(Vec::new())),
        Err(QuantizedConfidenceError::ScoreCardinality { .. })
    ));
    assert!(matches!(
        validate_accelerated_output(
            2,
            Ok(vec![
                AcceleratedCandidateScore {
                    candidate_id: 1,
                    score: QuantizedScore(1),
                },
                AcceleratedCandidateScore {
                    candidate_id: 0,
                    score: QuantizedScore(2),
                },
            ])
        ),
        Err(QuantizedConfidenceError::CandidateId { .. })
    ));
    assert_eq!(
        validate_accelerated_output(
            2,
            Ok(vec![
                AcceleratedCandidateScore {
                    candidate_id: 0,
                    score: QuantizedScore(1),
                },
                AcceleratedCandidateScore {
                    candidate_id: 1,
                    score: QuantizedScore(2),
                },
            ])
        )
        .expect("ordered scores"),
        vec![QuantizedScore(1), QuantizedScore(2)]
    );
}
