use keyhog_profile::{CoverageStateV2, Evidence, EvidenceGap, OutcomeIdentityV2, RunState};

/// A complete scan must bind its exit semantics and both result identities without manufacturing errors.
#[test]
fn completed_outcome_records_exit_findings_and_report_identity() {
    let outcome = OutcomeIdentityV2::recorded(
        RunState::Completed,
        CoverageStateV2::Complete,
        0,
        0,
        Evidence::recorded("findings-a".to_owned()),
        Evidence::recorded("report-a".to_owned()),
    );

    assert_eq!(outcome.status, RunState::Completed);
    assert_eq!(outcome.coverage, CoverageStateV2::Complete);
    assert_eq!(outcome.error_count, Evidence::recorded(0));
    assert_eq!(outcome.exit_code, Evidence::recorded(0));
    assert_eq!(
        outcome.findings_digest,
        Evidence::recorded("findings-a".to_owned())
    );
    assert_eq!(
        outcome.report_digest,
        Evidence::recorded("report-a".to_owned())
    );
}

/// Failed and interrupted runs must remain distinguishable from successful or merely partial coverage.
#[test]
fn failed_and_cancelled_coverage_states_remain_distinct() {
    let failed = OutcomeIdentityV2::recorded(
        RunState::Failed,
        CoverageStateV2::Failed,
        3,
        13,
        Evidence::recorded("failed-findings".to_owned()),
        Evidence::unavailable(EvidenceGap::Unavailable),
    );
    let cancelled = OutcomeIdentityV2::recorded(
        RunState::Failed,
        CoverageStateV2::Cancelled,
        1,
        130,
        Evidence::recorded("cancelled-findings".to_owned()),
        Evidence::unavailable(EvidenceGap::Unavailable),
    );

    assert_eq!(failed.coverage, CoverageStateV2::Failed);
    assert_eq!(failed.error_count, Evidence::recorded(3));
    assert_eq!(failed.exit_code, Evidence::recorded(13));
    assert_eq!(cancelled.coverage, CoverageStateV2::Cancelled);
    assert_eq!(cancelled.exit_code, Evidence::recorded(130));
    assert_ne!(failed, cancelled);
}

/// A report that was not materialized must preserve the reason instead of using an empty digest.
#[test]
fn unavailable_report_digest_survives_json_round_trip() {
    let outcome = OutcomeIdentityV2::recorded(
        RunState::Completed,
        CoverageStateV2::Partial,
        0,
        0,
        Evidence::recorded("findings".to_owned()),
        Evidence::unavailable(EvidenceGap::Unsupported),
    );
    let json = serde_json::to_vec(&outcome).expect("serialize outcome");
    let decoded: OutcomeIdentityV2 = serde_json::from_slice(&json).expect("deserialize outcome");

    assert_eq!(decoded, outcome);
    assert_eq!(
        decoded.report_digest,
        Evidence::Unavailable {
            reason: EvidenceGap::Unsupported
        }
    );
}
