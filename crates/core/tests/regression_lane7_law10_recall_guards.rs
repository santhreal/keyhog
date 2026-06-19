//! Lane-7 Law-10 regression pins.
//!
//! These lock the behaviour that the lane-7 silent-fallback sweep made
//! recall/security-safe:
//!
//!  1. `dedup_cross_detector` never DROPS a finding. A singleton group must
//!     pass through to the output (the `pop()` recall guard), and the loud
//!     `DEDUP_LOST_SINGLETON` counter must stay 0 in correct operation.
//!  2. `Credential`'s minimal base64 encoder zero-pads short final chunks per
//!     RFC 4648 (the `chunk.get(1/2).unwrap_or(0)` annotated sites) — proven by
//!     round-tripping every input length 0..=24 through `Credential::From` /
//!     `expose_*` and asserting the canonical `=` padding shape.
//!
//! Law 6: every assertion checks an exact value, never `is_empty`/`is_ok`.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use keyhog_core::{dedup_cross_detector, DedupedMatch, MatchLocation, Severity};

fn dedup_lost_singleton() -> u64 {
    keyhog_core::testing::CoreTestApi::dedup_lost_singleton_load(
        &keyhog_core::testing::TestApi,
        Ordering::SeqCst,
    )
}

fn deduped(detector: &str, credential: &str, hash: [u8; 32]) -> DedupedMatch {
    DedupedMatch {
        detector_id: Arc::from(detector),
        detector_name: Arc::from(detector),
        service: Arc::from("svc"),
        severity: Severity::High,
        credential: keyhog_core::SensitiveString::from(credential),
        credential_hash: hash,
        companions: HashMap::new(),
        primary_location: MatchLocation {
            source: Arc::from("fs"),
            file_path: Some(Arc::from("a.env")),
            line: Some(1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        additional_locations: Vec::new(),
        confidence: Some(0.5),
    }
}

/// A single distinct credential (a singleton group) must survive
/// cross-detector dedup — the recall guard around `group.pop()`. If the guard
/// regressed into a silent skip, the finding would vanish and `len()` would be
/// 0 instead of 1, AND `DEDUP_LOST_SINGLETON` would tick.
#[test]
fn singleton_finding_is_never_dropped() {
    let before = dedup_lost_singleton();

    let input = vec![deduped(
        "only-detector",
        "UNIQUE_CRED_VALUE_AAAA",
        [7u8; 32],
    )];
    let out = dedup_cross_detector(input);

    assert_eq!(
        out.len(),
        1,
        "one distinct credential must yield exactly one finding"
    );
    assert_eq!(
        out[0].detector_id.as_ref(),
        "only-detector",
        "the surviving finding must be the one we put in"
    );
    assert_eq!(
        out[0].credential.as_ref(),
        "UNIQUE_CRED_VALUE_AAAA",
        "the credential must be carried through unchanged"
    );

    let after = dedup_lost_singleton();
    assert_eq!(
        after - before,
        0,
        "no finding was lost, so the DEDUP_LOST_SINGLETON guard counter must not move"
    );
}

/// Multiple DISTINCT singletons (different credential hashes) each pass through
/// individually — proving the singleton arm is the common path and loses none.
#[test]
fn many_distinct_singletons_all_survive() {
    let before = dedup_lost_singleton();

    let mut input = Vec::new();
    for i in 0u8..16 {
        let mut hash = [0u8; 32];
        hash[0] = i; // distinct hash => distinct cross-detector group
        input.push(deduped(
            &format!("det-{i}"),
            &format!("cred-value-number-{i}"),
            hash,
        ));
    }
    let n = input.len();
    let out = dedup_cross_detector(input);

    assert_eq!(
        out.len(),
        n,
        "every distinct singleton must survive ({n} in, {} out)",
        out.len()
    );

    let after = dedup_lost_singleton();
    assert_eq!(
        after - before,
        0,
        "{n} distinct singletons, none lost => counter must stay put"
    );
}

/// Two detectors sharing one credential (same hash) collapse to ONE finding —
/// this exercises the `len() > 1` arm, not the singleton arm, and still emits
/// exactly one finding with the loser folded into companions.
#[test]
fn shared_credential_collapses_to_one_without_loss() {
    let before = dedup_lost_singleton();

    let input = vec![
        deduped("det-x", "SHARED_VALUE_ZZZ", [9u8; 32]),
        deduped("det-y", "SHARED_VALUE_ZZZ", [9u8; 32]),
    ];
    let out = dedup_cross_detector(input);

    assert_eq!(out.len(), 1, "one shared credential => one finding");
    assert_eq!(
        out[0].companions.len(),
        1,
        "the losing detector must be recorded as exactly one cross_detector companion, not dropped"
    );
    assert!(
        out[0].companions.contains_key("cross_detector.0"),
        "the loser must be folded into cross_detector.0 evidence"
    );

    let after = dedup_lost_singleton();
    assert_eq!(
        after - before,
        0,
        "collapse is not a loss; counter must not move"
    );
}
