//! Contract for `simdsieve_prefilter::build_hot_pattern_validators`.
//!
//! The compiler builds one optional validator per loaded detector, in detector
//! order. A detector declaring `simdsieve_prefixes` must also declare at least
//! one regex pattern, and its validator is anchored at the candidate start.
//! Detectors without SIMD-sieve prefixes have no validator.

#![cfg(feature = "simdsieve")]

use keyhog_core::{DetectorSpec, PatternSpec};
use keyhog_scanner::testing::{
    hot_pattern_validator_is_some_for_test as slot_is_some,
    hot_pattern_validator_matches_for_test as slot_matches,
};

fn detector(id: &str, prefixes: &[&str], regexes: &[&str]) -> DetectorSpec {
    DetectorSpec {
        id: id.to_string(),
        simdsieve_prefixes: prefixes
            .iter()
            .map(|prefix| (*prefix).to_string())
            .collect(),
        patterns: regexes
            .iter()
            .map(|regex| PatternSpec {
                regex: (*regex).to_string(),
                ..Default::default()
            })
            .collect(),
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    }
}

#[test]
fn loaded_hot_detector_is_some_and_others_are_none() {
    let ds = vec![detector(
        "github-classic-pat",
        &["ghp_"],
        &["ghp_[A-Za-z0-9]{36}"],
    )];
    let is_some = slot_is_some(&ds).expect("validators build");
    assert_eq!(is_some, [true], "validator slots follow detector order");
}

#[test]
fn validator_is_anchored_at_the_candidate_start() {
    let ds = vec![detector(
        "github-classic-pat",
        &["ghp_"],
        &["ghp_[A-Za-z0-9]{36}"],
    )];
    let tok = format!("ghp_{}", "a".repeat(36));
    assert_eq!(
        slot_matches(&ds, 0, &tok).expect("builds"),
        Some(true),
        "the validator matches a valid token anchored at the start"
    );
    // The `^` anchor: a token that does NOT begin at offset 0 must be rejected.
    assert_eq!(
        slot_matches(&ds, 0, &format!("XX{tok}")).expect("builds"),
        Some(false),
        "the ^ anchor rejects a mid-string occurrence"
    );
    // A too-short body fails validation.
    assert_eq!(
        slot_matches(&ds, 0, "ghp_short").expect("builds"),
        Some(false)
    );
}

#[test]
fn no_hot_detector_loaded_yields_all_none() {
    let ds = vec![detector("not-a-hot-detector", &[], &["whatever[0-9]+"])];
    let is_some = slot_is_some(&ds).expect("builds");
    assert!(
        is_some.iter().all(|&b| !b),
        "no hot detector loaded => every slot is None (skipped, not synthesized)"
    );
}

#[test]
fn a_hot_detector_with_no_patterns_fails_closed() {
    let ds = vec![detector("github-classic-pat", &["ghp_"], &[])];
    let error = slot_is_some(&ds).expect_err("prefixes without patterns must fail");
    assert!(
        error.contains("declares simdsieve prefixes but has no regex patterns"),
        "unexpected error: {error}"
    );
}

#[test]
fn a_slot_index_out_of_range_matches_nothing() {
    let ds = vec![detector(
        "github-classic-pat",
        &["ghp_"],
        &["ghp_[A-Za-z0-9]{36}"],
    )];
    // Past the end of the slot vector => None (no panic).
    assert_eq!(
        slot_matches(&ds, usize::MAX, "anything").expect("builds"),
        None
    );
}
