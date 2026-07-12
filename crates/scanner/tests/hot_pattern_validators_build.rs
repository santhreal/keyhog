//! Contract for `simdsieve_prefilter::build_hot_pattern_validators` — the
//! compiler that builds one validator regex per SIMD-sieve hot pattern from the
//! loaded detector set. Previously untested directly.
//!
//! The SIMD sieve fast-marks candidates that begin with a hot literal (`ghp_`,
//! `AKIA`, …); each mark must then be VALIDATED by the full detector regex
//! before it becomes a finding. `build_hot_pattern_validators` produces those
//! validators, in the same slot order as `HOT_PATTERN_DETECTOR_IDS`, with a slot:
//!   * `Some(re)` when the corresponding canonical detector is loaded AND has
//!     patterns — `re` is the `^`-anchored alternation of the detector's regexes;
//!   * `None` when the detector is absent (operator did not compile it) or has no
//!     patterns — the hot path then skips the slot rather than emitting a
//!     synthetic finding for a disabled detector.
//! A wrong `None` on a loaded detector would silently drop it from the hot path;
//! a validator that is NOT anchored would over-validate mid-string noise.

#![cfg(feature = "simdsieve")]

use keyhog_core::{DetectorSpec, PatternSpec};
use keyhog_scanner::testing::{
    hot_pattern_detector_ids_for_test as hot_ids,
    hot_pattern_validator_is_some_for_test as slot_is_some,
    hot_pattern_validator_matches_for_test as slot_matches,
};

fn detector(id: &str, regexes: &[&str]) -> DetectorSpec {
    DetectorSpec {
        id: id.to_string(),
        patterns: regexes
            .iter()
            .map(|r| PatternSpec {
                regex: (*r).to_string(),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
}

fn github_slot() -> usize {
    hot_ids()
        .iter()
        .position(|&id| id == "github-classic-pat")
        .expect("github-classic-pat is a compiled-in hot pattern")
}

#[test]
fn loaded_hot_detector_is_some_and_others_are_none() {
    let ids = hot_ids();
    let gh = github_slot();
    let ds = vec![detector("github-classic-pat", &["ghp_[A-Za-z0-9]{36}"])];
    let is_some = slot_is_some(&ds).expect("validators build");
    assert_eq!(is_some.len(), ids.len(), "exactly one slot per hot pattern");
    assert!(is_some[gh], "the loaded hot detector gets a Some validator");
    assert_eq!(
        is_some.iter().filter(|&&b| b).count(),
        1,
        "only the single loaded hot detector is Some; every other slot is None"
    );
}

#[test]
fn validator_is_anchored_at_the_candidate_start() {
    let ds = vec![detector("github-classic-pat", &["ghp_[A-Za-z0-9]{36}"])];
    let gh = github_slot();
    let tok = format!("ghp_{}", "a".repeat(36));
    assert_eq!(
        slot_matches(&ds, gh, &tok).expect("builds"),
        Some(true),
        "the validator matches a valid token anchored at the start"
    );
    // The `^` anchor: a token that does NOT begin at offset 0 must be rejected.
    assert_eq!(
        slot_matches(&ds, gh, &format!("XX{tok}")).expect("builds"),
        Some(false),
        "the ^ anchor rejects a mid-string occurrence"
    );
    // A too-short body fails validation.
    assert_eq!(
        slot_matches(&ds, gh, "ghp_short").expect("builds"),
        Some(false)
    );
}

#[test]
fn no_hot_detector_loaded_yields_all_none() {
    let ds = vec![detector("not-a-hot-detector", &["whatever[0-9]+"])];
    let is_some = slot_is_some(&ds).expect("builds");
    assert!(
        is_some.iter().all(|&b| !b),
        "no hot detector loaded => every slot is None (skipped, not synthesized)"
    );
}

#[test]
fn a_hot_detector_with_no_patterns_is_none() {
    let gh = github_slot();
    let ds = vec![detector("github-classic-pat", &[])];
    assert!(
        !slot_is_some(&ds).expect("builds")[gh],
        "a pattern-less hot detector yields no validator"
    );
}

#[test]
fn a_slot_index_out_of_range_matches_nothing() {
    let ds = vec![detector("github-classic-pat", &["ghp_[A-Za-z0-9]{36}"])];
    // Past the end of the slot vector => None (no panic).
    assert_eq!(
        slot_matches(&ds, usize::MAX, "anything").expect("builds"),
        None
    );
}
