//! Gap test: `resolution::match_priority` weights are all named constants.
//!
//! Every priority component in `match_priority` already used a named weight
//! (`NAMED_DETECTOR_PRIORITY`, `CONFIDENCE_WEIGHT`, and
//! `CREDENTIAL_LENGTH_WEIGHT`) except the known-prefix / service-anchored bonus,
//! which was a bare `priority += 5.0;` magic literal. It is now
//! `KNOWN_PREFIX_SERVICE_BONUS: f64 = 5.0`.
//!
//! Pinned behaviorally, not by source shape: two matches that are IDENTICAL in
//! detector_id, confidence, and credential length, differing only in whether
//! the credential carries a known prefix, differ in priority by EXACTLY the
//! bonus, because every other weighted term cancels in the difference. The
//! second pair pins the `&&` guard: with a *generic* detector the bonus must
//! not fire even when the credential has a known prefix.

use keyhog_scanner::testing::match_priority_for_test;

const EPSILON: f64 = 1e-9;

// AKIA is a known AWS access-key prefix; the body is random alnum so it trips
// no placeholder / degenerate-repeat suppression in `known_prefix_confidence_floor`.
const KNOWN_PREFIX_CRED: &str = "AKIArxq7n2mk4p8w"; // 16 bytes, prefix "AKIA"
const NO_PREFIX_CRED: &str = "Wprxq7n2mk4p8w01"; // 16 bytes, no known prefix
const CONF: Option<f64> = Some(0.5);

#[test]
fn service_anchored_known_prefix_adds_exactly_the_named_bonus() {
    // Same service-anchored detector, same confidence, same credential length:
    // the ONLY differing input is the known prefix, so the priority delta is
    // exactly KNOWN_PREFIX_SERVICE_BONUS (5.0).
    let with_prefix = match_priority_for_test("aws-access-key", KNOWN_PREFIX_CRED, CONF);
    let without_prefix = match_priority_for_test("aws-access-key", NO_PREFIX_CRED, CONF);

    assert!(
        with_prefix > without_prefix,
        "known-prefix service-anchored match must outrank its prefixless twin: \
         {with_prefix} vs {without_prefix}"
    );
    let delta = with_prefix - without_prefix;
    assert!(
        (delta - 5.0).abs() < EPSILON,
        "the known-prefix bonus must equal the named KNOWN_PREFIX_SERVICE_BONUS (5.0); got {delta}"
    );
}

#[test]
fn generic_detector_does_not_receive_the_known_prefix_bonus() {
    // A generic detector is NOT service-anchored, so the bonus's `&&` guard
    // fails and the known prefix must add nothing: the delta is exactly 0.
    let with_prefix = match_priority_for_test("generic-password", KNOWN_PREFIX_CRED, CONF);
    let without_prefix = match_priority_for_test("generic-password", NO_PREFIX_CRED, CONF);

    let delta = with_prefix - without_prefix;
    assert!(
        delta.abs() < EPSILON,
        "generic (non-service-anchored) detector must not receive the bonus; got delta {delta}"
    );
}

#[test]
fn detector_id_spelling_does_not_change_priority() {
    let short = match_priority_for_test("vendor-a", NO_PREFIX_CRED, CONF);
    let long = match_priority_for_test(
        "vendor-a-much-longer-reporting-identifier",
        NO_PREFIX_CRED,
        CONF,
    );
    assert!(
        (short - long).abs() < EPSILON,
        "detector-id length is not evidence of match specificity: {short} vs {long}"
    );
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin the bonus at one confidence; these SWEEP it. Every
// weighted term besides the known-prefix bonus is a function of detector_id,
// confidence, or credential LENGTH, all identical between the two 16-byte creds
// so their difference is EXACTLY the bonus for ANY confidence: 5.0 for a
// service-anchored detector, 0 for a generic one. A third property pins that the
// confidence term is positive (priority strictly increases with confidence).
// Traced against resolution.rs:276. No proptest before.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// The known-prefix bonus is EXACTLY 5.0 for a service-anchored detector, at
    /// any confidence (every other term cancels in the delta).
    #[test]
    fn known_prefix_bonus_is_exactly_five_for_any_confidence(conf in 0.0f64..=1.0) {
        let with_prefix = match_priority_for_test("aws-access-key", KNOWN_PREFIX_CRED, Some(conf));
        let without = match_priority_for_test("aws-access-key", NO_PREFIX_CRED, Some(conf));
        prop_assert!(((with_prefix - without) - 5.0).abs() < EPSILON);
    }

    /// A generic (non-service-anchored) detector receives NO bonus at any
    /// confidence (the delta is exactly zero).
    #[test]
    fn generic_detector_gets_no_bonus_for_any_confidence(conf in 0.0f64..=1.0) {
        let with_prefix = match_priority_for_test("generic-password", KNOWN_PREFIX_CRED, Some(conf));
        let without = match_priority_for_test("generic-password", NO_PREFIX_CRED, Some(conf));
        prop_assert!((with_prefix - without).abs() < EPSILON);
    }

    /// Priority strictly increases with confidence (the confidence weight is
    /// positive), holding detector and credential fixed.
    #[test]
    fn priority_strictly_increases_with_confidence(c in 0.0f64..0.98, d in 0.005f64..0.02) {
        let lo = match_priority_for_test("aws-access-key", KNOWN_PREFIX_CRED, Some(c));
        let hi = match_priority_for_test("aws-access-key", KNOWN_PREFIX_CRED, Some(c + d));
        prop_assert!(hi > lo, "priority must increase with confidence: {} !> {}", hi, lo);
    }
}
