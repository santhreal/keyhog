//! Gap test: `resolution::match_priority` weights are all named constants.
//!
//! Every priority component in `match_priority` already used a named weight
//! (`NAMED_DETECTOR_PRIORITY`, `CONFIDENCE_WEIGHT`, `DETECTOR_ID_LENGTH_WEIGHT`,
//! `CREDENTIAL_LENGTH_WEIGHT`) except the known-prefix / service-anchored bonus,
//! which was a bare `priority += 5.0;` magic literal. It is now
//! `KNOWN_PREFIX_SERVICE_BONUS: f64 = 5.0`.
//!
//! Pinned behaviorally, not by source shape: two matches that are IDENTICAL in
//! detector_id, confidence, and credential length — differing only in whether
//! the credential carries a known prefix — differ in priority by EXACTLY the
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
