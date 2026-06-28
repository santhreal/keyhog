//! Gap test: resolution's "service-specific detector" predicate is the single
//! canonical predicate, not an independent recomputation.
//!
//! `resolution::is_service_specific_detector` used to compute
//! `!entropy && !(generic || private_key_fallback)` through local wrappers —
//! algebraically identical to `detector_ids::is_service_anchored_detector`'s
//! `!generic && !entropy && !private_key_fallback`, i.e. a duplicated predicate
//! and a silent-drift hazard. It now delegates to the canonical owner. Pin both
//! the exact shared truth table AND that the two predicates agree on every
//! representative detector id (so future divergence fails the build).

use keyhog_scanner::testing::{
    is_service_anchored_detector_for_test, is_service_specific_detector_for_test,
};

// (detector_id, expected service-specific?) — one case per exclusion branch.
const CASES: &[(&str, bool)] = &[
    ("aws-access-key", true),    // real named service detector
    ("stripe-secret-key", true), // real named service detector
    ("generic-password", false), // `generic-` prefix -> generic
    ("entropy-token", false),    // `entropy-` prefix -> entropy
    ("entropy", false),          // bare `entropy` id
    ("private-key", false),      // the private-key fallback id
];

#[test]
fn service_specific_predicate_truth_table_is_exact() {
    for &(id, expected) in CASES {
        assert_eq!(
            is_service_specific_detector_for_test(id),
            expected,
            "is_service_specific_detector({id:?}) must be {expected}"
        );
    }
}

#[test]
fn service_specific_equals_canonical_service_anchored() {
    for &(id, _) in CASES {
        let specific = is_service_specific_detector_for_test(id);
        let anchored = is_service_anchored_detector_for_test(id);
        assert_eq!(
            specific, anchored,
            "resolution's predicate must equal the canonical detector_ids predicate for {id:?}: \
             specific={specific} anchored={anchored}"
        );
    }
}
