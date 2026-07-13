//! Gap test: resolution's "service-specific detector" predicate is the single
//! canonical predicate, not an independent recomputation.
//!
//! `resolution::is_service_specific_detector` used to compute
//! `!entropy && !(generic || private_key_fallback)` through local wrappers
//! algebraically identical to `detector_ids::is_service_anchored_detector`'s
//! `!generic && !entropy && !private_key_fallback`, i.e. a duplicated predicate
//! and a silent-drift hazard. It now delegates to the canonical owner. Pin both
//! the exact shared truth table AND that the two predicates agree on every
//! representative detector id (so future divergence fails the build).

use keyhog_scanner::testing::{
    is_service_anchored_detector_for_test, is_service_specific_detector_for_test,
};

// (detector_id, expected service-specific?) (one case per exclusion branch).
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

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin the truth table on 6 representative ids; these SWEEP it.
// The DEDUP guarantee is the killer: the two predicates agree on EVERY id (one
// delegates to the other), swept over arbitrary Unicode. Constructive cases pin
// each exclusion branch (`generic-`/`entropy-` prefixes, bare `entropy`) reject
// and a plain vendor id is service-specific. Traced against detector_ids.rs:99. No
// proptest before.

use keyhog_scanner::testing::is_service_anchored_detector_for_test as anchored;
use keyhog_scanner::testing::is_service_specific_detector_for_test as specific;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3_000))]

    /// DEDUP: the resolution predicate agrees with the canonical detector_ids
    /// predicate on EVERY id (no silent divergence), over arbitrary Unicode.
    #[test]
    fn both_predicates_agree_on_any_id(id in "(?s).{0,24}") {
        prop_assert_eq!(specific(&id), anchored(&id));
    }

    /// A `generic-` prefixed id is never service-specific.
    #[test]
    fn generic_prefixed_ids_are_not_service_specific(suffix in "[a-z-]{0,16}") {
        let id = format!("generic-{suffix}");
        prop_assert!(!specific(&id));
    }

    /// An `entropy-` prefixed id (and the bare `entropy` id) is never
    /// service-specific.
    #[test]
    fn entropy_ids_are_not_service_specific(suffix in "[a-z-]{0,16}") {
        let id = format!("entropy-{suffix}");
        prop_assert!(!specific(&id));
        prop_assert!(!specific("entropy"));
    }

    /// A plain vendor-style id (no generic/entropy prefix, not a private-key
    /// fallback) IS service-specific.
    #[test]
    fn plain_vendor_ids_are_service_specific(suffix in "[a-z]{1,16}") {
        let id = format!("vendor-{suffix}");
        prop_assert!(specific(&id));
    }
}
