//! Gap test: named-detector assignment-key ownership floors.
//!
//! `build_generic_named_assignment_keywords` precomputes the set of `KEY=value`
//! anchors that loaded named detectors own, so the broad generic bridge does not
//! second-guess them. The service-name-length floor is now named
//! `MIN_SERVICE_NAME_LEN` (= 3): a detector whose normalized service is only two
//! characters is too generic to claim ownership and contributes nothing, while a
//! three-character service is the first length that can. Pin that boundary
//! through real behavior, plus the secret-suffix gate that keeps a bare service
//! marker (`segment`) from being owned.

use keyhog_scanner::testing::generic_named_owned_keywords_for_test;

#[test]
fn three_char_service_owns_matching_anchor() {
    // service "aws" (3 chars) -> the anchor that embeds it and ends in a
    // credential suffix is owned.
    let owned = generic_named_owned_keywords_for_test("aws", &["aws_secret_access_key"]);
    assert_eq!(owned, vec!["aws_secret_access_key".to_string()]);
}

#[test]
fn min_service_name_len_floor_is_exactly_three() {
    // Same anchor shape, only the service length differs: a 2-char service is
    // below MIN_SERVICE_NAME_LEN and owns nothing; a 3-char service owns it.
    let below = generic_named_owned_keywords_for_test("ab", &["ab_secret_key"]);
    assert_eq!(
        below,
        Vec::<String>::new(),
        "a 2-char service is below MIN_SERVICE_NAME_LEN (3) and claims no anchor"
    );

    let at_floor = generic_named_owned_keywords_for_test("abc", &["abc_secret_key"]);
    assert_eq!(
        at_floor,
        vec!["abc_secret_key".to_string()],
        "a 3-char service is the first length that can own an anchor"
    );
}

#[test]
fn bare_service_marker_without_secret_suffix_is_not_owned() {
    // "segment" embeds the service but lacks a credential suffix, so it is NOT
    // owned; only "segment_write_key" (suffix "key") is claimed.
    let owned = generic_named_owned_keywords_for_test("segment", &["segment_write_key", "segment"]);
    assert_eq!(owned, vec!["segment_write_key".to_string()]);
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin the floor at 2/3 chars and the bare-marker case; these
// SWEEP the three ownership gates in isolation. A keyword is owned iff ALL of:
// (a) service.len() >= MIN_SERVICE_NAME_LEN (3), (b) the keyword has a secret
// suffix, and (c) the keyword CONTAINS the service substring — and the result is a
// sorted, deduped BTreeSet. Each property flips exactly one gate. Traced against
// `build_generic_named_assignment_keywords` (generic_keyword_owner.rs:100). No
// proptest before.

use proptest::prelude::*;

/// Secret-suffixed keyword tails (each string-ends with a credential suffix).
const SECRET_TAILS: &[&str] = &[
    "secret_key",
    "api_token",
    "password",
    "access_secret",
    "auth_token",
];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// The service-length floor is exactly 3: a service under 3 chars owns nothing;
    /// 3+ chars owns its secret-suffixed, service-embedding anchor.
    #[test]
    fn service_length_floor_is_three_sweep(svc in "[a-z]{1,10}") {
        let anchor = format!("{svc}_secret_key");
        let owned = generic_named_owned_keywords_for_test(&svc, &[anchor.as_str()]);
        if svc.len() >= 3 {
            prop_assert_eq!(owned, vec![anchor]);
        } else {
            prop_assert!(owned.is_empty());
        }
    }

    /// (b) The secret-suffix gate: a 3+ char service whose anchor lacks a credential
    /// suffix (`_region`) owns nothing.
    #[test]
    fn keyword_without_secret_suffix_is_not_owned(svc in "[a-z]{3,10}") {
        let anchor = format!("{svc}_region");
        let owned = generic_named_owned_keywords_for_test(&svc, &[anchor.as_str()]);
        prop_assert!(owned.is_empty());
    }

    /// (c) The embedding gate: a secret-suffixed keyword that does NOT contain the
    /// service substring is not owned. The service is drawn from letters `m-p`,
    /// none of which appear in `aws_secret_key`, so containment cannot hold.
    #[test]
    fn secret_suffixed_keyword_not_containing_service_is_not_owned(svc in "[m-p]{4,6}") {
        let owned = generic_named_owned_keywords_for_test(&svc, &["aws_secret_key"]);
        prop_assert!(owned.is_empty());
    }

    /// The owned set is sorted, deduped, and filtered to exactly the secret-suffixed
    /// service-embedding anchors (a non-suffixed sibling and a duplicate are dropped).
    #[test]
    fn owned_set_is_sorted_deduped_and_filtered(
        svc in "[a-z]{3,8}",
        i in 0usize..SECRET_TAILS.len(),
        j in 0usize..SECRET_TAILS.len(),
    ) {
        let a = format!("{svc}_{}", SECRET_TAILS[i]);
        let b = format!("{svc}_{}", SECRET_TAILS[j]);
        let non_suffix = format!("{svc}_region");
        let owned = generic_named_owned_keywords_for_test(
            &svc,
            &[a.as_str(), b.as_str(), non_suffix.as_str(), a.as_str()], // a repeated
        );
        // BTreeSet semantics: the distinct secret-suffixed anchors, sorted.
        let mut expected: Vec<String> = vec![a, b];
        expected.sort();
        expected.dedup();
        prop_assert_eq!(owned, expected);
    }
}
