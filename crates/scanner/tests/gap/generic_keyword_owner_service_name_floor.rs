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
    let owned =
        generic_named_owned_keywords_for_test("segment", &["segment_write_key", "segment"]);
    assert_eq!(owned, vec!["segment_write_key".to_string()]);
}
