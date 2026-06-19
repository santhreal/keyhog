//! Unit tests for the offline AWS account-ID decode + canary classification in
//! [`keyhog_core::aws`]. Migrated out of `src/aws.rs`: `core/src` must stay free
//! of inline `#[cfg(test)]` modules (KH-GAP-004 / `gap::no_inline_tests_in_src`),
//! so the shared decode/canary logic is exercised here under `tests/unit/`.

use keyhog_core::{finding_metadata, key_id_canary_status, parse_canary_account_ids};

#[test]
fn decodes_canonical_truffle_sample() {
    assert_eq!(
        keyhog_core::testing::CoreTestApi::aws_account_from_key_id(
            &keyhog_core::testing::TestApi,
            "ASIAY34FZKBOKMUTVV7A"
        )
        .as_deref(),
        Some("609629065308")
    );
}

#[test]
fn decodes_akia_with_leading_zero_account() {
    // canarytokens.org / Thinkst account; the leading zero MUST be kept.
    assert_eq!(
        keyhog_core::testing::CoreTestApi::aws_account_from_key_id(
            &keyhog_core::testing::TestApi,
            "AKIAAYLPMN5HAAAAAAAA"
        )
        .as_deref(),
        Some("052310077262")
    );
}

#[test]
fn rejects_non_aws_and_malformed_ids() {
    assert_eq!(
        keyhog_core::testing::CoreTestApi::aws_account_from_key_id(
            &keyhog_core::testing::TestApi,
            "not-an-aws-key"
        ),
        None
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::aws_account_from_key_id(
            &keyhog_core::testing::TestApi,
            "AKIA1234"
        ),
        None
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::aws_account_from_key_id(
            &keyhog_core::testing::TestApi,
            "ZZZZY34FZKBOKMUTVV7A"
        ),
        None
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::aws_account_from_key_id(
            &keyhog_core::testing::TestApi,
            "ASIAy34FZKBOKMUTVV7A"
        ),
        None
    );
}

#[test]
fn canary_account_is_recognised() {
    assert!(keyhog_core::testing::CoreTestApi::aws_account_is_canary(
        &keyhog_core::testing::TestApi,
        "052310077262"
    ));
    assert!(keyhog_core::testing::CoreTestApi::aws_account_is_canary(
        &keyhog_core::testing::TestApi,
        "044858866125"
    ));
    assert!(!keyhog_core::testing::CoreTestApi::aws_account_is_canary(
        &keyhog_core::testing::TestApi,
        "609629065308"
    ));
}

#[test]
fn canary_tier_b_parser_rejects_invalid_account_files() {
    let malformed = keyhog_core::testing::CoreTestApi::parse_aws_canary_accounts_for_test(
        &keyhog_core::testing::TestApi,
        "not = [",
    )
    .expect_err("malformed AWS canary TOML must fail closed");
    assert!(
        malformed.contains("invalid aws-canary-accounts.toml"),
        "unexpected malformed error: {malformed}"
    );

    let blank = keyhog_core::testing::CoreTestApi::parse_aws_canary_accounts_for_test(
        &keyhog_core::testing::TestApi,
        "[canary]\naccounts = [\"  \"]\n",
    )
    .expect_err("blank AWS canary account must fail closed");
    assert!(
        blank.contains("must not be empty"),
        "unexpected blank-account error: {blank}"
    );

    let malformed_account = keyhog_core::testing::CoreTestApi::parse_aws_canary_accounts_for_test(
        &keyhog_core::testing::TestApi,
        "[canary]\naccounts = [\"1234\"]\n",
    )
    .expect_err("short AWS canary account must fail closed");
    assert!(
        malformed_account.contains("12-digit AWS account id"),
        "unexpected malformed-account error: {malformed_account}"
    );
}

#[test]
fn configured_canary_account_parser_accepts_unique_toml_values() {
    let parsed = parse_canary_account_ids([" 609629065308 ", "609629065308", "000000000001"])
        .expect("valid configured AWS account IDs");

    assert_eq!(parsed.len(), 2);
    assert!(parsed.contains("609629065308"));
    assert!(parsed.contains("000000000001"));

    let invalid = parse_canary_account_ids(["1234"])
        .expect_err("configured AWS account IDs must be 12 digits");
    assert!(
        invalid.contains("12-digit AWS account id"),
        "unexpected invalid account error: {invalid}"
    );
}

#[test]
fn canary_key_id_round_trips_through_decode() {
    assert!(key_id_canary_status("AKIAAYLPMN5HAAAAAAAA").expect("canary status"));
    assert!(!key_id_canary_status("ASIAY34FZKBOKMUTVV7A").expect("canary status"));
    assert!(!key_id_canary_status("hunter2").expect("canary status"));
}

#[test]
fn finding_metadata_surfaces_account_id() {
    let meta = finding_metadata("ASIAY34FZKBOKMUTVV7A").expect("decodable");
    assert_eq!(
        meta.get("account_id").map(String::as_str),
        Some("609629065308")
    );
    assert!(finding_metadata("hunter2").is_none());
}

#[test]
fn finding_metadata_flags_canary_and_suppression_note() {
    let meta = finding_metadata("AKIAAYLPMN5HAAAAAAAA").expect("decodable canary key");
    assert_eq!(
        meta.get("account_id").map(String::as_str),
        Some("052310077262")
    );
    assert_eq!(meta.get("is_canary").map(String::as_str), Some("true"));
    assert!(meta
        .get("canary_message")
        .is_some_and(|m| m.contains("canarytokens.org")));

    let normal = finding_metadata("ASIAY34FZKBOKMUTVV7A").expect("decodable");
    assert_eq!(normal.get("is_canary"), None);
}
