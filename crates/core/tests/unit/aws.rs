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
fn canary_parser_rejects_confusable_and_overlong_account_ids() {
    // A 12-CHARACTER id whose length passes but contains a non-digit (letter 'O'
    // where '0' belongs) must fail closed. This exercises the `all(is_ascii_digit)`
    // half of the 12-digit contract, a DISTINCT branch from the "1234" case
    // above, which fails on length. A length-only guard would silently accept a
    // confusable account id and mis-classify a real credential's canary status.
    let confusable = keyhog_core::testing::CoreTestApi::parse_aws_canary_accounts_for_test(
        &keyhog_core::testing::TestApi,
        "[canary]\naccounts = [\"12345678901O\"]\n", // 11 digits + trailing letter O = 12 chars
    )
    .expect_err("a 12-char id with a non-digit must fail closed");
    assert!(
        confusable.contains("12-digit AWS account id"),
        "unexpected confusable-account error: {confusable}"
    );

    // A 13-digit id (one over) must also fail closed, the UPPER boundary of the
    // exact-length rule; "1234" only pins the lower boundary.
    let overlong = keyhog_core::testing::CoreTestApi::parse_aws_canary_accounts_for_test(
        &keyhog_core::testing::TestApi,
        "[canary]\naccounts = [\"1234567890123\"]\n", // 13 digits
    )
    .expect_err("a 13-digit id must fail closed");
    assert!(
        overlong.contains("12-digit AWS account id"),
        "unexpected overlong-account error: {overlong}"
    );
}

#[test]
fn canary_parser_merges_knockoff_table_into_the_canary_set() {
    // keyhog treats off-brand `[knockoff]` accounts IDENTICALLY to first-party
    // `[canary]` ones, both tables merge into ONE recognized set (aws.rs
    // `parse_canary_accounts` chains `canary.accounts` and `knockoff.accounts`).
    // A regression that dropped the knockoff table would silently stop
    // recognizing knockoff canary accounts, so a real knockoff canary credential
    // would be mishandled. Also confirms the shared trim contract applies to the
    // knockoff table (leading/trailing whitespace stripped).
    let merged = keyhog_core::testing::CoreTestApi::parse_aws_canary_accounts_for_test(
        &keyhog_core::testing::TestApi,
        "[canary]\naccounts = [\"000000000001\"]\n[knockoff]\naccounts = [\" 000000000002 \"]\n",
    )
    .expect("valid canary + knockoff accounts must parse");
    assert_eq!(
        merged.len(),
        2,
        "both the canary and the knockoff account must be present: {merged:?}"
    );
    assert!(
        merged.contains("000000000001"),
        "first-party canary account must be recognized: {merged:?}"
    );
    assert!(
        merged.contains("000000000002"),
        "knockoff account must be merged (and trimmed) into the same set: {merged:?}"
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

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// The 12-digit-AWS-account-id contract over ARBITRARY input, differential
    /// against an INDEPENDENT oracle. `parse_canary_account_ids` (the public
    /// `.keyhog.toml` config parser) shares the `insert_validated_account` owner
    /// with the embedded baseline parser, so this pins BOTH surfaces at once: an
    /// account is accepted IFF its trimmed form is EXACTLY 12 ASCII digits, and on
    /// acceptance the set stores that trimmed form. The generator `[0-9a ]{0,16}`
    /// is dense in every boundary the hand-written example tests pin only pointwise
    ///: exactly-12 (accept), 11/13 digits (length reject), a non-digit among 12
    /// chars (charset reject), and leading/trailing spaces (trim then re-check) 
    /// so no edge can let a malformed account into the canary set (which would
    /// silently mis-classify a real credential's canary status) or drop a valid one.
    #[test]
    fn parse_canary_account_ids_accepts_iff_trimmed_is_12_ascii_digits(
        raw in "[0-9a ]{0,16}"
    ) {
        let trimmed = raw.trim();
        let oracle_valid =
            trimmed.len() == 12 && trimmed.bytes().all(|byte| byte.is_ascii_digit());

        let result = parse_canary_account_ids([raw.as_str()]);
        prop_assert_eq!(
            result.is_ok(),
            oracle_valid,
            "accept/reject must match the exactly-12-ASCII-digits oracle: raw={:?} trimmed={:?}",
            raw,
            trimmed
        );
        if let Ok(set) = result {
            prop_assert!(
                set.contains(trimmed),
                "an accepted account must be stored in its TRIMMED form: raw={:?}",
                raw
            );
        }
    }
}
