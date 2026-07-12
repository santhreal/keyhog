//! Gap test: Slack structural-checksum verdicts across both token shapes.
//!
//! The bot and user gate regexes are now compiled through one shared
//! `compile_slack_re` helper (previously two duplicated `match Regex::new {…}`
//! blocks). Pin the verdicts that helper's regexes produce — in particular that
//! BOTH bot shapes the detector emits (3-segment and the older 2-segment) are
//! Valid, the contract the widened regex exists to preserve.

use keyhog_scanner::testing::slack_checksum_verdict_for_test;

#[test]
fn bot_token_three_segment_is_valid() {
    // xoxb-{10-15 digits}-{10-15 digits}-{15-40 alnum}
    assert_eq!(
        slack_checksum_verdict_for_test("xoxb-1234567890-0987654321-abcdefghijklmnop"),
        "valid"
    );
}

#[test]
fn bot_token_two_segment_is_valid() {
    // xoxb-{10-15 digits}-{15-40 alnum} (older installs; second numeric optional)
    assert_eq!(
        slack_checksum_verdict_for_test("xoxb-1234567890-abcdefghijklmnop"),
        "valid"
    );
}

#[test]
fn malformed_bot_token_is_invalid() {
    // First numeric segment is only 5 digits (< 10): structural reject.
    assert_eq!(
        slack_checksum_verdict_for_test("xoxb-12345-abcdefghijklmnop"),
        "invalid"
    );
}

#[test]
fn user_token_is_valid_and_malformed_is_invalid() {
    // xoxp-{10-15 d}-{10-15 d}(-{10-13 d})?-{24-40 alnum}
    assert_eq!(
        slack_checksum_verdict_for_test("xoxp-1234567890-0987654321-abcdefghijklmnopqrstuvwx"),
        "valid"
    );
    // Missing the required second numeric segment.
    assert_eq!(
        slack_checksum_verdict_for_test("xoxp-1234567890-abcdefghijklmnopqrstuvwx"),
        "invalid"
    );
}

#[test]
fn non_slack_prefix_is_not_applicable() {
    assert_eq!(
        slack_checksum_verdict_for_test("ghp_0123456789abcdefABCDEF"),
        "not-applicable"
    );
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin one example per shape; these SWEEP the two anchored
// regexes across their whole valid domain and the structural-reject boundaries.
// Constructive positives generate strings that satisfy each regex (both bot
// shapes, both user shapes) — a `letter`-anchored secret keeps the optional
// numeric group from greedily consuming it, so the parse is unambiguous. Negatives
// violate exactly ONE bound. Plus the prefix rule (only `xoxb-`/`xoxp-` are in
// scope). Regexes traced from checksum/slack.rs:42/48. No proptest before.

use keyhog_scanner::testing::slack_checksum_verdict_for_test as verdict;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// Canonical 3-segment bot token: `xoxb-{10-15 d}-{10-15 d}-{15-40 alnum}`.
    #[test]
    fn bot_three_segment_is_valid(
        n1 in "[0-9]{10,15}",
        n2 in "[0-9]{10,15}",
        secret in "[a-zA-Z][a-zA-Z0-9]{14,39}",
    ) {
        let tok = format!("xoxb-{n1}-{n2}-{secret}");
        prop_assert_eq!(verdict(&tok), "valid");
    }

    /// Older 2-segment bot token: `xoxb-{10-15 d}-{15-40 alnum}` (numeric group
    /// omitted).
    #[test]
    fn bot_two_segment_is_valid(
        n1 in "[0-9]{10,15}",
        secret in "[a-zA-Z][a-zA-Z0-9]{14,39}",
    ) {
        let tok = format!("xoxb-{n1}-{secret}");
        prop_assert_eq!(verdict(&tok), "valid");
    }

    /// A first numeric segment shorter than 10 digits is a structural reject.
    #[test]
    fn bot_short_first_numeric_is_invalid(
        n1 in "[0-9]{1,9}",
        secret in "[a-zA-Z][a-zA-Z0-9]{14,39}",
    ) {
        let tok = format!("xoxb-{n1}-{secret}");
        prop_assert_eq!(verdict(&tok), "invalid");
    }

    /// A secret shorter than 15 alnum is a structural reject.
    #[test]
    fn bot_short_secret_is_invalid(
        n1 in "[0-9]{10,15}",
        secret in "[a-zA-Z][a-zA-Z0-9]{0,13}",
    ) {
        let tok = format!("xoxb-{n1}-{secret}");
        prop_assert_eq!(verdict(&tok), "invalid");
    }

    /// User token, 3-segment and 4-segment (optional third numeric):
    /// `xoxp-{10-15 d}-{10-15 d}(-{10-13 d})?-{24-40 alnum}`.
    #[test]
    fn user_token_is_valid(
        d1 in "[0-9]{10,15}",
        d2 in "[0-9]{10,15}",
        mid in prop::option::of("[0-9]{10,13}"),
        secret in "[a-zA-Z][a-zA-Z0-9]{23,39}",
    ) {
        let tok = match &mid {
            Some(m) => format!("xoxp-{d1}-{d2}-{m}-{secret}"),
            None => format!("xoxp-{d1}-{d2}-{secret}"),
        };
        prop_assert_eq!(verdict(&tok), "valid");
    }

    /// A user token missing the required second numeric segment is a reject.
    #[test]
    fn user_missing_second_numeric_is_invalid(
        d1 in "[0-9]{10,15}",
        secret in "[a-zA-Z][a-zA-Z0-9]{23,39}",
    ) {
        let tok = format!("xoxp-{d1}-{secret}");
        prop_assert_eq!(verdict(&tok), "invalid");
    }

    /// Only `xoxb-`/`xoxp-` prefixes are in scope; anything else is
    /// not-applicable (the validator defers rather than rejecting).
    #[test]
    fn non_slack_prefix_is_not_applicable_sweep(cred in "(?s).{0,40}") {
        prop_assume!(!cred.starts_with("xoxb-") && !cred.starts_with("xoxp-"));
        prop_assert_eq!(verdict(&cred), "not-applicable");
    }
}
