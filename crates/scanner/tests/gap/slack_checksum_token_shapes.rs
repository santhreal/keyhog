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
