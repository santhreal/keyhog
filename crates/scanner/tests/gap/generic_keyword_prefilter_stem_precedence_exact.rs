//! Gap test: the generic-keyword prefilter-stem precedence chain.
//!
//! `engine::phase2_generic::keywords::generic_keyword_prefilter_stem` collapses a
//! detector keyword to the single literal the generic-keyword prefilter scans
//! for (the stem set consumed by the compile and GPU-artifact paths). It is a
//! PRIORITY-ORDERED `contains` chain:
//!   `secret` > `pass` > `pwd` > `token` > `webhook` > `key` > `auth` >
//!   `credential`, otherwise the keyword itself.
//!
//! Only a source-shape gate referenced the plural `_stems()` builder; the
//! singular classifier had no behavioral test. The ORDER is the load-bearing
//! property — a keyword containing two of these substrings resolves to the
//! earlier one — so pin every precedence collision and the fall-through. All
//! vectors were traced against the chain.

use keyhog_scanner::testing::generic_keyword_prefilter_stem_for_test as stem;

#[test]
fn each_stem_class_is_recognized() {
    assert_eq!(stem("client_secret"), "secret");
    assert_eq!(stem("user_pass"), "pass");
    assert_eq!(stem("user_pwd"), "pwd");
    assert_eq!(stem("access_token"), "token");
    assert_eq!(stem("webhook_url"), "webhook");
    assert_eq!(stem("api_key"), "key");
    assert_eq!(stem("authorization"), "auth");
    assert_eq!(stem("credentials"), "credential");
}

#[test]
fn earlier_substring_wins_each_collision() {
    // `secret` outranks both `key` and `webhook`.
    assert_eq!(stem("secret_key"), "secret");
    assert_eq!(stem("webhook_secret"), "secret");
    // `pass` outranks `pwd` — `passwd` contains `pass`, so it never reaches pwd.
    assert_eq!(stem("passwd"), "pass");
    // `token` outranks `auth`.
    assert_eq!(stem("oauth_token"), "token");
    // `key` outranks `auth`.
    assert_eq!(stem("auth_key"), "key");
}

#[test]
fn unmatched_keyword_falls_through_to_itself() {
    assert_eq!(stem("username"), "username");
    assert_eq!(stem("host"), "host");
}
