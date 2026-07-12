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

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin each class and a few collisions; these SWEEP the whole
// priority chain against an independent re-derivation. The ORDER is load-bearing
// (a keyword with two stem substrings must collapse to the earlier one, or the
// generic prefilter scans for the wrong literal). No proptest before.

use proptest::prelude::*;

/// The priority order the source `if/else if` chain encodes, highest first.
const STEM_PRIORITY: &[&str] = &[
    "secret",
    "pass",
    "pwd",
    "token",
    "webhook",
    "key",
    "auth",
    "credential",
];

/// Independent oracle: the FIRST priority stem the keyword contains (case-
/// sensitive `contains`, matching the source), else the keyword itself.
fn oracle_stem(keyword: &str) -> String {
    for &s in STEM_PRIORITY {
        if keyword.contains(s) {
            return s.to_string();
        }
    }
    keyword.to_string()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// Differential over realistic `[a-z_]` keywords (mostly the fall-through
    /// branch plus incidental stem hits). The facade takes `&'static str`, so the
    /// generated keyword is leaked (bounded: a test-process-lifetime leak).
    #[test]
    fn stem_matches_priority_chain_on_realistic_keywords(keyword in "[a-z_]{1,24}") {
        let leaked: &'static str = Box::leak(keyword.clone().into_boxed_str());
        prop_assert_eq!(stem(leaked), oracle_stem(&keyword));
    }

    /// Precedence stress: keywords built by joining 1-3 priority stems with short
    /// noise, so multiple stems co-occur and the EARLIER-priority one must win.
    #[test]
    fn stem_matches_priority_chain_on_stem_rich_keywords(
        idxs in prop::collection::vec(0usize..STEM_PRIORITY.len(), 1..4),
        sep in "[a-z_]{0,3}",
    ) {
        let keyword: String = idxs
            .iter()
            .map(|&i| STEM_PRIORITY[i])
            .collect::<Vec<_>>()
            .join(sep.as_str());
        let leaked: &'static str = Box::leak(keyword.clone().into_boxed_str());
        prop_assert_eq!(stem(leaked), oracle_stem(&keyword));
    }
}
