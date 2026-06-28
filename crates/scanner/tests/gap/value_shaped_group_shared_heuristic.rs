//! Regression: the variable-name -> value-shaped-sibling fallback is ONE shared
//! heuristic, exercised behaviourally.
//!
//! `extract_grouped_matches` (whole-chunk walk) and `extract_anchored` (phase-2
//! anchored verification) both resolve the credential group, and both used to
//! open-code the same fallback: when the configured group looks like a variable
//! name, scan the other capture groups for a value-shaped sibling. Two copies of
//! a detection-load-bearing heuristic is a drift hazard — a tweak to one path's
//! notion of "value-shaped" silently diverges recall between the whole-chunk and
//! anchored paths. It is now one `resolve_value_shaped_group` helper.
//!
//! The heuristic's definitions (matching `looks_like_variable_name`):
//!   * a group is "variable-name shaped" iff it is non-empty, <= 64 bytes, and
//!     every byte is `[A-Za-z0-9_]`;
//!   * a sibling is "value-shaped" iff it is NOT variable-name shaped (i.e. it
//!     contains some other byte, e.g. `-` `/` `.` `+`) AND is at least 8 bytes.
//!
//! This drives the shared helper through a real compiled regex and pins the
//! actual resolved byte ranges (Law 6 — real values, not shape).

use keyhog_scanner::testing::resolve_value_shaped_group_for_test as resolve;

#[test]
fn variable_name_group_falls_back_to_value_shaped_sibling() {
    // group 1 = "username" (pure [\w] => variable-name shaped); group 2 contains
    // a '-' (=> NOT variable-name shaped) and is >= 8 bytes (=> value-shaped).
    // The heuristic must move off group 1 onto group 2.
    let text = "username=alice key=sk-1234567890abcd";
    let pattern = r"(\w+)=\w+ \w+=([\w-]+)";
    let resolved = resolve(pattern, text, 1).expect("match");
    assert_eq!(
        &text[resolved.0..resolved.1],
        "sk-1234567890abcd",
        "a variable-name group must fall back to the value-shaped (non-[\\w], >=8) sibling"
    );
}

#[test]
fn non_variable_name_group_is_left_unchanged() {
    // group 1 contains '-' => already NOT variable-name shaped => returned
    // unchanged even though a sibling exists.
    let text = "sk-abcdefghij key=plainlongword";
    let pattern = r"([\w-]+) \w+=(\w+)";
    let resolved = resolve(pattern, text, 1).expect("match");
    assert_eq!(
        &text[resolved.0..resolved.1], "sk-abcdefghij",
        "a non-variable-name group must be returned unchanged"
    );
}

#[test]
fn short_sibling_does_not_qualify_so_original_group_is_kept() {
    // group 1 is variable-name shaped; the only sibling (group 2 = "ab-cd")
    // is non-[\w] but only 5 bytes (< 8), so it does NOT qualify and the
    // original variable-name group is kept (no spurious move).
    let text = "token=ab-cd";
    let pattern = r"(\w+)=([\w-]+)";
    let resolved = resolve(pattern, text, 1).expect("match");
    assert_eq!(
        &text[resolved.0..resolved.1], "token",
        "a sub-8-byte sibling must not be picked; the original group stays"
    );
}

#[test]
fn two_or_fewer_groups_never_scans_siblings() {
    // groups_total <= 2 (whole match + one group) short-circuits before any
    // sibling scan, even when the group is variable-name shaped.
    let text = "password=mypassword";
    let pattern = r"\w+=(\w+)";
    let resolved = resolve(pattern, text, 1).expect("match");
    assert_eq!(
        &text[resolved.0..resolved.1], "mypassword",
        "with <= 2 total groups the heuristic must not scan for siblings"
    );
}
