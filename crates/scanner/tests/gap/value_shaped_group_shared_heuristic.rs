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
        &text[resolved.0..resolved.1],
        "sk-abcdefghij",
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
        &text[resolved.0..resolved.1],
        "token",
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
        &text[resolved.0..resolved.1],
        "mypassword",
        "with <= 2 total groups the heuristic must not scan for siblings"
    );
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin one example per branch; these SWEEP the shared heuristic
// through real compiled regexes across the variable-name / value-shaped boundary:
// a variable-name group (`[A-Za-z0-9_]`, ≤64) moves to a value-shaped sibling
// (non-`\w`, ≥8 bytes); a group already non-variable-name is left unchanged; a
// var-name group with no value-shaped sibling keeps the original; and a ≤2-group
// pattern never scans. All assert the resolved BYTE RANGE (Law 6). Traced against
// `resolve_value_shaped_group` + `looks_like_variable_name`. No proptest before.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// A variable-name group falls back to a value-shaped sibling (contains a
    /// non-`\w` byte AND ≥ 8 bytes).
    #[test]
    fn var_name_group_moves_to_value_shaped_sibling(
        tok1 in "[A-Za-z0-9_]{1,20}",
        a in "[A-Za-z0-9]{4}",
        b in "[A-Za-z0-9]{3,20}",
    ) {
        let tok2 = format!("{a}-{b}"); // has '-', len >= 8 => value-shaped
        let text = format!("{tok1} {tok2}");
        let resolved = resolve(r"(\S+) (\S+)", &text, 1);
        prop_assert!(resolved.is_some());
        let (s, e) = resolved.unwrap();
        prop_assert_eq!(&text[s..e], tok2.as_str());
    }

    /// A group that is already NOT variable-name shaped is returned unchanged, even
    /// when a value-shaped sibling exists.
    #[test]
    fn non_var_name_group_is_unchanged(
        a in "[A-Za-z0-9]{2,10}",
        b in "[A-Za-z0-9]{2,10}",
        sib in "[A-Za-z0-9]{4}-[A-Za-z0-9]{4}",
    ) {
        let tok1 = format!("{a}-{b}"); // has '-' => not variable-name shaped
        let text = format!("{tok1} {sib}");
        let resolved = resolve(r"(\S+) (\S+)", &text, 1);
        prop_assert!(resolved.is_some());
        let (s, e) = resolved.unwrap();
        prop_assert_eq!(&text[s..e], tok1.as_str());
    }

    /// A var-name group whose only sibling is ALSO variable-name shaped (not
    /// value-shaped) keeps the original group — no spurious move.
    #[test]
    fn no_value_shaped_sibling_keeps_original(
        tok1 in "[A-Za-z0-9_]{1,20}",
        tok2 in "[A-Za-z0-9_]{1,20}",
    ) {
        let text = format!("{tok1} {tok2}");
        let resolved = resolve(r"(\S+) (\S+)", &text, 1);
        prop_assert!(resolved.is_some());
        let (s, e) = resolved.unwrap();
        prop_assert_eq!(&text[s..e], tok1.as_str());
    }

    /// With ≤ 2 total groups the heuristic short-circuits and returns the
    /// configured group unchanged (never scans for siblings).
    #[test]
    fn single_group_pattern_never_scans_siblings(value in "[A-Za-z0-9_]{1,20}") {
        let text = format!("key={value}");
        let resolved = resolve(r"\w+=(\w+)", &text, 1);
        prop_assert!(resolved.is_some());
        let (s, e) = resolved.unwrap();
        prop_assert_eq!(&text[s..e], value.as_str());
    }
}
