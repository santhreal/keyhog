//! Prefilter `{N,}`→`{N}` truncation soundness, migrated out of
//! `src/engine/fallback.rs` (no-inline-tests gate). `truncate_for_prefilter`
//! bounds the first top-level unbounded repetition so the always-active
//! prefilter RegexSet stays on the lazy-DFA; the truncated form must be a SOUND
//! SUPERSET of the full pattern (a truncated-no-match proves a full-no-match).

use keyhog_scanner::testing::truncate_for_prefilter;

/// The truncated prefilter form must be a SOUND SUPERSET: every string the
/// FULL pattern matches must also be matched by the truncated form (so a
/// truncated-no-match proves a full-no-match — the gate never under-marks).
fn assert_superset(full: &str, samples: &[&str]) {
    let trunc = truncate_for_prefilter(full).expect("expected truncation");
    let rf = regex::Regex::new(full).unwrap();
    let rt = regex::Regex::new(&trunc).unwrap();
    for s in samples {
        if rf.is_match(s) {
            assert!(
                rt.is_match(s),
                "UNSOUND: full {full:?} matched {s:?} but truncated {trunc:?} did not"
            );
        }
    }
}

#[test]
fn truncates_atleast_at_end() {
    assert_eq!(
        truncate_for_prefilter("sk_live_[a-z0-9]{20,}").as_deref(),
        Some("sk_live_[a-z0-9]{20}")
    );
}

#[test]
fn truncates_plus_to_one() {
    assert_eq!(
        truncate_for_prefilter("foo[a-z]+").as_deref(),
        Some("foo[a-z]")
    );
}

#[test]
fn truncates_star_dropping_rest() {
    assert_eq!(
        truncate_for_prefilter("bar[0-9]*baz").as_deref(),
        Some("bar")
    );
}

#[test]
fn drops_suffix_after_unbounded() {
    assert_eq!(
        truncate_for_prefilter("prefix[a-z]{5,}suffix").as_deref(),
        Some("prefix[a-z]{5}")
    );
}

#[test]
fn skips_bounded_until_unbounded() {
    // `{16,20}` is finite (kept), the trailing `[a-z]{20,}` is the blow-up.
    assert_eq!(
        truncate_for_prefilter("1/[0-9]{16,20}/[a-z]{20,}").as_deref(),
        Some("1/[0-9]{16,20}/[a-z]{20}")
    );
}

#[test]
fn none_when_already_bounded() {
    assert_eq!(truncate_for_prefilter("[a-f0-9]{32}"), None);
    assert_eq!(truncate_for_prefilter("ghp_[A-Za-z0-9]{36}"), None);
}

#[test]
fn superset_invariant_on_samples() {
    assert_superset(
        "sk_live_[a-z0-9]{20,}",
        &[
            "sk_live_abcdefghij0123456789",
            "sk_live_abcdefghij0123456789xyz",
            "nope",
        ],
    );
    assert_superset(
        "prefix[a-z]{5,}suffix",
        &["prefixaaaaasuffix", "prefixaaaaaaaaaasuffix", "prefixaa"],
    );
    assert_superset(
        "1/[0-9]{16,20}/[a-z]{20,}",
        &["1/1234567890123456/abcdefghijklmnopqrst", "1/123/x"],
    );
}
