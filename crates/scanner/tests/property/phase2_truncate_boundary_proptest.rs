//! Behavioral + property truth for the pure helpers in
//! `engine::phase2_truncate` that had NO direct coverage: `regex_prefix_anchorable`
//! (the soundness precondition for prefix-anchored scanning) and the decode-focus
//! UTF-8 window helpers `focus_floor_boundary` / `focus_ceil_boundary` /
//! `truncate_src`.
//!
//! `regex_prefix_anchorable` decides whether a pattern may be driven from
//! prefix-anchor positions instead of a whole-chunk walk — the precondition is a
//! FINITE, enumerable required-prefix set with every member >= 3 bytes. A false
//! TRUE would anchor a pattern lacking such a prefix and silently drop matches
//! (recall bug); a false FALSE forfeits the fast path (perf).
//!
//! `focus_floor_boundary` / `focus_ceil_boundary` snap the decode-focus window to
//! UTF-8 char boundaries so a slice never splits a multi-byte codepoint (a split
//! would panic on `&s[..i]`). `truncate_src` truncates on a boundary and appends
//! `…`. These are classic off-by-one / boundary logic — pinned here by fixed
//! multibyte vectors and boundary-bracketing property tests.

use keyhog_scanner::testing::{
    focus_ceil_boundary_for_test as focus_ceil, focus_floor_boundary_for_test as focus_floor,
    regex_prefix_anchorable_for_test as anchorable, truncate_src_for_test as truncate_src,
};
use proptest::prelude::*;

// ── regex_prefix_anchorable ──────────────────────────────────────────────────

#[test]
fn anchorable_true_for_a_finite_long_literal_prefix() {
    // A required literal prefix of >= 3 bytes before the variable body.
    assert!(anchorable("ghp_[A-Za-z0-9]{36}"));
    assert!(anchorable("AKIA[A-Z0-9]{16}"));
    assert!(anchorable("xoxb-[0-9]{10}"));
    // A bare >= 3-byte literal is trivially prefix-anchorable.
    assert!(anchorable("glpat"));
}

#[test]
fn anchorable_false_for_leading_charclass_or_unparseable() {
    // Leading character class => the required-prefix members are single bytes
    // (min length 1 < 3), so anchoring is unsound.
    assert!(!anchorable("[A-Za-z0-9]{32}"));
    assert!(!anchorable("[0-9]{10}"));
    // An unparseable pattern must return false (fail-closed), never panic.
    assert!(!anchorable("("));
    assert!(!anchorable("[z-"));
}

// ── focus_floor_boundary / focus_ceil_boundary: fixed multibyte vectors ──────

#[test]
fn boundary_helpers_snap_around_a_multibyte_codepoint() {
    // "café" bytes: c(0) a(1) f(2) é(3..5) — byte 4 is INSIDE the 2-byte 'é'.
    let s = "café";
    assert_eq!(s.len(), 5);
    // On an existing boundary: identity for both.
    for b in [0usize, 1, 2, 3, 5] {
        assert_eq!(focus_floor(s, b), b, "floor identity on boundary {b}");
        assert_eq!(focus_ceil(s, b), b, "ceil identity on boundary {b}");
    }
    // Mid-codepoint byte 4: floor rounds DOWN to 3, ceil rounds UP to 5.
    assert_eq!(focus_floor(s, 4), 3);
    assert_eq!(focus_ceil(s, 4), 5);
}

// ── truncate_src: verbatim when short, ellipsized on a boundary when long ─────

#[test]
fn truncate_src_verbatim_when_short_and_boundary_safe_when_long() {
    // len <= n => verbatim, no ellipsis.
    assert_eq!(truncate_src("short", 10), "short");
    assert_eq!(truncate_src("exactly10!", 10), "exactly10!"); // len == n
    assert_eq!(truncate_src("", 4), "");
    // len > n (ASCII) => cut at n + '…'.
    assert_eq!(truncate_src("abcdefghij", 4), "abcd…");
    // len > n landing mid-codepoint => floor to the boundary, never split 'é'.
    // "caféabc" = c a f é(3..5) a b c ; n=4 is mid-'é' -> floor to 3 -> "caf…".
    assert_eq!(truncate_src("caféabc", 4), "caf…");
}

// ── property tiers ───────────────────────────────────────────────────────────

proptest! {
    // Testing Contract: 4k cases; per case = two O(n) boundary scans over a
    // <=~40-byte string — cheap.
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// floor <= idx <= ceil, both land on real char boundaries, floor <= ceil,
    /// and on an existing boundary both collapse to idx.
    #[test]
    fn floor_and_ceil_bracket_idx_on_char_boundaries(s in r"\PC{0,40}", raw in 0usize..64) {
        let idx = raw.min(s.len());
        let f = focus_floor(&s, idx);
        let c = focus_ceil(&s, idx);
        prop_assert!(s.is_char_boundary(f), "floor {f} not a char boundary of {s:?}");
        prop_assert!(s.is_char_boundary(c), "ceil {c} not a char boundary of {s:?}");
        prop_assert!(f <= idx, "floor {f} > idx {idx}");
        prop_assert!(c >= idx, "ceil {c} < idx {idx}");
        prop_assert!(f <= c, "floor {f} > ceil {c}");
        prop_assert!(c <= s.len(), "ceil {c} > len {}", s.len());
        if s.is_char_boundary(idx) {
            prop_assert_eq!(f, idx);
            prop_assert_eq!(c, idx);
        }
    }

    /// truncate_src is verbatim when it fits, otherwise a real char-boundary
    /// prefix of `s` (<= n bytes) with a single trailing `…`.
    #[test]
    fn truncate_src_is_a_bounded_boundary_prefix(s in r"\PC{0,40}", n in 0usize..48) {
        let out = truncate_src(&s, n);
        if s.len() <= n {
            prop_assert_eq!(out, s);
        } else {
            prop_assert!(out.ends_with('…'), "long input {s:?} must be ellipsized, got {out:?}");
            let kept = out.strip_suffix('…').expect("just checked the suffix");
            prop_assert!(s.starts_with(kept), "kept {kept:?} is not a prefix of {s:?}");
            prop_assert!(kept.len() <= n, "kept {} bytes exceeds cap {n}", kept.len());
        }
    }
}
