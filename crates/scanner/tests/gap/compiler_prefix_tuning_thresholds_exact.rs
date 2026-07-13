//! Gap test: the prefix-compiler's four literal-extraction tuning thresholds
//! have exact, pinned values.
//!
//! These four constants jointly bound how the compiler turns detector regexes
//! into the Aho-Corasick prefilter set, the recall/precision tradeoff of the
//! whole fast path:
//!   - MIN_HOMOGLYPH_PREFIX_LEN (3): shortest literal prefix worth a homoglyph
//!     phase-2 variant;
//!   - MIN_INNER_LITERAL_CHARS (4): shortest standalone inner literal kept in
//!     the AC set;
//!   - MIN_DISTINCTIVE_INFIX_CHARS (8): shortest required-literal run that makes
//!     a pattern "distinctive";
//!   - MAX_CHARCLASS_PREFIX_EXPANSION (8): widest char class still enumerated
//!     into AC prefixes before it is treated as a body matcher.
//!
//! Before this, the homoglyph threshold was a bare `3` literal (unlike its three
//! named siblings) and NONE of the four had its exact value pinned, a silent
//! drift of any of them would shift prefilter recall with no failing test. Also
//! pin the one real cross-threshold invariant: the homoglyph prefix floor is
//! strictly below the standalone-inner-literal floor (a homoglyph variant still
//! requires the rest of the regex to match, so it can be shorter; an inner
//! literal stands alone and needs more distinctiveness).

use keyhog_scanner::testing::{
    compiler_max_charclass_prefix_expansion_for_test,
    compiler_min_distinctive_infix_chars_for_test, compiler_min_homoglyph_prefix_len_for_test,
    compiler_min_inner_literal_chars_for_test,
};

#[test]
fn homoglyph_prefix_floor_is_three() {
    assert_eq!(compiler_min_homoglyph_prefix_len_for_test(), 3);
}

#[test]
fn inner_literal_floor_is_four() {
    assert_eq!(compiler_min_inner_literal_chars_for_test(), 4);
}

#[test]
fn distinctive_infix_floor_is_eight() {
    assert_eq!(compiler_min_distinctive_infix_chars_for_test(), 8);
}

#[test]
fn charclass_prefix_expansion_cap_is_eight() {
    assert_eq!(compiler_max_charclass_prefix_expansion_for_test(), 8);
}

#[test]
fn homoglyph_prefix_floor_is_strictly_below_inner_literal_floor() {
    assert!(
        compiler_min_homoglyph_prefix_len_for_test() < compiler_min_inner_literal_chars_for_test(),
        "a homoglyph variant splices back into the full regex, so its prefix floor \
         must stay below the standalone inner-literal floor"
    );
}
