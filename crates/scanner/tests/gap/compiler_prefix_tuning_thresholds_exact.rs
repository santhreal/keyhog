//! Gap test: the prefix-compiler's literal-extraction tuning thresholds
//! have exact, pinned values.
//!
//! These constants jointly bound how the compiler turns detector regexes
//! into the Aho-Corasick prefilter set, the recall/precision tradeoff of the
//! whole fast path:
//!   - MIN_HOMOGLYPH_PREFIX_LEN (3): shortest literal prefix worth a homoglyph
//!     phase-2 variant;
//!   - MIN_DISTINCTIVE_INFIX_CHARS (8): shortest required-literal run that makes
//!     a pattern "distinctive";
//!   - MAX_CHARCLASS_PREFIX_EXPANSION (8): widest char class still enumerated
//!     into AC prefixes before it is treated as a body matcher.

use keyhog_scanner::testing::{
    compiler_max_charclass_prefix_expansion_for_test,
    compiler_min_distinctive_infix_chars_for_test, compiler_min_homoglyph_prefix_len_for_test,
};

#[test]
fn homoglyph_prefix_floor_is_three() {
    assert_eq!(compiler_min_homoglyph_prefix_len_for_test(), 3);
}

#[test]
fn distinctive_infix_floor_is_eight() {
    assert_eq!(compiler_min_distinctive_infix_chars_for_test(), 8);
}

#[test]
fn charclass_prefix_expansion_cap_is_eight() {
    assert_eq!(compiler_max_charclass_prefix_expansion_for_test(), 8);
}
