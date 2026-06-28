//! Regression: ONE ASCII-fold for every plain (homoglyph) phase-2 matcher.
//!
//! The plain phase-2 patterns run on pure-ASCII chunks as their ASCII-FOLDED
//! form (every non-ASCII codepoint dropped). Three independent sites used to
//! inline `regex.as_str().chars().filter(char::is_ascii).collect::<String>()`:
//!   * `phase2_prefilter::pattern_gate_literals` (the gate's required literals),
//!   * `phase2_prefilter::ascii_folded_sources` (the RegexSet alternate), and
//!   * `phase2_anchor::build` (the shared-anchor localizer's leading literals).
//! Their soundness contract is that ALL THREE fold identically — a folded gate
//! literal that disagreed with the folded matcher would skip a chunk the matcher
//! could still hit (a silent recall loss). The three copies were collapsed into
//! one `engine::phase2::ascii_fold_regex_src`; this pins its exact behaviour so a
//! future edit cannot reintroduce a divergent fold.

use keyhog_scanner::testing::ascii_fold_regex_src_for_test as fold;

#[test]
fn ascii_fold_regex_src_drops_non_ascii_preserving_order() {
    // All-ASCII source is returned byte-for-byte unchanged.
    assert_eq!(fold("sk-[A-Za-z0-9]{20}"), "sk-[A-Za-z0-9]{20}");

    // Homoglyph char class: the Cyrillic dze U+0455 is dropped, the ASCII 's'
    // and the rest of the class survive in order — the canonical [sѕ] -> [s]
    // fold the plain matcher actually compiles.
    assert_eq!(fold("[sѕ]k_live_[0-9]"), "[s]k_live_[0-9]");

    // Interleaved Greek (U+03B1/03B2/03B3) is removed; surrounding ASCII keeps
    // its order.
    assert_eq!(fold("aαbβcγ"), "abc");

    // Fullwidth latin small s (U+FF53) is non-ASCII -> dropped.
    assert_eq!(fold("ｓk-token"), "k-token");

    // Empty in, empty out (no panic, no synthesized bytes).
    assert_eq!(fold(""), "");

    // A source that is ALL non-ASCII folds to empty (the plain matcher would be
    // ungateable -> run unconditionally; the fold itself must not invent bytes).
    assert_eq!(fold("ѕαβ"), "");
}
