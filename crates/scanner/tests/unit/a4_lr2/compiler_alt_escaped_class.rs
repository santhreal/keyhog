//! `rewrite_alternation_prefix` must locate the leading group's matching close
//! with the SAME escape- and char-class-aware discipline as
//! `split_top_level_alternatives`: an escaped `\)` or a `)` / `(` inside a
//! `[...]` class is a LITERAL, not a group delimiter.
//!
//! Before the unification the close-finder was a naive `(` / `)` counter (the
//! source comment even called class parens "rare in real detectors"). That let
//! an escaped or classed paren prematurely balance the depth counter and
//! mis-locate the close, so the rewrite spliced a WRONG slice, a silent recall
//! bug (Law 10). These cases pin the corrected behavior.

/// Escaped `\)` inside the alternation body must NOT be mistaken for the group
/// close. The naive scanner stopped at the `\)` and produced the malformed,
/// unbalanced `[a]c)x`; the escape-aware scanner finds the real close and
/// collapses to the matched branch, yielding the correct `[a]x`.
#[test]
fn escaped_close_paren_in_leading_group_is_not_the_group_close() {
    assert_eq!(
        keyhog_scanner::testing::rewrite_alternation_prefix("(?:a|b\\)c)x", "a", "[a]").as_deref(),
        Some("[a]x"),
        "an escaped `\\)` was treated as the group close, splicing a wrong slice"
    );
}

/// A char class carrying an UNbalanced paren (`[)]`) must not corrupt the depth
/// count. The naive scanner counted the classed `)` and closed the group inside
/// the class (finding no `|`, it declined the rewrite entirely, lost
/// acceleration); the class-aware scanner steps over `[...]` and rewrites
/// correctly.
#[test]
fn char_class_close_paren_does_not_prematurely_balance() {
    assert_eq!(
        keyhog_scanner::testing::rewrite_alternation_prefix(
            "(?:x[)]y|abc_z)tail",
            "abc_",
            "[a]bc_"
        )
        .as_deref(),
        Some("[a]bc_ztail"),
        "a `)` inside a `[...]` class was counted as a group delimiter"
    );
}

/// A char class carrying an unbalanced OPEN paren (`[(]`) is the mirror case:
/// the naive scanner over-counted depth and never returned to zero, declining
/// the rewrite; the class-aware scanner rewrites correctly.
#[test]
fn char_class_open_paren_does_not_inflate_depth() {
    assert_eq!(
        keyhog_scanner::testing::rewrite_alternation_prefix(
            "(?:x[(]y|abc_z)tail",
            "abc_",
            "[a]bc_"
        )
        .as_deref(),
        Some("[a]bc_ztail"),
        "a `(` inside a `[...]` class was counted as a group delimiter"
    );
}

/// Non-regression positive control: a plain alternation with no escapes or
/// classes rewrites exactly as before, so the escape/class handling cannot have
/// perturbed the common path.
#[test]
fn plain_alternation_prefix_still_rewrites() {
    assert_eq!(
        keyhog_scanner::testing::rewrite_alternation_prefix("(?:abc|def)tail", "abc", "[a]bc")
            .as_deref(),
        Some("[a]bctail")
    );
}
