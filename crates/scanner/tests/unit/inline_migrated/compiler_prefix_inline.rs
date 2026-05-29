use keyhog_scanner::testing::compiler_prefix::{
    extract_literal_prefixes, strip_leading_boundary_guard, strip_leading_inline_flags,
};

#[test]
fn plain_alternation_prefix_extracts_both_arms() {
    // The classic shape - unchanged by the boundary-guard / flag work.
    assert_eq!(
        extract_literal_prefixes("(AKIA|ASIA)[0-9A-Z]{16}"),
        vec!["AKIA".to_string(), "ASIA".to_string()]
    );
}

#[test]
fn simple_literal_prefix_extracts() {
    assert_eq!(
        extract_literal_prefixes("AIza[0-9A-Za-z_-]{35}"),
        vec!["AIza".to_string()]
    );
}

#[test]
fn boundary_guard_idiom_extracts_the_inner_literal() {
    // `(?:^|[^...])(LITERAL...)` is the helicone/deepnote shape: the guard
    // carries no literal, but the captured token's prefix must still reach
    // the AC set or the detector falls dead to the keyword fallback.
    assert_eq!(
        extract_literal_prefixes("(?:^|[^A-Za-z0-9_])(sk-[a-zA-Z0-9]{20,})"),
        vec!["sk-".to_string()]
    );
    assert_eq!(
        extract_literal_prefixes("(?:^|[^A-Za-z0-9_])(dn_[a-zA-Z0-9_-]{20,})"),
        vec!["dn_".to_string()]
    );
}

#[test]
fn negative_case_flag_then_alternation_extracts() {
    // The exact AWS shape after the case-sensitivity fix: `(?-i)` must be
    // stripped as a leading flag so the alternation arms still extract.
    assert_eq!(
        extract_literal_prefixes("(?-i)(AKIA|ASIA)[0-9A-Z]{16}"),
        vec!["AKIA".to_string(), "ASIA".to_string()]
    );
}

#[test]
fn negative_case_flag_then_boundary_guard_extracts() {
    // Both mechanisms composed: `(?-i)` + boundary guard + inner literal.
    assert_eq!(
        extract_literal_prefixes("(?-i)(?:^|[^A-Za-z0-9_])(sk-[a-zA-Z0-9]{20,})"),
        vec!["sk-".to_string()]
    );
}

#[test]
fn strip_inline_flags_handles_positive_and_negative_forms() {
    assert_eq!(strip_leading_inline_flags("(?i)abc"), "abc");
    assert_eq!(strip_leading_inline_flags("(?-i)abc"), "abc");
    assert_eq!(strip_leading_inline_flags("(?im)abc"), "abc");
    assert_eq!(strip_leading_inline_flags("(?im-sx)abc"), "abc");
    // A non-capturing group is NOT a leading flag directive - leave it.
    assert_eq!(strip_leading_inline_flags("(?:abc)"), "(?:abc)");
    // A scoped flag group `(?-i:...)` is a group, not a directive - leave it.
    assert_eq!(strip_leading_inline_flags("(?-i:abc)"), "(?-i:abc)");
    // No leading flags - untouched.
    assert_eq!(strip_leading_inline_flags("abc"), "abc");
}

#[test]
fn strip_boundary_guard_only_for_real_guards() {
    // Real guard: stripped, remainder returned.
    assert_eq!(
        strip_leading_boundary_guard("(?:^|[^A-Za-z0-9_])(sk-x)"),
        Some("(sk-x)")
    );
    // A genuine literal alternation is NOT a boundary guard - don't strip.
    assert_eq!(strip_leading_boundary_guard("(?:foo|bar)x"), None);
    // No leading `(?:` group at all.
    assert_eq!(strip_leading_boundary_guard("AKIA[0-9]{16}"), None);
}
