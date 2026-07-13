use keyhog_scanner::testing::compiler_prefix::{
    extract_literal_prefixes, strip_leading_boundary_guard, strip_leading_inline_flags,
};

// Symbols re-exported through the doc-hidden `testing::compiler_prefix` facade
// for the inner-literal corpus suites migrated out of `compiler_prefix.rs`
// (no-inline-tests gate). The facade keeps these crate-private rather than
// widening the public API for white-box test placement.
use keyhog_scanner::testing::compiler_prefix::{
    expand_leading_charclass_prefixes, expand_leading_literal_alternation_with_tail,
    extract_literal_prefix, leading_literal_run, regex_has_required_literal_run,
    strip_leading_zero_width_assertions, MAX_CHARCLASS_PREFIX_EXPANSION,
    MIN_DISTINCTIVE_INFIX_CHARS,
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
    // the AC set or the detector falls dead to the phase-2 keyword lane.
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

#[test]
fn boundary_guard_with_escaped_class_bracket_extracts_inner_literal() {
    assert_eq!(
        strip_leading_boundary_guard(r"(?:^|[^\]])(ghp_token)"),
        Some("(ghp_token)")
    );
    assert_eq!(
        extract_literal_prefixes(r"(?:^|[^\]])(ghp_[A-Za-z0-9]{36})"),
        vec!["ghp_".to_string()]
    );
}

mod charclass_prefix_expansion_tests {
    use super::*;

    #[test]
    fn deno_kv_class_expands_to_one_prefix_per_member() {
        // `dd[npc]_[a-f0-9]{64}` carries no extractable single prefix (`dd` is
        // sub-floor), but each concrete branch is a clean ≥3-char literal.
        let got = expand_leading_charclass_prefixes("dd[npc]_[a-f0-9]{64}");
        assert_eq!(
            got,
            Some(vec!["ddn_".to_string(), "ddp_".to_string(), "ddc_".to_string()]),
            "the class members must expand IN ORDER, each extended past the class to the trailing `_`"
        );
    }

    #[test]
    fn plural_extractor_routes_deno_kv_through_the_expansion() {
        // End-to-end through the public plural extractor: the singular path
        // yields nothing, so the char-class fallback must supply the triggers.
        let got = extract_literal_prefixes("dd[npc]_[a-f0-9]{64}");
        assert_eq!(
            got,
            vec!["ddn_".to_string(), "ddp_".to_string(), "ddc_".to_string()]
        );
    }

    #[test]
    fn clean_leading_prefix_is_untouched_by_the_fallback() {
        // A detector with a normal literal prefix must still route through the
        // singular extractor and never reach the char-class fallback.
        assert_eq!(extract_literal_prefixes("AKIA[0-9A-Z]{16}"), vec!["AKIA"]);
        assert_eq!(
            extract_literal_prefixes("(?-i)cs_[a-z0-9]{32}"),
            vec!["cs_"]
        );
    }

    #[test]
    fn ranges_negation_and_perl_classes_are_not_enumerated() {
        // A range (`[a-f]`), a negation (`[^x]`), and a leading body matcher
        // are bodies, not enumerable prefixes (declined, no triggers emitted).
        assert_eq!(expand_leading_charclass_prefixes("dd[a-f]_[0-9]{8}"), None);
        assert_eq!(expand_leading_charclass_prefixes("dd[^np]_[0-9]{8}"), None);
        assert_eq!(expand_leading_charclass_prefixes("[a-z]{20}"), None);
    }

    #[test]
    fn oversized_class_is_declined() {
        // A class wider than MAX_CHARCLASS_PREFIX_EXPANSION is a body matcher;
        // enumerating it would flood the AC set.
        let wide: String = ('a'..='z')
            .take(MAX_CHARCLASS_PREFIX_EXPANSION + 1)
            .collect();
        let pattern = format!("xy[{wide}]_[0-9]{{8}}");
        assert_eq!(expand_leading_charclass_prefixes(&pattern), None);
    }

    #[test]
    fn sub_floor_branch_refuses_the_whole_expansion() {
        // Head is empty and the trailing literal is one char, so every branch
        // would be 2 chars, below the floor. Partial coverage is unsafe, so
        // the entire expansion is refused (no dead branches in AC).
        assert_eq!(expand_leading_charclass_prefixes("[npc]x[0-9]{8}"), None);
    }

    #[test]
    fn underscore_member_is_a_valid_literal() {
        // `_` is a legitimate enumerable member (e.g. `sk[_-]live`-style).
        let got = expand_leading_charclass_prefixes("sk[_x]live[0-9]{8}");
        assert_eq!(
            got,
            Some(vec!["sk_live".to_string(), "skxlive".to_string()])
        );
    }
}

mod zero_width_assertion_strip_tests {
    use super::*;

    #[test]
    fn leading_word_boundary_is_stripped() {
        assert_eq!(strip_leading_zero_width_assertions(r"\bser\.x"), r"ser\.x");
        assert_eq!(strip_leading_zero_width_assertions(r"\BAKIA"), "AKIA");
        assert_eq!(strip_leading_zero_width_assertions(r"\Atoken"), "token");
        assert_eq!(strip_leading_zero_width_assertions("^AKIA"), "AKIA");
    }

    #[test]
    fn multiple_assertions_are_all_stripped_order_free() {
        assert_eq!(strip_leading_zero_width_assertions(r"^\bAKIA"), "AKIA");
        assert_eq!(strip_leading_zero_width_assertions(r"\b\BAKIA"), "AKIA");
    }

    #[test]
    fn non_assertion_is_untouched() {
        assert_eq!(strip_leading_zero_width_assertions(r"\d{4}"), r"\d{4}");
        assert_eq!(strip_leading_zero_width_assertions("AKIA"), "AKIA");
    }

    #[test]
    fn flagsmith_word_boundary_prefix_is_recovered() {
        // `\bser\.[a-zA-Z0-9]{40,}`: the leading `\b` previously broke
        // extraction at the first byte; now `ser.` is the recovered prefix.
        assert_eq!(
            extract_literal_prefixes(r"\bser\.[a-zA-Z0-9]{40,}"),
            vec!["ser.".to_string()]
        );
        // Singular form must agree (it feeds `has_literal_prefix`).
        assert_eq!(
            extract_literal_prefix(r"\bser\.[a-zA-Z0-9]{40,}"),
            Some("ser.".to_string())
        );
    }
}

mod literal_alternation_tail_tests {
    use super::*;

    #[test]
    fn locationiq_alternation_carries_the_trailing_dot() {
        // `(?:pk|sk)\.[a-f0-9]{32,}`: `pk`/`sk` are sub-floor alone; carrying
        // the post-group `\.` recovers the real `pk.`/`sk.` discriminators.
        assert_eq!(
            extract_literal_prefixes(r"(?:pk|sk)\.[a-f0-9]{32,}"),
            vec!["pk.".to_string(), "sk.".to_string()]
        );
    }

    #[test]
    fn capturing_group_alternation_also_extends() {
        assert_eq!(
            expand_leading_literal_alternation_with_tail(r"(pk|sk)\.[a-f0-9]{8}"),
            Some(vec!["pk.".to_string(), "sk.".to_string()])
        );
    }

    #[test]
    fn no_trailing_literal_is_declined() {
        // Nothing to carry past the group ⇒ this fallback adds nothing.
        assert_eq!(
            expand_leading_literal_alternation_with_tail("(?:pk|sk)[a-f0-9]{8}"),
            None
        );
    }

    #[test]
    fn structured_branch_is_declined() {
        // A branch with a nested construct (`ab[0-9]`) is not a pure literal
        // run, so the post-group tail would not abut its literal head.
        assert_eq!(
            expand_leading_literal_alternation_with_tail(r"(?:ab[0-9]|cd)\.x"),
            None
        );
    }

    #[test]
    fn already_sufficient_alternation_keeps_the_existing_path() {
        // `(AKIA|ASIA)` branches already clear the floor, so the per-branch
        // alternation path handles them and the tail fallback is never reached.
        assert_eq!(
            extract_literal_prefixes("(AKIA|ASIA)[0-9]{12}"),
            vec!["AKIA".to_string(), "ASIA".to_string()]
        );
    }

    #[test]
    fn leading_literal_run_unescapes_dot_and_stops_at_class() {
        assert_eq!(leading_literal_run(r"\.[a-f0-9]"), ".");
        assert_eq!(leading_literal_run("_x[0-9]"), "_x");
        // A bare `.` is the any-char metachar and stops the run.
        assert_eq!(leading_literal_run(".abc"), "");
    }
}

mod required_literal_run_tests {
    use super::*;

    #[test]
    fn terraform_atlasv1_infix_is_a_required_run() {
        // `.atlasv1.` (9 chars) is required by every match even though the
        // regex opens with a class and captures the whole token.
        assert!(regex_has_required_literal_run(
            r"[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9]{67,}",
            MIN_DISTINCTIVE_INFIX_CHARS
        ));
    }

    #[test]
    fn short_or_absent_required_literal_is_not_distinctive() {
        // A pure char-class body has no required literal run.
        assert!(!regex_has_required_literal_run("[a-f0-9]{32}", 8));
        // `_live_` (6) is below the distinctive threshold.
        assert!(!regex_has_required_literal_run(
            r"sk[a-z]{4}_live_[0-9]{20}",
            8
        ));
    }

    #[test]
    fn literal_inside_alternation_is_not_required() {
        // Only one branch matches, so neither `atlasv1x` nor `betaaaaa` is
        // guaranteed (must NOT count as required).
        assert!(!regex_has_required_literal_run(
            r"[0-9]{4}(?:atlasv1x|betaaaaa)?[0-9]{4}",
            8
        ));
        assert!(!regex_has_required_literal_run(
            r"(?:atlasv1x|betbbbbb)[0-9]{4}",
            8
        ));
    }

    #[test]
    fn literal_inside_required_group_is_counted() {
        // A required (non-optional) group is always entered, so its internal
        // run counts.
        assert!(regex_has_required_literal_run(
            r"[0-9]{4}(?:\.atlasv1\.)[0-9]{4}",
            8
        ));
    }

    #[test]
    fn optional_group_literal_is_not_required() {
        // The `?` makes the group optional (its run is not guaranteed).
        assert!(!regex_has_required_literal_run(
            r"[0-9]{4}(?:\.atlasv1\.)?[0-9]{4}",
            8
        ));
    }
}
