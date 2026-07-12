//! Migrated from src/compiler.rs & src/compiler/compiler_prefix.rs

use keyhog_scanner::testing::{
    expand_homoglyphs, extract_inner_literals, extract_literal_prefixes,
    match_proves_keyword_nearby, rewrite_alternation_prefix, rewrite_homoglyph_literal_prefix,
    split_leading_inline_flag,
};

#[test]
fn alternation_rewrite_basic() {
    let out = rewrite_alternation_prefix("(?:ghp_|github_pat_)[a-zA-Z0-9_]{36}", "ghp_", "[gɡ]hp_");
    assert_eq!(out.unwrap(), "[gɡ]hp_[a-zA-Z0-9_]{36}");
}

#[test]
fn alternation_rewrite_with_inline_flag() {
    let out = rewrite_alternation_prefix(
        "(?i)(?:ghp_|github_pat_)[a-zA-Z0-9_]{36}",
        "ghp_",
        "[gɡ]hp_",
    );
    assert_eq!(out.unwrap(), "(?i)[gɡ]hp_[a-zA-Z0-9_]{36}");
}

#[test]
fn alternation_rewrite_with_alternative_flag_prefix() {
    let out = rewrite_alternation_prefix("(?i:abc|def)\\w+", "abc", "[a]bc");
    assert_eq!(out.unwrap(), "[a]bc\\w+");
}

#[test]
fn alternation_rewrite_handles_nested_groups() {
    // Inner `(\d+)` should not confuse the depth tracker.
    let out = rewrite_alternation_prefix("(?:abc(?:\\d{2})|def)body", "abc", "[a]bc");
    assert_eq!(out.unwrap(), "[a]bc(?:\\d{2})body");
}

#[test]
fn alternation_rewrite_preserves_branch_local_suffix() {
    let out = rewrite_alternation_prefix(
        "(?:-----BEGIN RSA PRIVATE KEY-----[\\s\\S]*?-----END RSA PRIVATE KEY-----|-----BEGIN EC PRIVATE KEY-----[\\s\\S]*?-----END EC PRIVATE KEY-----)",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----B[EΕ]GIN [EΕ]C PRIV[AΑ]T[EΕ] K[EΕ]Y-----",
    );
    assert_eq!(
        out.unwrap(),
        "-----B[EΕ]GIN [EΕ]C PRIV[AΑ]T[EΕ] K[EΕ]Y-----[\\s\\S]*?-----END EC PRIVATE KEY-----"
    );
}

#[test]
fn alternation_rewrite_returns_none_for_literal_head() {
    // No leading group → caller should fall through to strip_prefix.
    let out = rewrite_alternation_prefix("AKIA[A-Z0-9]{16}", "AKIA", "[a]kia");
    assert!(out.is_none());
}

#[test]
fn alternation_rewrite_returns_none_for_capturing_full_pattern() {
    // `(FLWSECK_(?:TEST|LIVE)-[a-f0-9]{32,64}-X)` is a CAPTURING group
    // around the full credential, not an alternation of prefixes.
    // Rewriting it would silently drop the credential body and leave
    // just the expanded prefix matching anywhere in the chunk - the
    // exact bug that caused flutterwave-api-key to fire on prose
    // `FLWSECK_TEST-short-X`. Refuse to rewrite capturing groups.
    let out = rewrite_alternation_prefix(
        "(FLWSECK_(?:TEST|LIVE)-[a-f0-9]{32,64}-X)",
        "FLWSECK_TEST-",
        "FLW[SСＳ]ECK_TEST-",
    );
    assert!(
        out.is_none(),
        "must not rewrite a capturing-group-around-full-credential; \
         a non-None result here matches the prefix anywhere"
    );
}

#[test]
fn alternation_rewrite_returns_none_for_singleton_group() {
    // `(?:foobody)` has no `|` so it's not an alternation; rewriting
    // would silently drop the `body` part. Refuse.
    let out = rewrite_alternation_prefix("(?:foobody)tail", "foo", "[fF]oo");
    assert!(out.is_none());
}

#[test]
fn split_leading_inline_flag_parses_common_shapes() {
    assert_eq!(split_leading_inline_flag("(?i)body"), ("(?i)", "body"));
    assert_eq!(split_leading_inline_flag("(?-i)body"), ("(?-i)", "body"));
    assert_eq!(split_leading_inline_flag("(?im)body"), ("(?im)", "body"));
    assert_eq!(split_leading_inline_flag("(?ims)body"), ("(?ims)", "body"));
    assert_eq!(split_leading_inline_flag("body"), ("", "body"));
    assert_eq!(
        split_leading_inline_flag("(?:abc|def)body"),
        ("", "(?:abc|def)body")
    );
}

#[test]
fn homoglyph_rewrite_preserves_negative_inline_flag() {
    let out = rewrite_homoglyph_literal_prefix("(?-i)ghp_[A-Za-z0-9_]{36}", "ghp_", "[gɡ]hp_");
    assert_eq!(out.as_deref(), Some("(?-i)[gɡ]hp_[A-Za-z0-9_]{36}"));
}

#[test]
fn homoglyph_rewrite_consumes_escaped_literal_prefix() {
    let out = rewrite_homoglyph_literal_prefix(r"\+KEY[A-Z0-9]{8}", "+KEY", r"[\+＋]K[EЕ]Y");
    assert_eq!(out.as_deref(), Some(r"[\+＋]K[EЕ]Y[A-Z0-9]{8}"));
}

#[test]
fn homoglyph_rewrite_escapes_regex_metachar_literal_prefix() {
    let expanded = expand_homoglyphs("?sv=");
    assert_eq!(expanded, r"\?[sѕｓ]v=");
    let out = rewrite_homoglyph_literal_prefix(
        r#"(\?sv=\d{4}-\d{2}-\d{2}&[^\s"'']*sig=[a-zA-Z0-9%]{20,})"#,
        "?sv=",
        &expanded,
    )
    .expect("capturing-group literal prefix should rewrite");
    assert!(regex::Regex::new(&out).is_ok(), "generated regex: {out}");
    assert!(
        !out.starts_with("(?["),
        "expanded literal question mark must stay escaped after group open: {out}"
    );
}

#[test]
fn homoglyph_rewrite_preserves_boundary_guard_and_wrapping_group() {
    let out = rewrite_homoglyph_literal_prefix(
        r"(?:^|[^A-Za-z0-9_])(ghp_[A-Za-z0-9_]{36})",
        "ghp_",
        "[gɡ]hp_",
    );
    assert_eq!(
        out.as_deref(),
        Some(r"(?:^|[^A-Za-z0-9_])([gɡ]hp_[A-Za-z0-9_]{36})")
    );
}

#[test]
fn inner_literal_after_leading_class() {
    let lits = extract_inner_literals(r"[a-zA-Z0-9]{20}_AKIA[A-Z0-9]{16}");
    assert_eq!(lits, vec!["_AKIA"]);
}

#[test]
fn inner_literal_alternation_branches() {
    let lits = extract_inner_literals(r"(?:secret|api_key)\s*=\s*[a-z0-9]{32}");
    // Both branches produce candidates; both meet the 4-char floor.
    assert!(lits.iter().any(|s| s == "secret"));
    assert!(lits.iter().any(|s| s == "api_key"));
}

#[test]
fn inner_literal_refuses_partially_covered_alternation() {
    assert!(
        extract_inner_literals(r"(?:DD.API.KEY|DATADOG.API.KEY)[=:\s]+[a-f0-9]{32}").is_empty()
    );
}

#[test]
fn inner_literal_pure_class_yields_empty() {
    assert!(extract_inner_literals(r"[a-f0-9]{32}").is_empty());
}

#[test]
fn inner_literal_below_threshold_dropped() {
    // `wx` is only 2 chars - below MIN_INNER_LITERAL_CHARS.
    assert!(extract_inner_literals(r"wx[a-f0-9]{16}").is_empty());
}

#[test]
fn inner_literal_handles_escaped_dot() {
    // `https?://[^/]+\.lambda-url\.[a-z0-9-]+\.on\.aws/...`
    // The contiguous-literal extractor flushes on each character class
    // and assertion, so the longest run is `.lambda-url.` (no - that's
    // broken by `\.`-then-`-`-then-class). Actual longest: `.lambda-url`.
    let lits = extract_inner_literals(r"https?://[^/]+\.lambda-url\.[a-z]+\.on\.aws/path");
    // Verify we extract SOMETHING substantive for this real-world AWS pattern.
    assert!(
        lits.iter().any(|s| s.contains("lambda-url")),
        "expected lambda-url in inner literals; got {lits:?}"
    );
}

#[test]
fn literal_prefix_drops_optional_literal_suffix() {
    let prefixes = extract_literal_prefixes(r"https?://[a-z0-9.-]+\.example\.com/[A-Za-z0-9]+");
    assert_eq!(
        prefixes,
        vec!["http"],
        "AC prefix must be the guaranteed scheme bytes so http and https both route"
    );
}

#[test]
fn literal_prefix_drops_optional_group_suffix() {
    assert_eq!(
        extract_literal_prefixes(r"genesys(?:_cloud)?[_\s]client"),
        vec!["genesys".to_string()]
    );
}

#[test]
fn boundary_guarded_captured_url_uses_earliest_scheme_prefix() {
    let prefixes = extract_literal_prefixes(
        r"(?:^|[^A-Za-z0-9_])(https?://[a-zA-Z0-9._-]+\.zksync\.[a-z]+/[a-zA-Z0-9_-]+)(?:$|[^A-Za-z0-9_-])",
    );
    assert_eq!(
        prefixes,
        vec!["http"],
        "captured service URLs must route from the match start, not a later host literal"
    );
}

#[test]
fn inner_literal_dedup() {
    // `(?:KEY|KEY|other)foo` → "KEY" should appear once even if both
    // literal alternatives emit it.
    let lits = extract_inner_literals(r"(?:KEYY|KEYY|other)foo");
    let key_count = lits.iter().filter(|s| *s == "KEYY").count();
    assert!(key_count <= 1, "expected dedup; got {lits:?}");
}

#[test]
fn inner_literal_garbage_regex_returns_empty() {
    assert!(extract_inner_literals(r"[unclosed").is_empty());
}

#[test]
fn keyword_signal_proof_requires_all_prefixes_to_start_with_detector_keyword() {
    let stripe_keywords = vec![
        "sk_live_".to_string(),
        "sk_test_".to_string(),
        "rk_live_".to_string(),
        "rk_test_".to_string(),
    ];
    assert!(match_proves_keyword_nearby(
        r"(?:sk_live_|sk_test_)[a-zA-Z0-9]{24,}",
        &stripe_keywords
    ));

    let mixed_keywords = vec!["sk_live_".to_string()];
    assert!(!match_proves_keyword_nearby(
        r"(?:sk_live_|rk_live_)[a-zA-Z0-9]{24,}",
        &mixed_keywords
    ));

    assert!(!match_proves_keyword_nearby(
        r"[a-zA-Z0-9]{20}",
        &stripe_keywords
    ));
}

/// Quantify how many embedded detectors move from fallback to AC
/// thanks to the inner-literal extractor. Acts both as a regression
/// guard (the count shouldn't drop) and as documentation of the
/// optimization's reach. Run with `--nocapture` to print the count.
#[test]
fn inner_literal_corpus_coverage() {
    let mut promoted_patterns = 0usize;
    let mut total_inner_literals = 0usize;
    let mut total_patterns = 0usize;
    for d in
        keyhog_core::load_embedded_detectors_or_fail().expect("embedded detector corpus must load")
    {
        for p in &d.patterns {
            total_patterns += 1;
            let prefixes = extract_literal_prefixes(&p.regex);
            if !prefixes.is_empty() {
                continue; // Already AC-eligible via prefix.
            }
            let inner = extract_inner_literals(&p.regex);
            if !inner.is_empty() {
                promoted_patterns += 1;
                total_inner_literals += inner.len();
            }
        }
    }
    assert!(
        promoted_patterns >= 3,
        "expected ≥3 patterns promoted out of fallback via inner-literal extraction; \
         got {promoted_patterns} (of {total_patterns} total)"
    );
    eprintln!(
        "inner-literal coverage: {promoted_patterns} patterns promoted out of fallback, \
         {total_inner_literals} inner literals added (of {total_patterns} total patterns)"
    );
}
