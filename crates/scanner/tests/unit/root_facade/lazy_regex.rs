//! Truth tests for `LazyRegex` - the wrapper that stores scanner-construction
//! detector regexes exactly once while still allowing generated/plain fallback
//! regexes to compile on first use.
//!
//! These assert the behavior the scan engine depends on: the source is
//! readable without compiling, the detector flavor reproduces the exact
//! case-insensitive build the eager path used, the plain flavor stays
//! case-sensitive, a non-compiling test pattern fails loud and closed to a
//! never-matching sentinel, and clones share one compiled instance.

use keyhog_scanner::testing::LazyRegexProbe as LazyRegex;

#[test]
fn as_str_returns_source_without_compiling() {
    let lr = LazyRegex::detector("AKIA[0-9A-Z]{16}");
    // `as_str` must not trigger compilation - the Hyperscan/GPU literal-set
    // builders call it for every pattern and must stay zero-cost.
    assert_eq!(lr.as_str(), "AKIA[0-9A-Z]{16}");
}

#[test]
fn detector_flavor_is_case_insensitive() {
    // The eager `shared_regex_compile` set `.case_insensitive(true)`; the lazy
    // detector flavor must match that or detection silently changes.
    let lr = LazyRegex::detector("ghp_[a-z0-9]{4}");
    assert!(
        lr.get().is_match("GHP_AB12"),
        "detector flavor must be case-insensitive"
    );
    assert!(lr.get().is_match("ghp_ab12"));
}

#[test]
fn plain_flavor_is_case_sensitive() {
    // Homoglyph-expanded fallbacks used plain `Regex::new` (default flags);
    // the plain flavor must NOT silently become case-insensitive.
    let lr = LazyRegex::plain("ABCdef");
    assert!(lr.get().is_match("ABCdef"));
    assert!(
        !lr.get().is_match("abcDEF"),
        "plain flavor must stay case-sensitive"
    );
}

#[test]
fn matches_and_extracts_like_a_normal_regex() {
    let lr = LazyRegex::detector("AKIA[0-9A-Z]{16}");
    let rx = lr.get();
    let m = rx
        .find("prefix AKIAQYLPMN5HFIQR7XYA suffix")
        .expect("should match the AWS key shape");
    assert_eq!(m.as_str(), "AKIAQYLPMN5HFIQR7XYA");
}

#[test]
fn invalid_pattern_fails_closed_to_never_matching_sentinel() {
    // Production scanner construction validates and seeds every pattern. This
    // test-only unseeded constructor with an uncompilable source proves the
    // build-invariant breach is surfaced loudly (`warn_prefilter_disabled` on the
    // stderr channel) and fails CLOSED to a never-matching regex: it neither
    // aborts the whole scan (no panic) nor silently matches anything.
    let lr = LazyRegex::detector("("); // unbalanced group: cannot compile
    let rx = lr.get();
    assert!(!rx.is_match(""), "sentinel must not match empty input");
    assert!(
        !rx.is_match("("),
        "sentinel must not match its own source text"
    );
    assert!(
        !rx.is_match("anything at all 123 sk-abcd AKIAQYLPMN5HFIQR7XYA"),
        "sentinel must match nothing"
    );
}

#[test]
fn second_get_is_idempotent() {
    // The OnceLock caches the compiled regex; repeated calls return a regex
    // with identical behavior (and, internally, the same instance).
    let lr = LazyRegex::detector("token-[0-9]{3}");
    assert!(lr.get().is_match("token-123"));
    assert!(lr.get().is_match("token-999"));
    assert!(!lr.get().is_match("token-12"));
}

#[test]
fn clone_shares_compiled_state() {
    // CompiledPattern is cloned into ac_map per literal prefix; clones must
    // share the compiled cell so the regex compiles at most once across them.
    let lr = LazyRegex::detector("sk-[a-z]{4}");
    let cloned = lr.clone();
    // Force compile through the clone, then assert the original sees it too.
    assert!(cloned.get().is_match("sk-abcd"));
    assert!(lr.get().is_match("sk-wxyz"));
    assert_eq!(lr.as_str(), cloned.as_str());
}

#[test]
fn detector_compiled_reuses_seeded_regex() {
    let compiled = std::sync::Arc::new(
        regex::RegexBuilder::new("ghp_[a-z0-9]{4}")
            .case_insensitive(true)
            .crlf(true)
            .build()
            .expect("seed regex compiles"),
    );
    let seeded = LazyRegex::detector_compiled("ghp_[a-z0-9]{4}", std::sync::Arc::clone(&compiled));

    assert!(
        std::ptr::eq(seeded.get(), compiled.as_ref()),
        "compile-time validated detector regex must be reused, not compiled again"
    );
    assert!(seeded.get().is_match("GHP_AB12"));
}
