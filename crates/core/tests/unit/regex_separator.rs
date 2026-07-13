//! Unit gate for the inter-keyword separator canonicalizer
//! (`keyhog_core::canonicalize_keyword_separators`). Migrated out of `src/` per
//! KH-GAP-004 (no inline `#[cfg(test)]` modules in core src).

use keyhog_core::{canonicalize_keyword_separators, CANONICAL_SEPARATOR};

fn canon(s: &str) -> String {
    canonicalize_keyword_separators(s).into_owned()
}

#[test]
fn every_corpus_separator_form_collapses_to_canonical() {
    // The 17 resolved forms enumerated across the shipped detector corpus 
    // clean and buggy alike (must all become exactly the one canonical class).
    let want = format!("api{CANONICAL_SEPARATOR}key");
    for form in [
        "[_-]?",
        "[_\\s]*",
        "[_\\s]?",
        "[_\\-\\s]?",
        "[_\\-\\s]*",
        "[_-]",
        "[\\\\s_-]?", // over-escaped: literal backslash + s, NOT \s (BUG)
        "[_]*",
        "[_\\-]?",
        "[_-]*",
        "[_\\-\\s]{0,2}",
        "[\\s_-]*",
        "[_\\s-]*",
        "[_\\\\s-]?", // over-escaped (BUG)
        "[_\\s]",
        "[-_]?",
        "[_\\t\\r\\n ]{1,16}",
    ] {
        assert_eq!(
            canon(&format!("api{form}key")),
            want,
            "form {form:?} did not canonicalize"
        );
    }
}

#[test]
fn pure_whitespace_classes_are_left_alone() {
    // Ambiguous with value-assignment spacing (`Key[\s]*:`), must NOT be
    // touched, and must keep its original (here unbounded) quantifier.
    for s in ["Key[\\s]*:", "Key[\\s]:", "header[\\s]*=[\\s]*(.+)"] {
        assert_eq!(canon(s), s, "pure-whitespace {s:?} must be untouched");
    }
}

#[test]
fn non_separator_classes_are_untouched() {
    for s in [
        "[a-z]+",
        "([A-Za-z0-9_\\-]{32,})", // token body, has letters/digits
        "[=:\\s\"']+",            // value assignment, has = : " '
        "\\b(?:avaya)\\b",        // no class at all
        "[0-9a-f]{32}",           // hex body
        "(?:KEY|key)[\\d]{4}",    // \d is not a separator
    ] {
        assert_eq!(canon(s), s, "{s:?} must be untouched");
    }
}

#[test]
fn negated_class_is_not_a_separator() {
    assert_eq!(canon("a[^_-]b"), "a[^_-]b");
}

#[test]
fn escaped_bracket_is_not_a_class() {
    // `\[` is a literal '['; the `[_-]?` after it is still canonicalized.
    assert_eq!(canon("a\\[b[_-]?c"), format!("a\\[b{CANONICAL_SEPARATOR}c"));
}

#[test]
fn multiple_separators_in_one_regex_all_canonicalize() {
    let s = &CANONICAL_SEPARATOR;
    assert_eq!(
        canon("(?:google[_\\-\\s]?meet|gmeet)[_\\s]?(?:api[_-]?key)"),
        format!("(?:google{s}meet|gmeet){s}(?:api{s}key)")
    );
}

#[test]
fn idempotent() {
    let once = canon("api[_\\s]?key");
    assert_eq!(once, format!("api{CANONICAL_SEPARATOR}key"));
    assert_eq!(canon(&once), once, "canonical form must be a fixed point");
}

#[test]
fn unchanged_input_is_borrowed() {
    use std::borrow::Cow;
    assert!(matches!(
        canonicalize_keyword_separators("AKIA[0-9A-Z]{16}"),
        Cow::Borrowed(_)
    ));
}

#[test]
fn non_ascii_literal_is_preserved() {
    // A regex carrying a multibyte literal must round-trip byte-exact while a
    // separator elsewhere is still canonicalized.
    assert_eq!(
        canon("café[_-]?key"),
        format!("café{CANONICAL_SEPARATOR}key")
    );
}

#[test]
fn the_canonical_class_compiles_and_matches_real_spacings() {
    // Guard the canonical string itself: a valid regex that matches no-sep,
    // single, double, tab, hyphen, and underscore spacings between words.
    let re = regex::Regex::new(&format!("api{CANONICAL_SEPARATOR}key")).unwrap();
    for s in [
        "apikey",
        "api key",
        "api  key",
        "api\tkey",
        "api-key",
        "api_key",
        "api__key",
        "api - key",
    ] {
        assert!(re.is_match(s), "canonical must match {s:?}");
    }
    assert!(
        !re.is_match("apiXkey"),
        "must not bridge a non-separator byte"
    );
}

#[test]
fn deepnote_style_nested_separator_canonicalizes_to_unbounded() {
    // deepnote nests a bounded separator inside a counted `(?:…){1,3}` anchor. It
    // must still collapse to the canonical (unbounded) form; the complexity
    // validator's acceptance of an unbounded simple-class repeat nested in a
    // counted group is covered by `validate.rs`.
    let out = canon("(?:DEEPNOTE)(?:[_\\t\\r\\n ]{1,16}(?:API|KEY)){1,3}");
    assert!(
        out.contains(CANONICAL_SEPARATOR),
        "separator must be canonicalized: {out}"
    );
    assert!(
        !out.contains("{1,16}"),
        "the bounded separator must be replaced: {out}"
    );
}
