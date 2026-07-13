//! A leading bare inline-flag group (`(?i)`, `(?-i)`, `(?im)`) sets match modes
//! but consumes no input, so BOTH prefix extractors must strip it and reach the
//! literal that follows. The two extractors had drifted: the routing
//! `extract_literal_prefixes` (plural) stripped it; the confidence-feeding
//! `extract_literal_prefix` (singular, behind `has_literal_prefix`) did not, so
//! the 62 detectors whose regex opens with `(?-i)` (cloudsmith `cs_`,
//! promptlayer `pl_`, ntfy `tk_`) were denied their literal-prefix credit and
//! scored below the `min_confidence` floor. Both forms are pinned here.

use keyhog_scanner::testing::{extract_literal_prefix, extract_literal_prefixes};

#[test]
fn compiler_extract_prefix_inline_flag_strip() {
    let prefixes = extract_literal_prefixes("(?i)ghp_[A-Za-z0-9]{36}");
    assert_eq!(prefixes, vec!["ghp_".to_string()]);
}

#[test]
fn singular_extract_literal_prefix_strips_leading_inline_flags() {
    // The singular form (feeds `has_literal_prefix` → confidence) must agree with
    // the plural: a `(?-i)` / `(?i)` / `(?im)` directive is stripped and the
    // following literal is returned.
    assert_eq!(
        extract_literal_prefix("(?-i)cs_[a-zA-Z0-9]{32,48}"),
        Some("cs_".to_string())
    );
    assert_eq!(
        extract_literal_prefix("(?i)pl_[a-zA-Z0-9]{20,}"),
        Some("pl_".to_string())
    );
    assert_eq!(
        extract_literal_prefix("(?im)AKIA[A-Z0-9]{16}"),
        Some("AKIA".to_string())
    );
    // A SCOPED flag group `(?i:…)` carries its `abc` body and is NOT a bare
    // mode-set directive: the strip leaves it intact for the `(`-group parser,
    // which descends and returns `abc`: unchanged by the fix.
    assert_eq!(
        extract_literal_prefix("(?i:abc)def"),
        Some("abc".to_string())
    );
    // A flag group followed by a too-short literal still yields None (the
    // MIN_LITERAL_PREFIX_CHARS floor is unaffected by the strip).
    assert_eq!(extract_literal_prefix("(?-i)x"), None);
}
