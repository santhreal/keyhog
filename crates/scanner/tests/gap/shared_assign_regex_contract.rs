//! Behavioral contract for the shared `ASSIGN_RE` assignment-detection regex
//! (crates/scanner/src/shared_regexes.rs). `ASSIGN_RE` is the SINGLE compiled
//! `key = "value"` source consumed by two scan paths — `engine` fragment
//! reassembly (scan_postprocess/fragments.rs) and the `multiline::structural`
//! preprocessor — so its exact match/reject behaviour is a real detection
//! contract: a silent shift in the one regex would move both paths at once.
//!
//! Pattern under test:
//!   (?i)([a-z0-9_-]{2,32})\s*[:=]\s*["'`]([a-zA-Z0-9/+=_-]{4,})["'`](?:;|,)?$
//!
//! These pin the four load-bearing pieces with EXACT captured values, not just
//! a boolean match: the two capture groups, the `{4,}` value-length floor, the
//! `{2,32}` key-length floor, the end `$` anchor, and the optional `;`/`,` tail.

use keyhog_scanner::testing::assign_re_captures_for_test as caps;

#[test]
fn assign_re_captures_key_and_value_groups() {
    // Canonical `key = "value"`: group 1 is the bare key, group 2 the unquoted
    // value (quotes are delimiters, not part of the capture).
    assert_eq!(
        caps(r#"api_key = "abcd1234""#),
        Some(("api_key".to_string(), "abcd1234".to_string())),
        "the two capture groups must be the bare key and the unquoted value"
    );
}

#[test]
fn assign_re_admits_colon_singlequote_and_preserves_key_case() {
    // `:` separator + single-quote delimiter both admitted; the `(?i)` flag lets
    // an upper-case key match while the capture preserves the ORIGINAL casing.
    assert_eq!(
        caps("Token: 'S3cr3tV'"),
        Some(("Token".to_string(), "S3cr3tV".to_string())),
        "colon separator + single quote admitted; key case preserved in the capture"
    );
}

#[test]
fn assign_re_enforces_value_length_floor_of_four() {
    // The value class is `{4,}`: exactly 4 chars matches, 3 does not. Pins the
    // boundary, not just "short values rejected".
    assert_eq!(
        caps(r#"kv = "abcd""#),
        Some(("kv".to_string(), "abcd".to_string()))
    );
    assert_eq!(
        caps(r#"kv = "abc""#),
        None,
        "a 3-char value is below the {{4,}} floor and must not match"
    );
}

#[test]
fn assign_re_enforces_key_length_floor_of_two() {
    // The key class is `{2,32}`: a single-character key is rejected even with a
    // valid value (this is exactly what ASSIGN_RE refuses but the looser
    // structural single-char-name path admits).
    assert_eq!(
        caps(r#"a = "abcd""#),
        None,
        "a 1-char key is below the {{2,32}} floor and must not match"
    );
    assert_eq!(
        caps(r#"ab = "abcd""#),
        Some(("ab".to_string(), "abcd".to_string())),
        "a 2-char key is exactly at the floor and matches"
    );
}

#[test]
fn assign_re_is_end_anchored_but_admits_trailing_separator() {
    // The `$` anchor rejects trailing content after the closing quote...
    assert_eq!(
        caps(r#"api_key = "abcd1234" trailing"#),
        None,
        "content after the closing quote fails the end `$` anchor"
    );
    // ...except a single optional `;` or `,`, which the `(?:;|,)?` tail consumes
    // without entering the value capture.
    assert_eq!(
        caps(r#"api_key = "abcd1234";"#),
        Some(("api_key".to_string(), "abcd1234".to_string())),
        "a trailing semicolon is admitted and excluded from the value group"
    );
    assert_eq!(
        caps(r#"api_key = "abcd1234","#),
        Some(("api_key".to_string(), "abcd1234".to_string())),
        "a trailing comma is admitted and excluded from the value group"
    );
}
