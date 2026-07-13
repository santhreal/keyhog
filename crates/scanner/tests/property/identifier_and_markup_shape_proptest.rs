//! Identifier / config-selector / XSS-markup FP-suppression contracts
//! (`crates/scanner/src/suppression/shape/{source,public}.rs`).
//!
//! More "captured grammar, not a secret" gates:
//!   • `looks_like_program_identifier`: bare snake_case or camelCase all-alpha name.
//!   • `looks_like_kebab_config_identifier`: short dash-joined majority-lowercase key.
//!   • `looks_like_public_reference_selector`: a run of `[sources.IDENT]` selectors.
//!   • `looks_like_percent_encoded_markup`: percent-encoded XSS markup.
//!   • `looks_like_html_event_handler_fragment`: a bare `onEvent=` handler attribute.

use keyhog_scanner::testing::{
    looks_like_html_event_handler_fragment_for_test, looks_like_kebab_config_identifier_for_test,
    looks_like_percent_encoded_markup_for_test, looks_like_program_identifier_for_test,
    looks_like_public_reference_selector_for_test,
};
use proptest::prelude::*;

// ── program identifiers ──────────────────────────────────────────────────────

#[test]
fn snake_and_camel_identifiers_match() {
    assert!(looks_like_program_identifier_for_test("my_program")); // snake_case
    assert!(looks_like_program_identifier_for_test("myProgram")); // camelCase transition
    assert!(!looks_like_program_identifier_for_test("myprogram")); // no _ and no case transition
    assert!(!looks_like_program_identifier_for_test("my_prog1")); // digit → not all-alpha
    assert!(!looks_like_program_identifier_for_test("")); // empty
}

// ── kebab config identifiers ─────────────────────────────────────────────────

#[test]
fn kebab_config_keys_match() {
    assert!(looks_like_kebab_config_identifier_for_test("log-level"));
    assert!(looks_like_kebab_config_identifier_for_test(
        "max-retry-count"
    ));
    assert!(!looks_like_kebab_config_identifier_for_test("loglevel")); // no dash
    assert!(!looks_like_kebab_config_identifier_for_test(
        "A-B-C-D-E-F-G-H"
    )); // not majority lowercase
    assert!(!looks_like_kebab_config_identifier_for_test(&format!(
        "a-{}",
        "b".repeat(30)
    ))); // > 24
    assert!(!looks_like_kebab_config_identifier_for_test("a-b/c=d")); // base64-ish chars
}

// ── [sources.IDENT] reference selectors ──────────────────────────────────────

#[test]
fn sources_selectors_match() {
    assert!(looks_like_public_reference_selector_for_test(
        "[sources.MY_BUCKET]"
    ));
    assert!(looks_like_public_reference_selector_for_test(
        "[sources.AWS_S3][sources.GCS_2]"
    ));
    assert!(!looks_like_public_reference_selector_for_test(
        "[sources.lowercase]"
    )); // ident not upper
    assert!(!looks_like_public_reference_selector_for_test(
        "[sources.AB]"
    )); // ident < 3
    assert!(!looks_like_public_reference_selector_for_test(
        "[sources.OK] trailing"
    )); // leftover
    assert!(!looks_like_public_reference_selector_for_test("short")); // < 12 and no selector
}

// ── percent-encoded XSS markup ───────────────────────────────────────────────

#[test]
fn percent_encoded_xss_markup_matches() {
    // Encoded `<script>` : %3c + script + %3e.
    assert!(looks_like_percent_encoded_markup_for_test(
        "%3Cscript%3Ealert%3C%2Fscript%3E"
    ));
    assert!(!looks_like_percent_encoded_markup_for_test(
        "%3Cdiv%3Ehello%3C%2Fdiv%3E"
    )); // no payload kw
    assert!(!looks_like_percent_encoded_markup_for_test("plainvalue")); // no percent-encoding
}

// ── HTML event-handler fragments ─────────────────────────────────────────────

#[test]
fn html_event_handlers_match() {
    assert!(looks_like_html_event_handler_fragment_for_test("onclick="));
    assert!(looks_like_html_event_handler_fragment_for_test("onerror="));
    assert!(!looks_like_html_event_handler_fragment_for_test("onclick")); // no trailing =
    assert!(!looks_like_html_event_handler_fragment_for_test(
        "notanevent="
    )); // not a known event
    assert!(!looks_like_html_event_handler_fragment_for_test("=")); // empty event
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// A program-identifier match IMPLIES the value is entirely `[A-Za-z_]` (all
    /// alpha or underscore) (a digit or symbol can never be a program identifier).
    #[test]
    fn program_id_match_implies_alpha_underscore(value in "[A-Za-z0-9_$-]{0,24}") {
        if looks_like_program_identifier_for_test(&value) {
            prop_assert!(value.bytes().all(|b| b.is_ascii_alphabetic() || b == b'_'));
        }
    }

    /// Any all-lowercase snake_case string (>=1 underscore) is ALWAYS a program id.
    #[test]
    fn lowercase_snake_case_is_always_a_program_id(
        a in "[a-z]{1,8}",
        b in "[a-z]{1,8}",
    ) {
        let value = format!("{a}_{b}");
        prop_assert!(looks_like_program_identifier_for_test(&value));
    }

    /// A kebab-config match IMPLIES length <= 24 and at least one dash.
    #[test]
    fn kebab_match_implies_bounded_and_dashed(value in "[a-zA-Z0-9-]{0,40}") {
        if looks_like_kebab_config_identifier_for_test(&value) {
            prop_assert!(value.len() <= 24);
            prop_assert!(value.contains('-'));
        }
    }

    /// A reference-selector match IMPLIES the value starts with `[sources.`: the
    /// gate never fires on a non-selector.
    #[test]
    fn selector_match_implies_sources_prefix(value in "[\\[\\]a-zA-Z0-9._]{0,60}") {
        if looks_like_public_reference_selector_for_test(&value) {
            prop_assert!(value.starts_with("[sources."));
        }
    }

    /// An event-handler match IMPLIES a trailing `=` and an all-alpha event name of
    /// length 5..=24.
    #[test]
    fn event_handler_match_implies_trailing_eq_and_alpha(value in "[a-zA-Z=]{0,30}") {
        if looks_like_html_event_handler_fragment_for_test(&value) {
            prop_assert!(value.ends_with('='));
            let event = &value[..value.len() - 1];
            prop_assert!((5..=24).contains(&event.len()));
            prop_assert!(event.bytes().all(|b| b.is_ascii_alphabetic()));
        }
    }
}
