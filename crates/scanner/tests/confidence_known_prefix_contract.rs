//! Contract for the well-known service-credential prefix set and its confidence
//! floor (`crate::confidence::prefixes`).
//!
//! `KNOWN_PREFIXES` is the single source of truth for the vendor-prefix set;
//! `known_prefix_body` strips the most-specific matching prefix (feeding
//! sequence-detection and the floor), and `known_prefix_confidence_floor` lifts a
//! real known-prefix credential to 0.8 while refusing placeholders and degenerate
//! repeats. These tests pin (1) the list's integrity, (2) that body extraction
//! picks the LONGEST matching prefix independent of list order, and (3) the floor's
//! grant/deny decisions — the exact recall/precision boundary this module owns.

use keyhog_scanner::testing::confidence::{
    known_prefix_body, known_prefix_confidence_floor, KNOWN_PREFIXES,
};

// ── list integrity ───────────────────────────────────────────────────────

#[test]
fn known_prefixes_is_nonempty() {
    assert!(!KNOWN_PREFIXES.is_empty());
}

#[test]
fn known_prefixes_has_no_duplicates() {
    let mut seen = std::collections::BTreeSet::new();
    for prefix in KNOWN_PREFIXES {
        assert!(seen.insert(*prefix), "duplicate known prefix: {prefix:?}");
    }
}

#[test]
fn no_known_prefix_is_empty() {
    for prefix in KNOWN_PREFIXES {
        assert!(!prefix.is_empty(), "empty prefix in KNOWN_PREFIXES");
    }
}

// ── known_prefix_body: most-specific (longest) prefix wins, order-independent ─

#[test]
fn body_strips_the_longest_matching_prefix_not_the_first() {
    // `sk-` also matches `sk-proj-…`, but `sk-proj-` is longer and must win, so the
    // body is the token after the full vendor prefix — regardless of which appears
    // first in KNOWN_PREFIXES.
    assert_eq!(known_prefix_body("sk-proj-ABCDEF"), Some("ABCDEF"));
    assert_eq!(known_prefix_body("sk-ant-ABCDEF"), Some("ABCDEF"));
}

#[test]
fn body_strips_bare_sk_when_no_longer_prefix_matches() {
    // `sk-live-…` is not one of the longer `sk-` families, so only the bare `sk-`
    // matches and the body keeps everything after it.
    assert_eq!(known_prefix_body("sk-live-XYZ"), Some("live-XYZ"));
}

#[test]
fn body_strips_a_simple_github_prefix() {
    assert_eq!(known_prefix_body("ghp_abcdef123456"), Some("abcdef123456"));
}

#[test]
fn body_strips_an_underscored_stripe_prefix() {
    assert_eq!(known_prefix_body("sk_live_deadbeef"), Some("deadbeef"));
}

#[test]
fn body_of_a_credential_without_a_known_prefix_is_none() {
    assert_eq!(known_prefix_body("totally-unknown-value-1234"), None);
}

#[test]
fn body_of_empty_credential_is_none() {
    assert_eq!(known_prefix_body(""), None);
}

#[test]
fn body_of_a_credential_equal_to_a_prefix_is_empty_not_none() {
    // Stripping the whole thing leaves an empty body — Some(""), a match with no
    // body — never None (None means "no known prefix").
    assert_eq!(known_prefix_body("ghp_"), Some(""));
}

#[test]
fn every_known_prefix_yields_a_body_for_a_token_built_from_it() {
    // For each prefix, prefix + "Z9x" must strip back to exactly the longest prefix
    // that matches; the body is never longer than the appended suffix.
    for prefix in KNOWN_PREFIXES {
        let token = format!("{prefix}Z9x");
        let body = known_prefix_body(&token)
            .unwrap_or_else(|| panic!("no body for token built from prefix {prefix:?}"));
        assert!(
            body.len() <= "Z9x".len(),
            "prefix {prefix:?} left an over-long body {body:?} (a shorter shadowing prefix won)"
        );
    }
}

// ── known_prefix_confidence_floor: grants ────────────────────────────────

#[test]
fn a_real_github_token_gets_the_floor() {
    assert_eq!(
        known_prefix_confidence_floor("ghp_A1b2C3d4E5f6G7h8J9k0L1m2"),
        Some(0.8)
    );
}

#[test]
fn a_real_aws_access_key_gets_the_floor() {
    assert_eq!(
        known_prefix_confidence_floor("AKIA1B2C3D4E5F6G7H8J"),
        Some(0.8)
    );
}

#[test]
fn a_real_slack_and_gitlab_token_get_the_floor() {
    assert_eq!(
        known_prefix_confidence_floor("xoxb-9f2k7Qh4Lm1Pn6Rs8Tv3Wx5Yz"),
        Some(0.8)
    );
    assert_eq!(
        known_prefix_confidence_floor("glpat-aB3dE7gH1jK4mN6pQ8rS"),
        Some(0.8)
    );
}

#[test]
fn a_hex_body_shopify_token_gets_the_floor() {
    // The distinctive-prefix hex-body family the floor exists to rescue.
    assert_eq!(
        known_prefix_confidence_floor("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"),
        Some(0.8)
    );
}

// ── known_prefix_confidence_floor: denials ───────────────────────────────

#[test]
fn a_placeholder_word_credential_is_denied_the_floor() {
    // ghp_EXAMPLE… is a doc sample, not a credential.
    assert_eq!(
        known_prefix_confidence_floor("ghp_EXAMPLE_token_value"),
        None
    );
}

#[test]
fn a_degenerate_repeat_body_is_denied_the_floor() {
    // AKIA + a 16-char X run: a known-prefix placeholder, not a key body.
    assert_eq!(known_prefix_confidence_floor("AKIAXXXXXXXXXXXXXXXX"), None);
}

#[test]
fn a_body_containing_a_placeholder_word_is_denied_the_floor() {
    assert_eq!(
        known_prefix_confidence_floor("sk_live_PLACEHOLDER0000"),
        None
    );
}

#[test]
fn a_credential_with_no_known_prefix_is_denied_the_floor() {
    assert_eq!(
        known_prefix_confidence_floor("just-a-random-string-value"),
        None
    );
}

#[test]
fn an_empty_credential_is_denied_the_floor() {
    assert_eq!(known_prefix_confidence_floor(""), None);
}

// ── the two consumers agree: a floored credential has a body ──────────────

#[test]
fn every_floored_prefix_family_also_produces_a_body() {
    // A representative real token per structural family: if it earns the floor it
    // must also strip to a non-None body (the two consumers share KNOWN_PREFIXES).
    for token in [
        "ghp_A1b2C3d4E5f6G7h8J9k0L1m2",
        "AKIA1B2C3D4E5F6G7H8J",
        "xoxb-9f2k7Qh4Lm1Pn6Rs8Tv3Wx5Yz",
        "sk-ant-aB3dE7gH1jK4mN6pQ8rS",
    ] {
        assert_eq!(
            known_prefix_confidence_floor(token),
            Some(0.8),
            "floor: {token}"
        );
        assert!(known_prefix_body(token).is_some(), "body: {token}");
    }
}
