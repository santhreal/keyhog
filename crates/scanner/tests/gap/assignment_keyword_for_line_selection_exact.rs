//! Gap test: the per-line assignment-keyword selection.
//!
//! `entropy::keywords::assignment_keyword_for_line` decides which key a line is
//! assigning a value to. The selection contract:
//!   - an XML tag takes precedence and is returned directly (no credential gate);
//!   - otherwise the `=`/`:` separators are scanned RIGHT-TO-LEFT;
//!   - the first key that is a credential short-circuits and is returned, even if
//!     a separator further right held a non-credential key;
//!   - if no key is a credential, the rightmost non-credential key is the
//!     fallback;
//!   - a line with no separator (and no XML tag) yields None.
//!
//! All vectors were traced through `xml_assignment_tag`,
//! `normalize_assignment_keyword`, and `normalized_assignment_keyword_is_credential`.

use keyhog_scanner::testing::assignment_keyword_for_line_for_test as keyword_for_line;

#[test]
fn a_credential_key_before_a_separator_is_returned() {
    assert_eq!(
        keyword_for_line("api_key=AKIA1234"),
        Some("api_key".to_string())
    );
}

#[test]
fn the_first_credential_scanning_from_the_right_wins() {
    // Rightmost separator's key is already a credential.
    assert_eq!(
        keyword_for_line("user=bob password=hunter2"),
        Some("password".to_string())
    );
    // Rightmost key `host` is NOT a credential, so the scan continues left and
    // the credential `api_key` wins despite being further left.
    assert_eq!(
        keyword_for_line("api_key=AKIA host=localhost"),
        Some("api_key".to_string())
    );
}

#[test]
fn without_a_credential_the_rightmost_key_is_the_fallback() {
    // Neither `port` nor `host` is a credential; the rightmost (`port`) is kept.
    assert_eq!(
        keyword_for_line("host=localhost port=8080"),
        Some("port".to_string())
    );
}

#[test]
fn a_line_with_no_separator_has_no_assignment_keyword() {
    assert_eq!(keyword_for_line("just some text"), None);
}

#[test]
fn an_xml_tag_takes_precedence_over_an_inner_separator() {
    // The `<config>` tag is returned, not the `api_key` from the inner `=`.
    assert_eq!(
        keyword_for_line("<config>api_key=secret</config>"),
        Some("config".to_string())
    );
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin one example of each selection rule; these SWEEP them.
// A CROSS-FACADE invariant (every returned keyword is already in normalized form)
// plus CONSTRUCTIVE differentials for the three behavioral rules: no-separator ⇒
// None; a credential key short-circuits the right-to-left scan even when a
// non-credential sits further right; with no credential the RIGHTMOST key is the
// fallback. Traced against entropy/keywords.rs:340. No proptest before.

use keyhog_scanner::testing::normalize_assignment_keyword_for_test as normalize;
use proptest::prelude::*;

/// Keys that normalize to a credential slot (short-circuit the scan).
const CREDENTIAL_KEYS: &[&str] = &["api_key", "client_secret", "access_token", "db_password"];

/// Keys proven non-credential by the fixed fallback vector (`host=… port=…` →
/// `port`, which requires BOTH to be non-credential).
const NON_CREDENTIAL_KEYS: &[&str] = &["host", "port"];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// A line with no `=`/`:` separator and no `<xml>` tag has no assignment
    /// keyword. (Alphabet excludes every separator and `<`, so the scan never
    /// fires.) Also locks no-panic on this class.
    #[test]
    fn a_line_without_a_separator_or_tag_yields_none(line in "[A-Za-z0-9 ]{0,40}") {
        prop_assert_eq!(keyword_for_line(&line), None);
    }

    /// Every returned keyword is ALREADY in normalized form (the selector always
    /// returns a `normalize_assignment_keyword` output). Swept over arbitrary
    /// Unicode (also the no-panic guarantee for the whole selector).
    #[test]
    fn every_returned_keyword_is_normalized(line in "(?s).{0,48}") {
        if let Some(k) = keyword_for_line(&line) {
            let renormalized = normalize(&k);
            prop_assert_eq!(renormalized.as_deref(), Some(k.as_str()));
        }
    }

    /// CREDENTIAL-FIRST: a credential key wins even when a non-credential key sits
    /// further right (the right-to-left scan short-circuits on the credential).
    #[test]
    fn a_credential_key_short_circuits_over_a_rightward_non_credential(
        ci in 0usize..CREDENTIAL_KEYS.len(),
        ni in 0usize..NON_CREDENTIAL_KEYS.len(),
        v in "[A-Za-z0-9]{1,12}",
        w in "[A-Za-z0-9]{1,12}",
    ) {
        let cred = CREDENTIAL_KEYS[ci];
        let noncred = NON_CREDENTIAL_KEYS[ni];
        let line = format!("{cred}={v} {noncred}={w}");
        let got = keyword_for_line(&line);
        prop_assert_eq!(got.as_deref(), Some(cred));
    }

    /// FALLBACK: with no credential key, the RIGHTMOST key is selected. `offset`
    /// is derived (1..len, wrapped) so `left` and `right` are ALWAYS distinct, no
    /// `prop_assume` rejection (which would trip the global-reject limit on this
    /// tiny two-key domain).
    #[test]
    fn the_rightmost_non_credential_key_is_the_fallback(
        ai in 0usize..NON_CREDENTIAL_KEYS.len(),
        offset in 1usize..NON_CREDENTIAL_KEYS.len().max(2),
        v in "[A-Za-z0-9]{1,12}",
        w in "[A-Za-z0-9]{1,12}",
    ) {
        let left = NON_CREDENTIAL_KEYS[ai];
        let right = NON_CREDENTIAL_KEYS[(ai + offset) % NON_CREDENTIAL_KEYS.len()];
        let line = format!("{left}={v} {right}={w}");
        let got = keyword_for_line(&line);
        prop_assert_eq!(got.as_deref(), Some(right));
    }
}
