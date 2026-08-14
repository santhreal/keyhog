//! Migrated from `src/engine/scan_filters.rs` `#[cfg(test)]` (KH-GAP-004).
//!
//! Credential-boundary extension: `extend_known_prefix_credential` must not
//! drag a checksum-valid known-prefix token past its canonical boundary (which
//! would break the checksum), while still recovering base64 padding for ordinary
//! non-checksum values.

use keyhog_scanner::testing::scan_filters::extend_known_prefix_credential;

// A checksum-valid PyPI token (checksum/pypi.rs: `pypi-` + base64url body).
const VALID_PYPI: &str =
    "pypi-EUJykml7ZgrfPCV8aS7QTdFqbB2uTkz8KP4a8d3M1JxnuJn7UfyK_Dalj4zgPh-hecYl8DYcWbo6yT2c7xfyT0QjAXikOrHrbMNH";

#[test]
fn valid_checksum_token_is_not_extended_over_a_trailing_equals() {
    // `pypi-…MNH="x"`: the base64-padding extension would append the `=`,
    // breaking the PyPI checksum. The extension must be reverted.
    let data = format!("{VALID_PYPI}=\"x\"");
    let credential = &data[..VALID_PYPI.len()];
    let (cred, end) = extend_known_prefix_credential(&data, credential, VALID_PYPI.len());
    assert_eq!(
        cred, VALID_PYPI,
        "valid token must keep its canonical boundary"
    );
    assert_eq!(end, VALID_PYPI.len());
    assert_eq!(
        keyhog_scanner::testing::checksum::validate_checksum(cred),
        keyhog_scanner::testing::checksum::ChecksumResult::Valid
    );
}

#[test]
fn non_checksum_base64_value_still_recovers_padding() {
    // No checksum applies, so the base64-padding recovery is UNCHANGED: a
    // generic base64 value still absorbs its trailing `==`. This pins that
    // the no-downgrade guard only fires on a Valid→non-Valid checksum
    // transition and never weakens padding recovery for ordinary base64.
    let token = "YWJjZGVmZ2hpamtsbW5vcA"; // base64, no known-prefix checksum
    let data = format!("{token}==trailing");
    let credential = &data[..token.len()];
    let (cred, end) = extend_known_prefix_credential(&data, credential, token.len());
    assert_eq!(
        cred, "YWJjZGVmZ2hpamtsbW5vcA==",
        "padding must still be recovered"
    );
    assert_eq!(end, token.len() + 2);
}

#[test]
fn candidate_used_as_assignment_key_does_not_absorb_separator() {
    let token = "sk-0ocqX7mxUDlWFHzlNiC0oKONoezJ9vAX";
    let data = format!("{token}=\"{token}\"");
    let credential = &data[..token.len()];
    let (cred, end) = extend_known_prefix_credential(&data, credential, token.len());
    assert_eq!(
        cred, token,
        "a quoted assignment delimiter is syntax, not token padding"
    );
    assert_eq!(end, token.len());
}

/// WHY: the quoted-assignment guard is provider-boundary evidence, not a
/// global reinterpretation of detector captures that intentionally own `=`.
#[test]
fn ordinary_candidate_can_recover_equals_before_quoted_value() {
    let token = "73405814";
    let data = format!("{token}=\"{token}\"");
    let credential = &data[..token.len()];
    let (cred, end) = extend_known_prefix_credential(&data, credential, token.len());
    assert_eq!(cred, "73405814=");
    assert_eq!(end, token.len() + 1);
}

/// WHY: assignment syntax is proved by its immediate boundary; malformed or
/// multiline values must not turn the separator into credential padding.
#[test]
fn assignment_key_guard_does_not_require_a_same_line_closing_quote() {
    let token = "sk-0ocqX7mxUDlWFHzlNiC0oKONoezJ9vAX";
    for suffix in [
        "=\"unterminated",
        "=\"first line\nsecond line\"",
        "='unterminated",
        "='first line\nsecond line'",
    ] {
        let data = format!("{token}{suffix}");
        let credential = &data[..token.len()];
        let (cred, end) = extend_known_prefix_credential(&data, credential, token.len());
        assert_eq!(cred, token, "assignment suffix {suffix:?}");
        assert_eq!(end, token.len(), "assignment suffix {suffix:?}");
    }
}

/// WHY: a quote immediately before the candidate proves value position. In
/// that position a following `=` is token padding even if another quote follows.
#[test]
fn quoted_provider_value_retains_real_base64_padding() {
    let token = "sk-0ocqX7mxUDlWFHzlNiC0oKONoezJ9vAX";
    for quote in ['"', '\''] {
        let data = format!("{quote}{token}={quote}, {quote}other{quote}: {quote}value{quote}");
        let credential = &data[1..1 + token.len()];
        let (cred, end) = extend_known_prefix_credential(&data, credential, 1 + token.len());
        assert_eq!(cred, format!("{token}="), "quote {quote:?}");
        assert_eq!(end, 1 + token.len() + 1, "quote {quote:?}");
    }
}
