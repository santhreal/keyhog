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
    // `pypi-…MNH="x"` — the base64-padding extension would append the `=`,
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
