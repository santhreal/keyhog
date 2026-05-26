//! Hex literals with `_` readability separators must decode and surface
//! credentials. Negative twin uses the same encoding shape on a fake body.

use super::support::*;

/// `VALID_CREDENTIAL` as contiguous lowercase hex (56 nibbles).
const VALID_HEX: &str = "544553544b45595f614b377850396d5132774535725438795531694f";

/// `FAKE_CREDENTIAL` as contiguous lowercase hex.
const FAKE_HEX: &str = "544553544b45595f3131313131313131313131313131313131";

fn underscored(hex: &str) -> String {
    hex.as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<_>>()
        .join("_")
}

#[test]
#[cfg(feature = "decode")]
fn hex_underscore_separators_decode_to_credential() {
    let encoded = underscored(VALID_HEX);
    let body = format!("const token_hex = \"{encoded}\";\n");
    let scanner = test_scanner();
    let matches = scanner.scan(&make_chunk(&body));
    assert!(
        matches
            .iter()
            .any(|m| m.credential.as_ref() == VALID_CREDENTIAL),
        "hex+underscore blob must decode to {VALID_CREDENTIAL}; matches={:?}",
        matches
            .iter()
            .map(|m| m.credential.as_ref())
            .collect::<Vec<_>>()
    );
}

#[test]
#[cfg(feature = "decode")]
fn hex_underscore_negative_twin_suppresses_fake() {
    let encoded = underscored(FAKE_HEX);
    let body = format!("const token_hex = \"{encoded}\";\n");
    assert_not_detected(&body, FAKE_CREDENTIAL);
}
