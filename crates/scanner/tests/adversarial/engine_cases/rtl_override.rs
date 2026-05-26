//! RTL override characters (U+202E) embedded in keyword/value context must
//! be stripped during Unicode normalization without hiding real credentials.

use super::support::*;

const RTL: char = '\u{202E}';

#[test]
fn rtl_override_in_assignment_does_not_hide_credential() {
    let body = format!("TESTKEY_{RTL}token = \"{VALID_CREDENTIAL}\"\n");
    let scanner = test_scanner();
    let matches = scanner.scan(&make_chunk(&body));
    assert!(
        matches
            .iter()
            .any(|m| m.credential.as_ref() == VALID_CREDENTIAL),
        "RTL override must not suppress {VALID_CREDENTIAL}; matches={:?}",
        matches
            .iter()
            .map(|m| m.credential.as_ref())
            .collect::<Vec<_>>()
    );
}

#[test]
fn rtl_override_negative_twin_suppresses_fake_credential() {
    let body = format!("TESTKEY_{RTL}token = \"{FAKE_CREDENTIAL}\"\n");
    assert_not_detected(&body, FAKE_CREDENTIAL);
}
