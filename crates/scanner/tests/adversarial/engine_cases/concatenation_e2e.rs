//! End-to-end split-string concatenation through the compiled scanner
//! (not just the multiline preprocessor unit tests).

use super::support::*;

#[test]
#[cfg(feature = "multiline")]
fn split_string_concat_e2e_surfaces_reassembled_credential() {
    let body = format!(
        "head = \"TESTKEY_\"\n\
         tail = \"aK7xP9mQ2wE5rT8yU1iO\"\n\
         token = head + tail\n"
    );
    let scanner = test_scanner();
    let matches = scanner.scan(&make_chunk(&body));
    assert!(
        matches
            .iter()
            .any(|m| m.credential.as_ref() == VALID_CREDENTIAL),
        "split-string concat must reassemble {VALID_CREDENTIAL}; matches={:?}",
        matches
            .iter()
            .map(|m| m.credential.as_ref())
            .collect::<Vec<_>>()
    );
}

#[test]
#[cfg(feature = "multiline")]
fn split_string_concat_negative_twin_suppresses_fake() {
    let body = "head = \"TESTKEY_\"\n\
                tail = \"11111111111111111111\"\n\
                token = head + tail\n";
    assert_not_detected(body, FAKE_CREDENTIAL);
}
