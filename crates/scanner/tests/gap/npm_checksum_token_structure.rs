//! Gap test: npm token structure (body = entropy + checksum) is exact.
//!
//! The npm validator now names its layout: `NPM_BODY_LEN = NPM_ENTROPY_LEN (30)
//! + NPM_CHECKSUM_LEN (6)`, previously bare `36` / `[..30]` / `[30..]` / `, 6)`
//! magic literals. Pin the layout through real behavior: a token built with the
//! correct CRC32 checksum over its first 30 chars validates as `valid` (pinning
//! the 30/6 split), a single flipped checksum char makes it `invalid`, a
//! non-36-char body is `not-applicable`, a non-alphanumeric body is `invalid`,
//! and a non-npm prefix is `not-applicable`.

use keyhog_scanner::testing::{npm_checksum_verdict_for_test, npm_expected_checksum_for_test};

fn entropy30() -> String {
    "a".repeat(30)
}

#[test]
fn correct_checksum_validates() {
    let entropy = entropy30();
    let checksum = npm_expected_checksum_for_test(&entropy);
    assert_eq!(checksum.len(), 6, "npm checksum is exactly 6 base62 chars");
    let token = format!("npm_{entropy}{checksum}");
    assert_eq!(token.len(), 4 + 36, "npm_ + 30 entropy + 6 checksum");
    assert_eq!(
        npm_checksum_verdict_for_test(&token),
        "valid",
        "a token whose 6-char checksum matches CRC32 of its first 30 chars is Valid"
    );
}

#[test]
fn flipped_checksum_char_is_invalid() {
    let entropy = entropy30();
    let mut bytes = npm_expected_checksum_for_test(&entropy).into_bytes();
    // Flip the last checksum byte to a different base62 char -> guaranteed mismatch.
    let last = bytes.last_mut().unwrap();
    *last = if *last == b'A' { b'B' } else { b'A' };
    let bad = String::from_utf8(bytes).unwrap();
    let token = format!("npm_{entropy}{bad}");
    assert_eq!(
        npm_checksum_verdict_for_test(&token),
        "invalid",
        "a token whose checksum does not match its entropy is Invalid"
    );
}

#[test]
fn wrong_body_length_is_not_applicable() {
    assert_eq!(
        npm_checksum_verdict_for_test(&format!("npm_{}", "a".repeat(35))),
        "not-applicable",
        "35-char body is not the 36-char modern format"
    );
    assert_eq!(
        npm_checksum_verdict_for_test(&format!("npm_{}", "a".repeat(37))),
        "not-applicable",
        "37-char body is not the 36-char modern format"
    );
}

#[test]
fn non_alnum_body_and_missing_prefix() {
    // 36-char body containing a non-alphanumeric char -> charset gate -> Invalid.
    let body = format!("{}!", "a".repeat(35));
    assert_eq!(body.len(), 36);
    assert_eq!(
        npm_checksum_verdict_for_test(&format!("npm_{body}")),
        "invalid",
        "a non-alphanumeric body char is Invalid"
    );
    assert_eq!(
        npm_checksum_verdict_for_test("ghp_0123456789abcdefABCDEF"),
        "not-applicable",
        "no npm_ prefix -> NotApplicable"
    );
}
