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

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin the layout on a single `aaa…` entropy; these SWEEP it. The
// core is a ROUND-TRIP recall property: for ANY 30-char alnum entropy, a token
// carrying its real 6-char CRC32/base62 checksum validates — proving the 30/6
// split and the checksum computation over the whole entropy space, not one value.
// Negatives sweep the reject rules (wrong checksum, wrong body length, non-alnum
// body, missing prefix), and one property pins the checksum OUTPUT shape (always 6
// base62 chars). Traced against checksum/npm.rs:20. No proptest before.

use keyhog_scanner::testing::npm_checksum_verdict_for_test as verdict;
use keyhog_scanner::testing::npm_expected_checksum_for_test as expected_checksum;
use proptest::prelude::*;

/// Bytes outside the npm body charset (strictly ASCII-alphanumeric).
const NON_ALNUM: &[char] = &['!', ' ', '#', '-', '_', '.', '/', '+'];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// ROUND-TRIP RECALL: any 30-char alnum entropy plus its real checksum is Valid.
    #[test]
    fn correct_checksum_over_arbitrary_entropy_is_valid(entropy in "[A-Za-z0-9]{30}") {
        let checksum = expected_checksum(&entropy);
        let token = format!("npm_{entropy}{checksum}");
        prop_assert_eq!(verdict(&token), "valid");
    }

    /// A 6-char checksum that differs from the expected one is invalid.
    #[test]
    fn wrong_checksum_is_invalid(
        entropy in "[A-Za-z0-9]{30}",
        cs in "[A-Za-z0-9]{6}",
    ) {
        let expected = expected_checksum(&entropy);
        prop_assume!(cs != expected);
        let token = format!("npm_{entropy}{cs}");
        prop_assert_eq!(verdict(&token), "invalid");
    }

    /// An alnum body whose length is not the 36-char modern format is
    /// not-applicable (length is checked before the checksum).
    #[test]
    fn wrong_body_length_is_not_applicable_sweep(body in "[A-Za-z0-9]{0,60}") {
        prop_assume!(body.len() != 36);
        prop_assert_eq!(verdict(&format!("npm_{body}")), "not-applicable");
    }

    /// A 36-char body containing a non-alphanumeric char is invalid (charset gate
    /// runs after the length check passes).
    #[test]
    fn non_alnum_body_of_correct_length_is_invalid(
        head in "[A-Za-z0-9]{35}",
        n in 0usize..NON_ALNUM.len(),
    ) {
        let body = format!("{head}{}", NON_ALNUM[n]);
        prop_assert_eq!(verdict(&format!("npm_{body}")), "invalid");
    }

    /// No `npm_` prefix at all → not-applicable.
    #[test]
    fn no_npm_prefix_is_not_applicable(cred in "(?s).{0,40}") {
        prop_assume!(!cred.starts_with("npm_"));
        prop_assert_eq!(verdict(&cred), "not-applicable");
    }

    /// The expected checksum is ALWAYS exactly 6 base62 (alphanumeric) chars, for
    /// any entropy input.
    #[test]
    fn expected_checksum_is_always_six_base62(entropy in "(?s).{0,50}") {
        let cs = expected_checksum(&entropy);
        prop_assert_eq!(cs.len(), 6);
        prop_assert!(cs.bytes().all(|b| b.is_ascii_alphanumeric()), "non-base62 checksum: {:?}", cs);
    }
}
