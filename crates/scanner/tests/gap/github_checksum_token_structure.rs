//! Gap test: GitHub PAT structural+checksum verdicts (classic and fine-grained).
//!
//! The classic body layout is now named (`GITHUB_CLASSIC_BODY_LEN =
//! GITHUB_CLASSIC_ENTROPY_LEN (30) + CHECKSUM_LEN (6)`) and the 6-char base62
//! CRC32 checksum width is the single `CHECKSUM_LEN`, shared by both validators
//! (previously bare `36`/`30`/`6`/`7` literals). Pin the layout through real
//! behavior: tokens built with the correct CRC32 checksum validate as valid, a
//! flipped checksum char is invalid, and the over-long (`> 36` -> Invalid) vs
//! short (`!= 36` -> NotApplicable) split is exact.

use keyhog_scanner::testing::{
    github_classic_checksum_verdict_for_test, github_fine_grained_checksum_verdict_for_test,
    npm_expected_checksum_for_test,
};

fn entropy(n: usize) -> String {
    "a".repeat(n)
}

#[test]
fn classic_correct_checksum_validates() {
    let body = entropy(30);
    let checksum = npm_expected_checksum_for_test(&body); // base62(crc32(body), 6)
    let token = format!("ghp_{body}{checksum}");
    assert_eq!(token.len(), 4 + 36);
    assert_eq!(github_classic_checksum_verdict_for_test(&token), "valid");
}

#[test]
fn classic_flipped_checksum_is_invalid() {
    let body = entropy(30);
    let mut bytes = npm_expected_checksum_for_test(&body).into_bytes();
    let last = bytes.last_mut().unwrap();
    *last = if *last == b'A' { b'B' } else { b'A' };
    let token = format!("ghp_{body}{}", String::from_utf8(bytes).unwrap());
    assert_eq!(github_classic_checksum_verdict_for_test(&token), "invalid");
}

#[test]
fn classic_overlong_is_invalid_but_short_is_not_applicable() {
    // > 36 body chars -> Invalid (fabricated); < 36 -> NotApplicable (unmodelled).
    assert_eq!(
        github_classic_checksum_verdict_for_test(&format!("ghp_{}", entropy(37))),
        "invalid"
    );
    assert_eq!(
        github_classic_checksum_verdict_for_test(&format!("ghp_{}", entropy(35))),
        "not-applicable"
    );
}

#[test]
fn classic_charset_and_missing_prefix() {
    let body = format!("{}!", entropy(35)); // 36 chars incl '!'
    assert_eq!(
        github_classic_checksum_verdict_for_test(&format!("ghp_{body}")),
        "invalid"
    );
    assert_eq!(
        github_classic_checksum_verdict_for_test("glpat-0123456789abcdefghij"),
        "not-applicable"
    );
}

#[test]
fn fine_grained_right_segment_checksum_validates() {
    // github_pat_ + {22 alnum}_{53 entropy + 6 checksum} ; the right segment's
    // trailing 6 chars are the correct base62 CRC32 of its first 53 chars.
    let left = entropy(22);
    let right_entropy = entropy(53);
    let right = format!("{right_entropy}{}", npm_expected_checksum_for_test(&right_entropy));
    assert_eq!(right.len(), 59);
    let token = format!("github_pat_{left}_{right}");
    assert_eq!(
        github_fine_grained_checksum_verdict_for_test(&token),
        "valid"
    );
}

#[test]
fn fine_grained_wrong_segment_lengths_and_missing_prefix() {
    // left is 21 chars (!= 22) -> Invalid.
    let token = format!("github_pat_{}_{}", entropy(21), entropy(59));
    assert_eq!(
        github_fine_grained_checksum_verdict_for_test(&token),
        "invalid"
    );
    assert_eq!(
        github_fine_grained_checksum_verdict_for_test("ghp_0123456789abcdefABCDEF"),
        "not-applicable"
    );
}

#[test]
fn fine_grained_segment_length_boundaries_are_exact() {
    // Named GITHUB_FINE_GRAINED_LEFT_LEN (22) / _RIGHT_LEN (59): one char off on
    // either segment is Invalid.
    assert_eq!(
        github_fine_grained_checksum_verdict_for_test(&format!(
            "github_pat_{}_{}",
            entropy(23),
            entropy(59)
        )),
        "invalid",
        "a 23-char left segment is not the 22-char format"
    );
    assert_eq!(
        github_fine_grained_checksum_verdict_for_test(&format!(
            "github_pat_{}_{}",
            entropy(22),
            entropy(58)
        )),
        "invalid",
        "a 58-char right segment is not the 59-char format"
    );
}
