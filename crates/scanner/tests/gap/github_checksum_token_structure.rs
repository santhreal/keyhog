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
    let right = format!(
        "{right_entropy}{}",
        npm_expected_checksum_for_test(&right_entropy)
    );
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

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin the layout at a handful of points; these SWEEP both
// validators over ARBITRARY entropy bodies (not the fixed `"a".repeat`), using the
// real `npm_expected_checksum_for_test` = base62(crc32(body),6) checksum owner. For
// the classic PAT: any 30-char alnum body with its correct checksum is "valid";
// any single checksum-char change (kept alnum, so the compare, not the charset
// gate, decides) is "invalid"; a <36 payload is "not-applicable" and a >36 alnum
// payload is "invalid" (the length policy split). For the fine-grained PAT: a
// correct 22-char-left / 53+6-char-right token is "valid", and any left length !=
// 22 is "invalid". Traced against GithubClassic/FineGrainedPatValidator. No
// proptest before.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// Any 30-char alnum body with its correct base62-CRC32 checksum validates.
    #[test]
    fn classic_correct_checksum_validates_sweep(body in "[A-Za-z0-9]{30}") {
        let checksum = npm_expected_checksum_for_test(&body);
        let token = format!("ghp_{body}{checksum}");
        prop_assert_eq!(github_classic_checksum_verdict_for_test(&token), "valid");
    }

    /// Changing any single checksum char (to a different alnum char) breaks the
    /// checksum compare: "invalid", never a false "valid".
    #[test]
    fn classic_any_checksum_char_change_is_invalid(
        body in "[A-Za-z0-9]{30}",
        pos in 0usize..6,
    ) {
        let mut cs: Vec<char> = npm_expected_checksum_for_test(&body).chars().collect();
        // Flip to a guaranteed-different base62 (alnum) char so the charset gate
        // still passes and the checksum comparison is what rejects.
        cs[pos] = if cs[pos] == 'a' { 'b' } else { 'a' };
        let bad: String = cs.into_iter().collect();
        let token = format!("ghp_{body}{bad}");
        prop_assert_eq!(github_classic_checksum_verdict_for_test(&token), "invalid");
    }

    /// A payload shorter than 36 chars is unmodelled -> "not-applicable" (the length
    /// gate rejects before any checksum math).
    #[test]
    fn classic_short_payload_is_not_applicable(payload in "[A-Za-z0-9]{0,35}") {
        let token = format!("ghp_{payload}");
        prop_assert_eq!(github_classic_checksum_verdict_for_test(&token), "not-applicable");
    }

    /// A payload longer than 36 alnum chars is fabricated -> "invalid".
    #[test]
    fn classic_overlong_payload_is_invalid(payload in "[A-Za-z0-9]{37,60}") {
        let token = format!("ghp_{payload}");
        prop_assert_eq!(github_classic_checksum_verdict_for_test(&token), "invalid");
    }

    /// A well-formed fine-grained token (22 alnum left, 53 alnum entropy + correct
    /// 6-char checksum right) validates for any entropy.
    #[test]
    fn fine_grained_correct_right_checksum_validates_sweep(
        left in "[A-Za-z0-9]{22}",
        right_entropy in "[A-Za-z0-9]{53}",
    ) {
        let checksum = npm_expected_checksum_for_test(&right_entropy);
        let token = format!("github_pat_{left}_{right_entropy}{checksum}");
        prop_assert_eq!(github_fine_grained_checksum_verdict_for_test(&token), "valid");
    }

    /// A left segment of any length != 22 is not the fine-grained format ->
    /// "invalid", even with a correct right segment.
    #[test]
    fn fine_grained_wrong_left_length_is_invalid(
        off in 1usize..8,
        longer in any::<bool>(),
        right_entropy in "[A-Za-z0-9]{53}",
    ) {
        let left_len = if longer { 22 + off } else { 22 - off };
        let left = "a".repeat(left_len);
        let checksum = npm_expected_checksum_for_test(&right_entropy);
        let token = format!("github_pat_{left}_{right_entropy}{checksum}");
        prop_assert_eq!(github_fine_grained_checksum_verdict_for_test(&token), "invalid");
    }
}
