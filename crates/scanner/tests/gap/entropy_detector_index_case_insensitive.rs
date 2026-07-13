//! Contract for `classify_entropy_detector_index` (phase2_entropy/helpers.rs):
//! mapping an entropy candidate's keyword to its detector-metadata index
//! (0 generic / 1 password / 2 token / 3 api-key). The keyword is the captured
//! assignment key and preserves its source case, so the mapping must be
//! ASCII-case-insensitive, an all-caps `PASSWORD=`/`TOKEN=` anchor must land in
//! the Password/Token bucket, not default to the API-Key bucket. These tests pin
//! every casing, the branch precedence, and the preserved `none`-sentinel cases.

use keyhog_scanner::testing::classify_entropy_detector_index_for_test as classify;

// ── index 0: the high-entropy no-keyword sentinel ───────────────────────────

#[test]
fn none_high_entropy_sentinel_is_generic_index_0() {
    assert_eq!(classify("none (high-entropy)"), 0);
}

// ── index 1: password / pwd, every casing ───────────────────────────────────

#[test]
fn lowercase_password_is_index_1() {
    assert_eq!(classify("password"), 1);
}

#[test]
fn uppercase_password_is_index_1() {
    assert_eq!(classify("PASSWORD"), 1);
}

#[test]
fn titlecase_password_is_index_1() {
    assert_eq!(classify("Password"), 1);
}

#[test]
fn mixed_case_password_is_index_1() {
    assert_eq!(classify("PaSsWoRd"), 1);
}

#[test]
fn embedded_uppercase_password_is_index_1() {
    assert_eq!(classify("DB_PASSWORD"), 1);
}

#[test]
fn lowercase_pwd_is_index_1() {
    assert_eq!(classify("pwd"), 1);
}

#[test]
fn uppercase_pwd_is_index_1() {
    assert_eq!(classify("PWD"), 1);
}

#[test]
fn embedded_pwd_is_index_1() {
    assert_eq!(classify("user_pwd"), 1);
}

// ── index 2: token, every casing ────────────────────────────────────────────

#[test]
fn lowercase_token_is_index_2() {
    assert_eq!(classify("token"), 2);
}

#[test]
fn uppercase_token_is_index_2() {
    assert_eq!(classify("TOKEN"), 2);
}

#[test]
fn titlecase_token_is_index_2() {
    assert_eq!(classify("Token"), 2);
}

#[test]
fn embedded_uppercase_token_is_index_2() {
    assert_eq!(classify("API_TOKEN"), 2);
}

#[test]
fn mixed_case_token_is_index_2() {
    assert_eq!(classify("ToKeN"), 2);
}

#[test]
fn isolated_token_label_maps_to_index_2() {
    // Pre-existing behaviour preserved: the isolated-bare label contains the
    // substring "token", so it maps to the token bucket.
    assert_eq!(classify("none (isolated-token)"), 2);
}

// ── index 3: the api-key / generic default ──────────────────────────────────

#[test]
fn lowercase_api_key_is_index_3() {
    assert_eq!(classify("api_key"), 3);
}

#[test]
fn uppercase_api_key_is_index_3() {
    assert_eq!(classify("API_KEY"), 3);
}

#[test]
fn bare_key_is_index_3() {
    assert_eq!(classify("key"), 3);
}

#[test]
fn secret_keyword_is_index_3() {
    // There is no Secret bucket; a secret-only keyword falls to the default.
    assert_eq!(classify("SECRET"), 3);
}

#[test]
fn empty_keyword_is_index_3() {
    assert_eq!(classify(""), 3);
}

#[test]
fn unrelated_keyword_is_index_3() {
    assert_eq!(classify("username"), 3);
}

// ── branch precedence ───────────────────────────────────────────────────────

#[test]
fn password_takes_precedence_over_token() {
    // password is checked before token, so a keyword containing both resolves
    // to the password bucket.
    assert_eq!(classify("PASSWORD_TOKEN"), 1);
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin each bucket at fixed casings; these SWEEP the classifier's
// exact branch order (helpers.rs:26): `== KEYWORD_FREE_LABEL → 0`; else
// `keyword_is_password_family` (ci-substring "password"|"pwd", OR a trailing
// `_pass`/`-pass`/`.pass` segment) `→ 1`; else `ci_find "token" → 2`; else `3`.
// Five properties: a password/pwd substring (any affix) is 1; a trailing `pass`
// segment is 1; a `token` substring (any case) without a password family is 2;
// password-precedence-over-token is 1; and a keyword with NONE of the families
// (alphabet excludes `d`/`n` so "password"/"pwd"/"token" can't form, and != "pass")
// is 3. Traced against `classify_entropy_detector_index`. No proptest before.

use proptest::prelude::*;

/// Case variants of "token" (ci_find is ASCII-case-insensitive).
const TOKEN_CASES: &[&str] = &["token", "TOKEN", "Token", "ToKeN"];
/// Segment separators that split off a trailing `pass`.
const SEPS: &[char] = &['_', '-', '.'];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// A keyword containing "password" or "pwd" (any surrounding, digit affixes so
    /// no other family interferes) lands in the Password bucket (index 1).
    #[test]
    fn password_substring_is_index_1(
        pre in "[0-9]{0,6}",
        post in "[0-9]{0,6}",
        use_pwd in any::<bool>(),
    ) {
        let core = if use_pwd { "pwd" } else { "password" };
        let kw = format!("{pre}{core}{post}");
        prop_assert_eq!(classify(&kw), 1);
    }

    /// A keyword whose trailing `_`/`-`/`.`-delimited segment is `pass` is the
    /// Password bucket (the third password-family branch).
    #[test]
    fn trailing_pass_segment_is_index_1(pre in "[a-z0-9]{1,8}", si in 0usize..SEPS.len()) {
        let kw = format!("{pre}{}pass", SEPS[si]);
        prop_assert_eq!(classify(&kw), 1);
    }

    /// A keyword containing "token" (any case) but no password family lands in the
    /// Token bucket (index 2). Digit affixes cannot form a password family.
    #[test]
    fn token_without_password_is_index_2(
        ti in 0usize..TOKEN_CASES.len(),
        pre in "[0-9]{0,5}",
        post in "[0-9]{0,5}",
    ) {
        let kw = format!("{pre}{}{post}", TOKEN_CASES[ti]);
        prop_assert_eq!(classify(&kw), 2);
    }

    /// Password is checked before token, so a keyword with BOTH resolves to the
    /// Password bucket regardless of order.
    #[test]
    fn password_and_token_together_is_index_1(
        pre in "[0-9]{0,4}",
        mid in "[0-9]{0,4}",
        post in "[0-9]{0,4}",
        password_first in any::<bool>(),
    ) {
        let kw = if password_first {
            format!("{pre}password{mid}token{post}")
        } else {
            format!("{pre}token{mid}password{post}")
        };
        prop_assert_eq!(classify(&kw), 1);
    }

    /// A keyword with none of the families (alphabet excludes `d` and `n`, so
    /// "password"/"pwd"/"token" cannot form; and it is not the bare "pass" segment)
    /// falls to the default api-key bucket (index 3).
    #[test]
    fn no_family_keyword_is_index_3(kw in "[a-ce-mo-z0-9]{1,12}") {
        prop_assume!(kw != "pass");
        prop_assert_eq!(classify(&kw), 3);
    }
}
