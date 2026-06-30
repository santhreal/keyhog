//! Contract for `classify_entropy_detector_index` (phase2_entropy/helpers.rs):
//! mapping an entropy candidate's keyword to its detector-metadata index
//! (0 generic / 1 password / 2 token / 3 api-key). The keyword is the captured
//! assignment key and preserves its source case, so the mapping must be
//! ASCII-case-insensitive — an all-caps `PASSWORD=`/`TOKEN=` anchor must land in
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
