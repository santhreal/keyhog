//! Gap test: the credential-keyword predicate used by the entropy line-owner.
//!
//! `entropy::keywords::normalized_assignment_keyword_is_credential` takes an
//! already-normalized assignment key and decides whether it names a credential
//! slot. Two branches:
//!   - separated secret suffix: the key CONTAINS `_` and its last `_`-segment is
//!     one of {key, secret, token, password, passwd, pwd};
//!   - compact: drop `_`, lowercase, then EXACT membership in the credential
//!     list, OR a `salt`/`nonce`/`seed` suffix.
//!
//! The compact branch is an EXACT whole-string match (not a suffix), which is
//! what distinguishes this predicate from the `*_has_secret_suffix` family:
//! `myapikey` is NOT a credential here even though it ends with `apikey`.
//! All vectors were hand-traced against the credential list and both branches.

use keyhog_scanner::testing::normalized_assignment_keyword_is_credential_for_test as is_credential;

#[test]
fn a_separated_secret_suffix_is_a_credential() {
    assert!(is_credential("api_key"));
    assert!(is_credential("client_secret"));
    assert!(is_credential("auth_token"));
}

#[test]
fn a_compact_credential_keyword_without_a_separator_is_a_credential() {
    // No `_`, so the first branch cannot fire; the compact list match does.
    assert!(is_credential("apikey"));
    assert!(is_credential("password"));
    assert!(is_credential("bearer"));
}

#[test]
fn a_salt_nonce_or_seed_suffix_is_a_credential_via_ends_with() {
    // `salt`/`nonce`/`seed` are not in the separated-suffix set, so these reach
    // the compact ends_with check.
    assert!(is_credential("client_salt"));
    assert!(is_credential("request_nonce"));
    assert!(is_credential("random_seed"));
}

#[test]
fn a_non_credential_keyword_is_not_a_credential() {
    assert!(!is_credential("username"));
    assert!(!is_credential("db_host"));
    // EXACT compact match, not a suffix: ends with `apikey` but is not it.
    assert!(!is_credential("myapikey"));
}
