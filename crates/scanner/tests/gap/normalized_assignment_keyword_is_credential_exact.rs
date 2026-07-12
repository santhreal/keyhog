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

use keyhog_scanner::testing::keyword_is_password_family_for_test as is_password_family;
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

#[test]
fn a_pass_suffix_is_a_credential_but_bypass_and_compass_are_not() {
    // `pass` is the `*_PASS=` credential-env stem (dominant CredData shape:
    // `SES_PASS=`, `DB_PASS=`). It lives ONLY in the `_`-separated-suffix branch,
    // so the last `_`-segment must be exactly `pass`.
    assert!(is_credential("ses_pass"));
    assert!(is_credential("db_pass"));
    assert!(is_credential("mysql_root_pass"));
    // Boundary safety — the left `_` boundary is what makes this safe:
    //  * no `_` at all (`bypass`, `compass`, `encompass`) never reaches branch 1
    //    and is not an exact compact credential, so it stays a non-credential;
    //  * a `_`-segment other than `pass` (`ci_bypass` -> last segment `bypass`)
    //    is likewise not promoted.
    assert!(!is_credential("bypass"));
    assert!(!is_credential("compass"));
    assert!(!is_credential("encompass"));
    assert!(!is_credential("ci_bypass"));
}

#[test]
fn password_family_routes_pass_stem_but_not_bypass_or_passing() {
    // Both entropy classifiers use this to give `*_PASS=` the Password-tier
    // entropy floor (so `SES_PASS=<value>` surfaces like `DB_PASSWORD=<value>`).
    assert!(is_password_family("DB_PASSWORD"));
    assert!(is_password_family("PWD"));
    assert!(is_password_family("SES_PASS"));
    assert!(is_password_family("MY-PASS"));
    assert!(is_password_family("app.pass"));
    assert!(is_password_family("PASS"));
    // Boundary: last separator-segment must be exactly `pass`.
    assert!(!is_password_family("bypass")); // no separator; segment `bypass`
    assert!(!is_password_family("compass"));
    assert!(!is_password_family("encompass"));
    assert!(!is_password_family("SES_PASSING")); // segment `passing`, not `pass`
                                                 // A key-family/token-family key is not password-family.
    assert!(!is_password_family("api_key"));
    assert!(!is_password_family("auth_token"));
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin each branch at fixed keywords; these SWEEP them.
// `is_credential` has two branches (keywords.rs): a `_`-separated last segment in
// {key,secret,token,password,passwd,pwd,pass} → credential; else compact (drop `_`,
// lowercase) EXACT membership OR a salt/nonce/seed ends_with. So a `{prefix}_{suffix}`
// with a secret suffix is a credential, a `{prefix}_{salt|nonce|seed}` is a
// credential via the compact ends_with, and a `{prefix}_host` (segment not in the
// set, compact not a member, no salt/nonce/seed) is NOT. And `is_password_family`
// promotes a `_`/`-`/`.`-separated trailing `pass` segment. No proptest before.

use proptest::prelude::*;

/// The `_`-separated last-segment set that makes a key a credential (branch 1).
const SECRET_SUFFIXES: &[&str] = &[
    "key", "secret", "token", "password", "passwd", "pwd", "pass",
];
/// Suffixes that reach the compact `ends_with` credential branch.
const SALT_SUFFIXES: &[&str] = &["salt", "nonce", "seed"];
/// Segment separators the password-family stem check splits on.
const SEPS: &[char] = &['_', '-', '.'];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// A `{prefix}_{suffix}` whose last `_`-segment is a secret suffix is a credential.
    #[test]
    fn separated_secret_suffix_is_credential_sweep(
        prefix in "[a-z]{1,8}",
        si in 0usize..SECRET_SUFFIXES.len(),
    ) {
        let kw = format!("{prefix}_{}", SECRET_SUFFIXES[si]);
        prop_assert!(is_credential(&kw));
    }

    /// A `{prefix}_{salt|nonce|seed}` is a credential via the compact `ends_with`
    /// branch (these are NOT in the separated-suffix set).
    #[test]
    fn salt_nonce_seed_suffix_is_credential_sweep(
        prefix in "[a-z]{1,8}",
        si in 0usize..SALT_SUFFIXES.len(),
    ) {
        let kw = format!("{prefix}_{}", SALT_SUFFIXES[si]);
        prop_assert!(is_credential(&kw));
    }

    /// A `{prefix}_host` key is NOT a credential: `host` is not in the separated set,
    /// the compact form is not an exact member, and it has no salt/nonce/seed tail.
    #[test]
    fn host_suffix_is_not_credential(prefix in "[a-z]{1,8}") {
        let kw = format!("{prefix}_host");
        prop_assert!(!is_credential(&kw));
    }

    /// A `{prefix}{sep}pass` key (sep = `_`/`-`/`.`) is password-family: the trailing
    /// separator-segment is exactly `pass`.
    #[test]
    fn pass_segment_is_password_family_sweep(
        prefix in "[a-z]{1,8}",
        si in 0usize..SEPS.len(),
    ) {
        let kw = format!("{prefix}{}pass", SEPS[si]);
        prop_assert!(is_password_family(&kw));
    }
}
