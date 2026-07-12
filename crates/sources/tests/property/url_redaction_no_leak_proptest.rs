//! Property tier for `redact_url` (reached via the `SourceTestApi` web facade) —
//! the ONE credential-masking gate every WebSource / cloud / DNS error message
//! routes through before it is logged (`url_redaction.rs`; called at each SSRF
//! refusal site in `web/ssrf.rs`). A leak here is a real secret-disclosure bug:
//! a `user:password@` or `?sig=…` fragment surviving into an error log defeats
//! the "never log secrets" engineering standard.
//!
//! The fixed-vector twins (`url_redaction.rs` inline tests, `tests/unit/
//! web_redact_url_userinfo_boundary.rs`, `tests/unit/a5_lr2/web_redact_*`) pin a
//! handful of hand-built URLs. This file sweeps the two REDACTION CONTRACTS over
//! generated secrets so a regression in the authority `@`-boundary scan or the
//! sensitive-query masking surfaces on a shape nobody wrote a vector for.
//!
//! Invariants proved here:
//!   * USERINFO — for ANY secret in the `user:secret@` / `secret@` position, the
//!     whole userinfo collapses to `***@`; the emitted URL is EXACTLY the
//!     host+path with the userinfo masked, so no byte of the secret survives.
//!     The generated secret spans the rich authority charset (incl. an embedded
//!     `@`, the `rfind`-not-`find` boundary case) but excludes `/ ? # &` and
//!     space, which are the authority/query terminators — so the secret stays in
//!     the region the masker owns and the expected output is deterministic.
//!   * SENSITIVE QUERY — for every key in the module's `SENSITIVE_QUERY_KEYS`
//!     contract, `?key=secret` masks the value to `key=***` while the benign
//!     siblings (`&page=2`) are preserved verbatim.
//!   * NO-LEAK (literal) — with a secret drawn from a charset DISJOINT from the
//!     lowercase+symbol scaffold, `!output.contains(secret)` is a sound, direct
//!     statement of the security property (no coincidental-substring escape).
//!   * NO OVER-REDACTION — a URL with only benign query keys and no userinfo is
//!     returned byte-for-byte unchanged; the masker never eats innocent content.
//!
//! Feature gate: `redact_url` is exposed on the facade under `feature = "web"`,
//! which is a default source feature, so this runs in the base `all_tests` step.

use keyhog_sources::testing::{SourceTestApi, TestApi};
use proptest::prelude::*;

/// The sensitive query-parameter keys, mirrored from `url_redaction.rs`'s
/// `SENSITIVE_QUERY_KEYS` as the contract-of-record: every one of these must
/// have its value masked. If the source list grows, this test should grow with
/// it (the mirror makes a silent divergence visible as an un-swept key).
const SENSITIVE_QUERY_KEYS: &[&str] = &[
    "sig",
    "signature",
    "x-amz-signature",
    "x-amz-credential",
    "x-amz-security-token",
    "access_token",
    "token",
    "id_token",
    "refresh_token",
    "sas",
    "code",
    "api_key",
    "apikey",
    "secret",
    "password",
    "auth",
];

/// Query keys that carry NO credential — the masker must leave their values
/// alone. None of these appear (case-insensitively) in `SENSITIVE_QUERY_KEYS`.
const BENIGN_QUERY_KEYS: &[&str] = &[
    "page", "sort", "state", "limit", "offset", "format", "sv", "se", "q", "lang",
];

/// A secret that stays inside the URL authority AND inside a single query value:
/// the rich reg-name / userinfo / query-value charset MINUS the four span
/// terminators `/ ? # &` and space. An embedded `@` is deliberately allowed so
/// the `rfind`-based userinfo boundary (a password containing `@`) is swept.
fn safe_secret() -> impl Strategy<Value = String> {
    // Inside a regex class `-` is placed last to stay literal; `. % = : @ ! $ *
    // ( ) + _` are all literal within `[...]`.
    proptest::string::string_regex("[A-Za-z0-9._%+=:@!$*()-]{8,40}").expect("valid regex")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// `user:<secret>@host` — the whole userinfo (name AND password, including an
    /// embedded `@`) collapses to `***@`, emitting exactly the host+path. Nothing
    /// of the secret can survive because the output is fully determined and
    /// contains only the mask.
    #[test]
    fn userinfo_with_password_is_always_fully_masked(secret in safe_secret()) {
        let url = format!("https://user:{secret}@host.example/path/to/resource");
        let redacted = TestApi.redact_url(&url);
        prop_assert_eq!(redacted, "https://***@host.example/path/to/resource");
    }

    /// `<secret>@host` — userinfo with no `:` password separator is masked just
    /// the same (a bare token in the userinfo slot).
    #[test]
    fn userinfo_without_password_is_always_fully_masked(secret in safe_secret()) {
        let url = format!("https://{secret}@host.example/path");
        let redacted = TestApi.redact_url(&url);
        prop_assert_eq!(redacted, "https://***@host.example/path");
    }

    /// Every sensitive query key masks its value to `key=***`, while the trailing
    /// benign `&page=2` is preserved — proving the masker is value-scoped, not a
    /// blunt whole-query wipe.
    #[test]
    fn every_sensitive_query_key_masks_only_its_value(
        key_idx in 0..SENSITIVE_QUERY_KEYS.len(),
        secret in safe_secret(),
    ) {
        let key = SENSITIVE_QUERY_KEYS[key_idx];
        let url = format!("https://host.example/cb?{key}={secret}&page=2");
        let expected = format!("https://host.example/cb?{key}=***&page=2");
        prop_assert_eq!(TestApi.redact_url(&url), expected);
    }

    /// LITERAL no-leak: a secret drawn from an UPPERCASE-only charset (disjoint
    /// from the lowercase+symbol scaffold) placed in BOTH the userinfo and a
    /// sensitive query value must not appear anywhere in the output. Disjointness
    /// makes `!contains` sound — no coincidental substring can mask a real leak.
    #[test]
    fn secret_bytes_never_survive_userinfo_or_query(secret in "[A-Z]{8,40}") {
        let url = format!("https://user:{secret}@host.example/cb?token={secret}&page=2");
        let redacted = TestApi.redact_url(&url);
        prop_assert!(
            !redacted.contains(&secret),
            "redaction leaked the secret {secret:?} into {redacted:?}"
        );
        // And it positively redacted both sites (guards against a vacuous pass
        // where the input was mangled instead of masked).
        prop_assert_eq!(
            redacted.as_str(),
            "https://***@host.example/cb?token=***&page=2"
        );
    }

    /// No over-redaction: a URL with only benign query keys and no userinfo comes
    /// back byte-for-byte. A masker that touched innocent content (or spuriously
    /// found a userinfo `@` in the path/query) would fail here.
    #[test]
    fn benign_url_without_userinfo_is_returned_unchanged(
        key_idx in 0..BENIGN_QUERY_KEYS.len(),
        value in "[A-Za-z0-9]{1,24}",
        with_port in any::<bool>(),
    ) {
        let key = BENIGN_QUERY_KEYS[key_idx];
        let port = if with_port { ":8443" } else { "" };
        let url = format!("https://host.example{port}/x?{key}={value}&sort=name");
        prop_assert_eq!(TestApi.redact_url(&url), url.clone());
    }
}
