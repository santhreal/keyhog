//! authorization_header_value matches the Bearer/Basic scheme case-insensitively
//! WITHOUT allocating a lowercase copy of the header value (Law 7). This pins the
//! equivalence to the old `rhs.to_ascii_lowercase().starts_with(...)` form: the
//! scheme is detected case-insensitively and the returned token is sliced from
//! the ORIGINAL (un-lowercased) header value.

use keyhog_scanner::testing::entropy_keywords::authorization_header_value;

#[test]
fn authorization_scheme_matched_case_insensitively_token_from_original() {
    // Canonical Bearer header.
    assert_eq!(
        authorization_header_value("Authorization: Bearer tok123").as_deref(),
        Some("tok123")
    );
    // Mixed-case scheme still matches (the case-insensitive compare this fix
    // preserves) and the token preserves the ORIGINAL casing.
    assert_eq!(
        authorization_header_value("authorization: bEaReR ToK_AbC").as_deref(),
        Some("ToK_AbC")
    );
    // Basic scheme + uppercase header name.
    assert_eq!(
        authorization_header_value("AUTHORIZATION: BASIC dXNlcjpwYXNz").as_deref(),
        Some("dXNlcjpwYXNz")
    );
    // Extra whitespace after the scheme: token is the first whitespace-delimited
    // field of the original value.
    assert_eq!(
        authorization_header_value("authorization: Bearer  spacedToken extra").as_deref(),
        Some("spacedToken")
    );

    // Unknown scheme -> None (neither bearer nor basic).
    assert_eq!(
        authorization_header_value("Authorization: Digest abc"),
        None
    );
    // Not an Authorization header -> None.
    assert_eq!(authorization_header_value("X-Custom: Bearer tok"), None);
    // No scheme value -> None.
    assert_eq!(authorization_header_value("Authorization: Bearer"), None);
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vector pins a handful of cases; these SWEEP the contract:
// `split_once(':')` → name must ci-EQUAL "authorization" (exact, trimmed); the
// scheme must ci-start-with "bearer " / "basic " (trailing space REQUIRED); the
// returned token is the first whitespace field of the ORIGINAL (case-preserving)
// value. Five properties isolate each gate: any-case scheme returns the original
// token; the header name is case-insensitive; an unknown scheme is None; a
// non-authorization name is None (exact match, so `Proxy-Authorization` is None);
// a scheme with no token is None. Traced against keywords.rs:536. No proptest before.

use proptest::prelude::*;

const SCHEMES: &[&str] = &[
    "Bearer", "bearer", "BEARER", "bEaReR", "Basic", "basic", "BASIC", "BaSiC",
];
const NAME_CASES: &[&str] = &[
    "Authorization",
    "authorization",
    "AUTHORIZATION",
    "AuThOrIzAtIoN",
];
const UNKNOWN_SCHEMES: &[&str] = &["Digest", "Token", "OAuth", "Negotiate", "ApiKey", "Foo"];
const OTHER_NAMES: &[&str] = &[
    "X-Custom",
    "Cookie",
    "Host",
    "X-Api-Key",
    "Content-Type",
    "Proxy-Authorization",
];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// A Bearer/Basic scheme in any ASCII case returns the first whitespace field of
    /// the value, sliced from the ORIGINAL (case-preserving). The trailing ` {extra}`
    /// always gives a whitespace boundary after the token.
    #[test]
    fn known_scheme_any_case_returns_original_first_token(
        si in 0usize..SCHEMES.len(),
        token in "[A-Za-z0-9_./+=-]{1,24}",
        extra in "[A-Za-z0-9]{0,8}",
    ) {
        let header = format!("Authorization: {} {token} {extra}", SCHEMES[si]);
        let got = authorization_header_value(&header);
        prop_assert_eq!(got.as_deref(), Some(token.as_str()));
    }

    /// The `Authorization` header NAME is matched case-insensitively.
    #[test]
    fn authorization_name_is_case_insensitive(
        ni in 0usize..NAME_CASES.len(),
        token in "[A-Za-z0-9_./+=-]{1,24}",
    ) {
        let header = format!("{}: Bearer {token}", NAME_CASES[ni]);
        let got = authorization_header_value(&header);
        prop_assert_eq!(got.as_deref(), Some(token.as_str()));
    }

    /// A scheme other than Bearer/Basic yields None.
    #[test]
    fn unknown_scheme_is_none(
        si in 0usize..UNKNOWN_SCHEMES.len(),
        token in "[A-Za-z0-9]{1,20}",
    ) {
        let header = format!("Authorization: {} {token}", UNKNOWN_SCHEMES[si]);
        prop_assert!(authorization_header_value(&header).is_none());
    }

    /// A header name that is not exactly `authorization` (incl. `Proxy-Authorization`)
    /// yields None (the name match is exact, not a substring).
    #[test]
    fn non_authorization_header_is_none(
        ni in 0usize..OTHER_NAMES.len(),
        token in "[A-Za-z0-9]{1,20}",
    ) {
        let header = format!("{}: Bearer {token}", OTHER_NAMES[ni]);
        prop_assert!(authorization_header_value(&header).is_none());
    }

    /// A recognised scheme with no following token (no trailing space) yields None.
    #[test]
    fn scheme_without_token_is_none(si in 0usize..SCHEMES.len()) {
        let header = format!("Authorization: {}", SCHEMES[si]);
        prop_assert!(authorization_header_value(&header).is_none());
    }
}
