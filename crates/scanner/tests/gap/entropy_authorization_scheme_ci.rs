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
    assert_eq!(authorization_header_value("Authorization: Digest abc"), None);
    // Not an Authorization header -> None.
    assert_eq!(authorization_header_value("X-Custom: Bearer tok"), None);
    // No scheme value -> None.
    assert_eq!(authorization_header_value("Authorization: Bearer"), None);
}
