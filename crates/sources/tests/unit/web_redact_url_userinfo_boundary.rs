//! Contract for `url_redaction::redact_url` (reached via the `SourceTestApi`
//! facade), the function that strips `user:password@` userinfo from a URL before
//! it is printed in an error or log line (engineering standard: never log
//! secrets).
//!
//! The load-bearing property is the userinfo/host boundary. Per RFC 3986 /
//! WHATWG URL, `host` cannot contain `@`, so the userinfo extends to the LAST
//! `@` in the authority. A password with a literal (improperly unescaped) `@`
//!: `https://u:pa@ss@host/`: must redact to `https://***@host/`. Splitting on
//! the FIRST `@` instead leaks the password tail (`https://***@ss@host/`, which
//! exposes `ss`). These tests pin the last-`@` rule, prove the leak is closed,
//! and prove an `@` outside the authority (path / query / fragment) is never
//! mistaken for a userinfo separator (no over-redaction).

use keyhog_sources::testing::{SourceTestApi, TestApi};

fn redact(url: &str) -> String {
    TestApi.redact_url(url)
}

// ── the fix: a literal `@` in the password does not leak ─────────────────────

#[test]
fn password_with_embedded_at_is_fully_redacted() {
    // Pre-fix this leaked `ss` as `https://***@ss@host/x`.
    assert_eq!(redact("https://user:pa@ss@host/x"), "https://***@host/x");
}

#[test]
fn redacted_output_contains_no_password_fragment() {
    // Strong no-leak property: none of the secret bytes survive.
    let out = redact("https://user:pa@ss@host/x");
    assert!(
        !out.contains("pa"),
        "username/password fragment leaked: {out}"
    );
    assert!(!out.contains("ss"), "password fragment leaked: {out}");
    assert_eq!(out, "https://***@host/x");
}

#[test]
fn multiple_ats_in_userinfo_all_redacted() {
    assert_eq!(redact("https://a@b@c@host/"), "https://***@host/");
}

#[test]
fn username_with_at_is_fully_redacted() {
    assert_eq!(redact("https://us@er:pw@host/"), "https://***@host/");
}

#[test]
fn double_at_before_host_is_fully_redacted() {
    assert_eq!(redact("https://secret@@host/"), "https://***@host/");
}

#[test]
fn percent_encoded_at_in_password_is_redacted() {
    // The `%40` stays inside the redacted userinfo; the real separator is the
    // single literal `@` before the host.
    assert_eq!(redact("https://u:pa%40ss@host/"), "https://***@host/");
}

// ── single-`@` userinfo still redacts (no regression) ───────────────────────

#[test]
fn simple_user_password_redacted() {
    assert_eq!(redact("https://u:SECRET@host/p"), "https://***@host/p");
}

#[test]
fn username_only_no_password_redacted() {
    assert_eq!(redact("https://user@host/p?q=1"), "https://***@host/p?q=1");
}

#[test]
fn port_and_fragment_preserved_around_redaction() {
    assert_eq!(
        redact("http://x:y@example.com:8080/p#frag"),
        "http://***@example.com:8080/p#frag"
    );
}

#[test]
fn empty_password_after_colon_redacted() {
    assert_eq!(redact("https://user:@host/"), "https://***@host/");
}

#[test]
fn empty_username_before_colon_redacted() {
    assert_eq!(redact("https://:pw@host/"), "https://***@host/");
}

#[test]
fn empty_userinfo_just_at_sign_redacted() {
    assert_eq!(redact("https://@host/"), "https://***@host/");
}

// ── authority with no trailing delimiter (whole remainder) ──────────────────

#[test]
fn userinfo_redacted_when_authority_is_whole_remainder() {
    assert_eq!(redact("https://u:p@host"), "https://***@host");
}

#[test]
fn userinfo_redacted_before_query_with_no_path() {
    assert_eq!(redact("https://u:p@host?q=1"), "https://***@host?q=1");
}

#[test]
fn userinfo_redacted_before_fragment_with_no_path() {
    assert_eq!(redact("https://u:p@host#frag"), "https://***@host#frag");
}

// ── IPv6 host literals ──────────────────────────────────────────────────────

#[test]
fn ipv6_host_with_userinfo_redacts_only_userinfo() {
    // The `:` inside `[::1]` must not confuse the userinfo boundary.
    assert_eq!(redact("https://u:p@[::1]:443/x"), "https://***@[::1]:443/x");
}

#[test]
fn ipv6_host_without_userinfo_unchanged() {
    let url = "https://[::1]:443/x";
    assert_eq!(redact(url), url);
}

// ── no userinfo / no scheme → returned unchanged ────────────────────────────

#[test]
fn url_without_userinfo_unchanged() {
    let url = "https://host/path";
    assert_eq!(redact(url), url);
}

#[test]
fn bare_host_url_unchanged() {
    let url = "https://example.com";
    assert_eq!(redact(url), url);
}

#[test]
fn string_without_scheme_unchanged() {
    let url = "host/path@noturl";
    assert_eq!(redact(url), url);
}

// ── `@` outside the authority must NOT be treated as a userinfo separator ────

#[test]
fn at_in_path_is_not_redacted() {
    let url = "https://example.com/users/@me";
    assert_eq!(redact(url), url);
}

#[test]
fn at_in_query_is_not_redacted() {
    let url = "https://host/p?email=a@b.com";
    assert_eq!(redact(url), url);
}

#[test]
fn at_in_fragment_is_not_redacted() {
    let url = "https://host/p#sec@tion";
    assert_eq!(redact(url), url);
}

#[test]
fn userinfo_redacted_but_query_at_preserved() {
    // The userinfo `@` is redacted; the unrelated `@` in the query survives.
    assert_eq!(
        redact("https://u:p@host/a?email=x@y.com"),
        "https://***@host/a?email=x@y.com"
    );
}

// ── scheme variations ───────────────────────────────────────────────────────

#[test]
fn http_scheme_userinfo_redacted() {
    assert_eq!(redact("http://u:p@host/"), "http://***@host/");
}

#[test]
fn non_http_scheme_with_authority_redacted() {
    // Any `scheme://` authority carrying userinfo is redacted, not just http(s).
    assert_eq!(redact("ftp://u:p@host/f"), "ftp://***@host/f");
}
