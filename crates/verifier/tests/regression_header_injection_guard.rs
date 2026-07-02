//! Regression coverage for the verifier's HTTP header-injection guard.
//!
//! A verified credential is scanned, attacker-influenced content. It is
//! interpolated into outbound verification-request header VALUES (and bodies)
//! via `interpolate::interpolate_http_value`, which control-strips the value
//! with `sanitize_raw_value` before it reaches the `reqwest` builder. This file
//! pins the concrete guard behaviour at that boundary:
//!
//!   * a credential carrying CR / LF (the header-injection primitive) has those
//!     bytes REMOVED, so no `\r\n` can split one header into two — the injected
//!     bytes collapse into the value, they do not error and do not survive;
//!   * the full C0 control range (except TAB 0x09), DEL 0x7F, and the C1 range
//!     0x80..=0x9F are stripped, while TAB, SP, and printable / non-C1 Unicode
//!     survive verbatim (exact boundary bytes pinned);
//!   * a NORMAL credential passes through byte-for-byte unchanged;
//!   * the guard is WIRED into the real request builder
//!     (`apply_header_body_templates`): the BUILT `reqwest::Request` carries the
//!     sanitized value, an injected header NAME never appears as a second
//!     header, and the body template is sanitized the same way.
//!
//! Every assertion pins an EXACT rendered string / byte outcome. No network I/O
//! occurs — `built_request_header_body_for_test` BUILDS the request and inspects
//! the assembled bytes; it never sends.

use keyhog_verifier::testing::{TestApi, VerifierTestApi};
use std::collections::HashMap;

fn companions(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Case-insensitive header lookup over the `(name, value)` pairs returned by
/// the wired builder (reqwest lower-cases header names).
fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

// ===========================================================================
// sanitize_raw_value: the core CR/LF + control-byte guard
// ===========================================================================

#[test]
fn crlf_in_credential_is_stripped_to_single_line() {
    // The classic header-injection primitive: CR (0x0D) + LF (0x0A) that would
    // start a forged header line. Both bytes are DROPPED; the surrounding text
    // collapses onto one line — it does not error, it neutralizes.
    assert_eq!(
        TestApi.sanitize_raw_value("abc\r\nX-Evil: 1"),
        "abcX-Evil: 1",
        "CR and LF are removed so the value can never split into a second header"
    );
}

#[test]
fn bare_cr_and_bare_lf_each_stripped() {
    // Some proxies treat a lone CR or lone LF as a line boundary; both must go.
    assert_eq!(TestApi.sanitize_raw_value("a\rb"), "ab");
    assert_eq!(TestApi.sanitize_raw_value("a\nb"), "ab");
}

#[test]
fn tab_is_preserved_but_other_c0_controls_are_stripped() {
    // TAB (0x09) is the sole allowed C0 control (legit in Basic-auth / JWT
    // combos). NUL (0x00), VT (0x0B), FF (0x0C), ESC (0x1B) are stripped.
    assert_eq!(
        TestApi.sanitize_raw_value("a\tb\0c\x0b\x0c\x1bd"),
        "a\tbcd",
        "TAB survives; NUL/VT/FF/ESC are removed"
    );
}

#[test]
fn c0_upper_boundary_0x1f_stripped_space_and_tab_kept() {
    // Boundary: 0x1F (Unit Separator, last C0 control) is stripped; 0x20 (SP)
    // and 0x09 (TAB) are kept.
    assert_eq!(
        TestApi.sanitize_raw_value("a\u{001F}\tb c"),
        "a\tb c",
        "0x1F removed, TAB and space retained"
    );
}

#[test]
fn del_0x7f_is_stripped() {
    assert_eq!(
        TestApi.sanitize_raw_value("a\u{007F}b"),
        "ab",
        "DEL (0x7F) is removed"
    );
}

#[test]
fn c1_control_range_boundary_0x80_and_0x9f_stripped_0xa0_kept() {
    // C1 controls 0x80..=0x9F are stripped (NEL 0x85 is an alternate line
    // terminator some parsers honor). 0xA0 (NBSP), just past the range, survives.
    assert_eq!(
        TestApi.sanitize_raw_value("a\u{0080}b\u{0085}c\u{009F}d\u{00A0}e"),
        "abcd\u{00A0}e",
        "0x80, 0x85 (NEL), 0x9F stripped; 0xA0 (NBSP) preserved"
    );
}

#[test]
fn normal_credential_passes_through_unchanged() {
    // Negative twin: a real-shaped token contains no control bytes and must be
    // byte-for-byte identical after sanitization.
    let cred = "ghp_ABCdef0123456789XYZ_-.tokenvalue";
    assert_eq!(
        TestApi.sanitize_raw_value(cred),
        cred,
        "a clean credential is not altered by the guard"
    );
}

#[test]
fn full_forged_header_block_collapses_to_one_line() {
    // Adversarial: an entire multi-header injection payload. Every CR/LF is
    // removed, so the result contains no line terminators at all — the forged
    // Host / X-Forwarded-For lines cannot exist as separate headers.
    let payload = "secret\r\nHost: attacker.example\r\nX-Forwarded-For: 1.2.3.4\r\n\r\nGET /admin";
    let out = TestApi.sanitize_raw_value(payload);
    assert_eq!(
        out, "secretHost: attacker.exampleX-Forwarded-For: 1.2.3.4GET /admin",
        "the entire injection payload collapses onto a single line"
    );
    assert!(!out.contains('\r'), "no CR survives");
    assert!(!out.contains('\n'), "no LF survives");
}

// ===========================================================================
// interpolate_http_value: the guard as reached through the template path
// ===========================================================================

#[test]
fn http_value_fast_path_match_strips_crlf() {
    // Template exactly `{{match}}` hits the raw fast path; the credential's
    // CR/LF are still stripped.
    let c = companions(&[]);
    assert_eq!(
        TestApi.interpolate_http_value("{{match}}", "abc\r\ndef", &c),
        "abcdef"
    );
}

#[test]
fn http_value_general_path_match_strips_crlf() {
    // Template `Bearer {{match}}` is NOT the fast path; the general loop still
    // control-strips (but does not percent-encode, per header/body context).
    let c = companions(&[]);
    assert_eq!(
        TestApi.interpolate_http_value("Bearer {{match}}", "tok\r\nX-Injected: yes", &c),
        "Bearer tokX-Injected: yes",
        "header/body context strips CR/LF and leaves the rest un-encoded"
    );
}

#[test]
fn companion_value_crlf_injection_is_stripped_in_header_context() {
    // The injection primitive can also arrive through a companion credential.
    let c = companions(&[("other", "x\r\nEvil-Header: 1")]);
    assert_eq!(
        TestApi.interpolate_http_value("X-Auth: {{companion.other}}", "cred", &c),
        "X-Auth: xEvil-Header: 1"
    );
}

// ===========================================================================
// WIRED: the guard is actually installed in the reqwest request builder
// ===========================================================================

#[test]
fn built_request_header_value_has_crlf_removed() {
    // Drives the real `apply_header_body_templates` boundary. The credential's
    // CR/LF are gone in the BUILT request's header value — proving the sanitizer
    // is wired into the builder, not just callable in isolation.
    let c = companions(&[]);
    let (headers, _body) = TestApi.built_request_header_body_for_test(
        &[("Authorization", "Bearer {{match}}")],
        None,
        "tok\r\nX-Injected-Crlf: pwned",
        &c,
    );
    assert_eq!(
        header(&headers, "authorization"),
        Some("Bearer tokX-Injected-Crlf: pwned"),
        "the built Authorization header carries the sanitized, single-line value"
    );
}

#[test]
fn built_request_never_gains_a_forged_second_header() {
    // The injected `X-Injected-Crlf` name must NOT appear as a distinct header
    // in the assembled request — CR/LF removal makes a second header impossible.
    let c = companions(&[]);
    let (headers, _body) = TestApi.built_request_header_body_for_test(
        &[("Authorization", "Bearer {{match}}")],
        None,
        "tok\r\nX-Injected-Crlf: pwned",
        &c,
    );
    assert!(
        header(&headers, "x-injected-crlf").is_none(),
        "no forged header was smuggled into the built request; headers = {headers:?}"
    );
    // Positive twin on the same request: exactly the one header we set is present
    // by that name.
    assert_eq!(
        headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("authorization"))
            .count(),
        1,
        "exactly one Authorization header exists"
    );
}

#[test]
fn built_request_normal_credential_value_unchanged() {
    // Negative twin at the wired boundary: a clean credential renders verbatim.
    let c = companions(&[]);
    let (headers, _body) = TestApi.built_request_header_body_for_test(
        &[("X-Api-Key", "{{match}}")],
        None,
        "ghp_ABCdef0123456789",
        &c,
    );
    assert_eq!(
        header(&headers, "x-api-key"),
        Some("ghp_ABCdef0123456789"),
        "a clean credential reaches the built header untouched"
    );
}

#[test]
fn built_request_body_template_is_sanitized() {
    // The body path uses the same guard. A CR/LF-bearing credential inside a
    // JSON body template renders as a single-line, injection-free body.
    let c = companions(&[]);
    let (_headers, body) = TestApi.built_request_header_body_for_test(
        &[],
        Some("{\"key\":\"{{match}}\"}"),
        "v\r\ninject",
        &c,
    );
    assert_eq!(
        body.as_deref(),
        Some("{\"key\":\"vinject\"}"),
        "the credential's CR/LF are stripped inside the request body"
    );
}

#[test]
fn built_request_full_injection_payload_yields_no_line_breaks_in_header() {
    // Adversarial, end-to-end: a full forged header block as the credential.
    // The single built header value contains no CR/LF, and none of the forged
    // header names appear as separate headers.
    let c = companions(&[]);
    let (headers, _body) = TestApi.built_request_header_body_for_test(
        &[("Authorization", "token {{match}}")],
        None,
        "s\r\nHost: evil.example\r\nX-Forwarded-Host: evil.example",
        &c,
    );
    let value = header(&headers, "authorization").expect("authorization header present");
    assert_eq!(
        value, "token sHost: evil.exampleX-Forwarded-Host: evil.example",
        "the full payload collapses into the single Authorization value"
    );
    assert!(!value.contains('\r') && !value.contains('\n'));
    assert!(
        header(&headers, "host").map(|h| h == "evil.example") != Some(true),
        "no forged Host header equals the attacker value"
    );
    assert!(
        header(&headers, "x-forwarded-host").is_none(),
        "no forged X-Forwarded-Host header exists; headers = {headers:?}"
    );
}
