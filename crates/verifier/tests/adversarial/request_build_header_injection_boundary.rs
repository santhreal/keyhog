//! End-to-end WIRING lock for the outbound-request header/body boundary.
//!
//! `interpolate_no_second_order_expansion.rs` proves the interpolation helper
//! (`interpolate_http_value`) produces a control-stripped, single-pass string.
//! This suite proves the *next* link in the chain: that the real request builder
//! `verify::request::apply_header_body_templates` actually FEEDS every header
//! value and the body through that helper, and that the resulting
//! `reqwest::Request` — the exact object keyhog would put on the wire — carries
//! no injected header, no CR/LF or control byte, and no second-order
//! `{{companion.*}}` expansion.
//!
//! Why the extra layer matters (adversarial vector #9, WIRING): a regression that
//! attached a raw `header.value` (or a `body_template`) WITHOUT interpolation
//! would leave the helper-only tests green while reopening CR/LF header injection
//! on the shipped path. The credential here is attacker-controlled — it is the
//! literal bytes of a secret found in a scanned file — so a `\r\n` in it must
//! never split the request into an extra header. The request is BUILT and
//! inspected, never sent: no traffic leaves the test.

use keyhog_verifier::testing::{TestApi, VerifierTestApi};
use std::collections::HashMap;

/// One templated `Authorization: Bearer {{match}}` header, `cred` interpolated.
fn auth_headers(cred: &str) -> (Vec<(String, String)>, Option<String>) {
    TestApi.built_request_header_body_for_test(
        &[("authorization", "Bearer {{match}}")],
        None,
        cred,
        &HashMap::new(),
    )
}

fn comps(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

fn has_header(headers: &[(String, String)], name: &str) -> bool {
    headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(name))
}

/// The core invariant every built header value must satisfy: no raw CR and no
/// raw LF byte can survive into the outbound request.
fn assert_no_bare_crlf(headers: &[(String, String)]) {
    for (name, value) in headers {
        assert!(
            !value.contains('\r') && !value.contains('\n'),
            "header {name:?} value carried a bare CR/LF: {value:?}"
        );
    }
}

// ── CR/LF cannot inject a second header ─────────────────────────────────────

#[test]
fn crlf_in_credential_does_not_add_second_header() {
    let (headers, _) = auth_headers("realtoken\r\nX-Injected: evil");
    assert!(
        !has_header(&headers, "x-injected"),
        "CRLF in the credential injected a second header: {headers:?}"
    );
    // The remainder folds into the single authorization value with the line
    // break removed.
    assert_eq!(
        header_value(&headers, "authorization").as_deref(),
        Some("Bearer realtokenX-Injected: evil")
    );
}

#[test]
fn crlf_stripped_from_authorization_value() {
    let (headers, _) = auth_headers("a\r\nb");
    assert_no_bare_crlf(&headers);
    assert_eq!(
        header_value(&headers, "authorization").as_deref(),
        Some("Bearer ab")
    );
}

#[test]
fn lone_lf_stripped() {
    let (headers, _) = auth_headers("a\nb");
    assert_no_bare_crlf(&headers);
    assert_eq!(
        header_value(&headers, "authorization").as_deref(),
        Some("Bearer ab")
    );
}

#[test]
fn lone_cr_stripped() {
    let (headers, _) = auth_headers("a\rb");
    assert_no_bare_crlf(&headers);
    assert_eq!(
        header_value(&headers, "authorization").as_deref(),
        Some("Bearer ab")
    );
}

#[test]
fn repeated_crlf_runs_all_stripped() {
    let (headers, _) = auth_headers("a\r\n\r\n\r\nb");
    assert_no_bare_crlf(&headers);
    assert_eq!(
        header_value(&headers, "authorization").as_deref(),
        Some("Bearer ab")
    );
}

#[test]
fn injected_header_name_via_value_never_becomes_a_header() {
    // A payload that tries to smuggle an `X-Evil` header must remain inert text.
    let (headers, _) = auth_headers("t\r\nX-Evil: 1\r\nX-Also: 2");
    assert!(
        !has_header(&headers, "x-evil"),
        "x-evil leaked: {headers:?}"
    );
    assert!(
        !has_header(&headers, "x-also"),
        "x-also leaked: {headers:?}"
    );
    assert_no_bare_crlf(&headers);
}

// ── other control bytes are stripped ────────────────────────────────────────

#[test]
fn nul_byte_stripped() {
    let (headers, _) = auth_headers("a\u{0}b");
    assert_eq!(
        header_value(&headers, "authorization").as_deref(),
        Some("Bearer ab")
    );
}

#[test]
fn del_0x7f_stripped() {
    let (headers, _) = auth_headers("a\u{7f}b");
    assert_eq!(
        header_value(&headers, "authorization").as_deref(),
        Some("Bearer ab")
    );
}

#[test]
fn bel_and_esc_stripped() {
    let (headers, _) = auth_headers("a\u{7}b\u{1b}c");
    assert_eq!(
        header_value(&headers, "authorization").as_deref(),
        Some("Bearer abc")
    );
}

#[test]
fn vertical_tab_and_form_feed_stripped() {
    let (headers, _) = auth_headers("a\u{b}b\u{c}c");
    assert_eq!(
        header_value(&headers, "authorization").as_deref(),
        Some("Bearer abc")
    );
}

#[test]
fn c1_nel_0x85_stripped() {
    // U+0085 (NEL) is a C1 line-break some lenient HTTP parsers honour; it must
    // be dropped so it cannot act as a CR/LF surrogate.
    let (headers, _) = auth_headers("a\u{85}b");
    assert_no_bare_crlf(&headers);
    assert_eq!(
        header_value(&headers, "authorization").as_deref(),
        Some("Bearer ab")
    );
}

#[test]
fn c1_controls_0x80_to_0x9f_stripped() {
    let (headers, _) = auth_headers("a\u{80}b\u{9f}c");
    assert_eq!(
        header_value(&headers, "authorization").as_deref(),
        Some("Bearer abc")
    );
}

// ── legitimate bytes are preserved ──────────────────────────────────────────

#[test]
fn tab_preserved_in_header_value() {
    // HTAB is valid within an HTTP field value; a Basic-auth / JWT combination
    // may legitimately contain it, so it must survive.
    let (headers, _) = auth_headers("a\tb");
    let value = header_value(&headers, "authorization").expect("authorization header present");
    assert!(value.contains('\t'), "tab was wrongly stripped: {value:?}");
    assert_eq!(value, "Bearer a\tb");
}

#[test]
fn high_unicode_value_preserved_and_builds() {
    let (headers, _) = auth_headers("tökénλ");
    assert_no_bare_crlf(&headers);
    assert_eq!(
        header_value(&headers, "authorization").as_deref(),
        Some("Bearer tökénλ")
    );
}

#[test]
fn unicode_line_separator_u2028_is_not_an_http_break() {
    // U+2028/U+2029 are Unicode line separators but NOT ASCII CR/LF bytes, so
    // they carry no HTTP header-splitting power; they are preserved verbatim and
    // the request still builds.
    let (headers, _) = auth_headers("a\u{2028}b\u{2029}c");
    assert_no_bare_crlf(&headers);
    assert_eq!(
        header_value(&headers, "authorization").as_deref(),
        Some("Bearer a\u{2028}b\u{2029}c")
    );
}

#[test]
fn empty_credential_yields_prefix_only_value() {
    let (headers, _) = auth_headers("");
    assert_eq!(
        header_value(&headers, "authorization").as_deref(),
        Some("Bearer ")
    );
}

// ── second-order expansion cannot reach the built request ───────────────────

#[test]
fn credential_companion_token_not_expanded_in_built_header() {
    let (headers, _) = TestApi.built_request_header_body_for_test(
        &[("x-api-key", "{{match}}")],
        None,
        "{{companion.secret}}",
        &comps(&[("secret", "OTHER_SECRET")]),
    );
    let value = header_value(&headers, "x-api-key").expect("x-api-key present");
    assert_eq!(value, "{{companion.secret}}");
    assert!(
        !value.contains("OTHER_SECRET"),
        "a different companion secret leaked into the request: {value:?}"
    );
}

#[test]
fn companion_value_carrying_match_token_not_expanded() {
    let (headers, _) = TestApi.built_request_header_body_for_test(
        &[("x-h", "{{companion.a}}")],
        None,
        "REAL_CREDENTIAL",
        &comps(&[("a", "{{match}}")]),
    );
    let value = header_value(&headers, "x-h").expect("x-h present");
    assert_eq!(value, "{{match}}");
    assert!(
        !value.contains("REAL_CREDENTIAL"),
        "the match value leaked through a companion token: {value:?}"
    );
}

#[test]
fn missing_companion_yields_empty_not_leak() {
    let (headers, _) = TestApi.built_request_header_body_for_test(
        &[("x-h", "{{companion.none}}")],
        None,
        "cred",
        &HashMap::new(),
    );
    assert_eq!(header_value(&headers, "x-h").as_deref(), Some(""));
}

// ── multiple headers + interleaved tokens ───────────────────────────────────

#[test]
fn multiple_headers_all_sanitized() {
    let (headers, _) = TestApi.built_request_header_body_for_test(
        &[
            ("authorization", "Bearer {{match}}"),
            ("x-api-key", "{{match}}"),
        ],
        None,
        "a\r\nb",
        &HashMap::new(),
    );
    assert_no_bare_crlf(&headers);
    assert_eq!(
        header_value(&headers, "authorization").as_deref(),
        Some("Bearer ab")
    );
    assert_eq!(header_value(&headers, "x-api-key").as_deref(), Some("ab"));
}

#[test]
fn crlf_between_two_match_tokens_in_one_value() {
    let (headers, _) = TestApi.built_request_header_body_for_test(
        &[("x-h", "{{match}}|{{match}}")],
        None,
        "a\r\nb",
        &HashMap::new(),
    );
    assert_no_bare_crlf(&headers);
    assert_eq!(header_value(&headers, "x-h").as_deref(), Some("ab|ab"));
}

// ── the request body is sanitized on the same boundary ──────────────────────

#[test]
fn body_crlf_stripped() {
    let (_, body) = TestApi.built_request_header_body_for_test(
        &[],
        Some("token={{match}}"),
        "a\r\nb",
        &HashMap::new(),
    );
    assert_eq!(body.as_deref(), Some("token=ab"));
}

#[test]
fn body_control_bytes_stripped() {
    let (_, body) = TestApi.built_request_header_body_for_test(
        &[],
        Some("{{match}}"),
        "a\u{0}\u{1f}b",
        &HashMap::new(),
    );
    assert_eq!(body.as_deref(), Some("ab"));
}

#[test]
fn body_second_order_companion_not_expanded() {
    let (_, body) = TestApi.built_request_header_body_for_test(
        &[],
        Some("{{match}}"),
        "{{companion.s}}",
        &comps(&[("s", "LEAK")]),
    );
    assert_eq!(body.as_deref(), Some("{{companion.s}}"));
    assert!(
        !body.unwrap_or_default().contains("LEAK"),
        "companion secret leaked into the request body"
    );
}

#[test]
fn body_plain_match_substituted() {
    let (_, body) = TestApi.built_request_header_body_for_test(
        &[],
        Some("grant_type=token&secret={{match}}"),
        "s3cr3t",
        &HashMap::new(),
    );
    assert_eq!(body.as_deref(), Some("grant_type=token&secret=s3cr3t"));
}
