//! Standalone coverage for the verifier's template-interpolation surface:
//! `interpolate::{resolve_field, interpolate, sanitize_oob_value,
//! sanitize_raw_value, companions_with_oob}` plus the `OOB_COMPANION_*`
//! constants.
//!
//! Each assertion pins the exact rendered string for a concrete template +
//! credential + companion map: the URL-encoded form, the control-stripped
//! form, the DNS-charset-filtered form. No `is_ok()` / `!is_empty()`.

use keyhog_verifier::testing::{TestApi, VerifierTestApi};
use std::collections::HashMap;

const OOB_COMPANION_URL: &str = <TestApi as VerifierTestApi>::OOB_COMPANION_URL;
const OOB_COMPANION_HOST: &str = <TestApi as VerifierTestApi>::OOB_COMPANION_HOST;
const OOB_COMPANION_ID: &str = <TestApi as VerifierTestApi>::OOB_COMPANION_ID;

fn companions(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

// ===========================================================================
// resolve_field
// ===========================================================================

#[test]
fn resolve_field_match_returns_credential() {
    let c = companions(&[]);
    assert_eq!(
        TestApi.resolve_field("match", "ghp_secretvalue", &c),
        "ghp_secretvalue"
    );
}

#[test]
fn resolve_field_companion_returns_named_value() {
    let c = companions(&[("client_id", "abc123"), ("client_secret", "xyz789")]);
    assert_eq!(
        TestApi.resolve_field("companion.client_id", "cred", &c),
        "abc123"
    );
    assert_eq!(
        TestApi.resolve_field("companion.client_secret", "cred", &c),
        "xyz789"
    );
}

#[test]
fn resolve_field_missing_companion_is_empty() {
    let c = companions(&[("present", "v")]);
    assert_eq!(
        TestApi.resolve_field("companion.absent", "cred", &c),
        "",
        "an absent companion resolves to the empty string, not the credential"
    );
}

#[test]
fn resolve_field_empty_string_is_empty() {
    let c = companions(&[]);
    assert_eq!(TestApi.resolve_field("", "cred", &c), "");
}

#[test]
fn resolve_field_literal_passthrough() {
    let c = companions(&[]);
    // Anything not `match`, `companion.*`, or `""` is a literal.
    assert_eq!(
        TestApi.resolve_field("application/json", "cred", &c),
        "application/json"
    );
    assert_eq!(TestApi.resolve_field("Bearer", "cred", &c), "Bearer");
}

// ===========================================================================
// sanitize_oob_value: DNS-hostname charset filter
// ===========================================================================

#[test]
fn sanitize_oob_keeps_dns_charset() {
    assert_eq!(
        TestApi.sanitize_oob_value("abc123.example-host.com"),
        "abc123.example-host.com"
    );
}

#[test]
fn sanitize_oob_folds_uppercase_to_lower() {
    assert_eq!(
        TestApi.sanitize_oob_value("ABC.Example.COM"),
        "abc.example.com"
    );
}

#[test]
fn sanitize_oob_drops_structural_punctuation() {
    // Slash, colon, query, fragment, at, quotes, angle brackets, space (all dropped).
    assert_eq!(
        TestApi.sanitize_oob_value("evil.com/path?x=1#frag"),
        "evil.compathx1frag"
    );
    // a @ b : c " d ' e < f > g <space> h  -> only [a-z0-9.-] survive:
    // a b c d e f g h  (the space between g and h is dropped too).
    assert_eq!(TestApi.sanitize_oob_value("a@b:c\"d'e<f>g h"), "abcdefgh");
}

#[test]
fn sanitize_oob_drops_control_bytes() {
    assert_eq!(TestApi.sanitize_oob_value("host\r\n\t.com"), "host.com");
    assert_eq!(TestApi.sanitize_oob_value("a\0b.com"), "ab.com");
}

#[test]
fn sanitize_oob_empty_stays_empty() {
    assert_eq!(TestApi.sanitize_oob_value(""), "");
    // A string of ONLY disallowed chars collapses to empty.
    assert_eq!(TestApi.sanitize_oob_value("///???"), "");
}

// ===========================================================================
// sanitize_raw_value, control-byte stripping
// ===========================================================================

#[test]
fn sanitize_raw_strips_crlf() {
    assert_eq!(
        TestApi.sanitize_raw_value("token\r\nHeader: injected"),
        "tokenHeader: injected",
        "CRLF must be stripped to defeat header injection"
    );
}

#[test]
fn sanitize_raw_strips_nul_del_bel_esc() {
    assert_eq!(TestApi.sanitize_raw_value("a\0b\x7Fc\x07d\x1Be"), "abcde");
}

#[test]
fn sanitize_raw_strips_c1_controls() {
    // 0x80..=0x9F C1 controls.
    let input = format!("x{}y{}z", '\u{0085}', '\u{009F}');
    assert_eq!(TestApi.sanitize_raw_value(&input), "xyz");
}

#[test]
fn sanitize_raw_keeps_tab() {
    // Tab (0x09) is explicitly allowed.
    assert_eq!(TestApi.sanitize_raw_value("a\tb"), "a\tb");
}

#[test]
fn sanitize_raw_keeps_normal_credential() {
    let cred = "ghp_AbC123_-.xyz/+=";
    assert_eq!(
        TestApi.sanitize_raw_value(cred),
        cred,
        "a normal credential must pass through unchanged"
    );
}

#[test]
fn sanitize_raw_keeps_unicode_above_c1() {
    // Non-control Unicode (e.g. é, emoji) is preserved.
    assert_eq!(TestApi.sanitize_raw_value("café"), "café");
}

// ===========================================================================
// interpolate: {{match}} fast paths and URL-encoding
// ===========================================================================

#[test]
fn interpolate_bare_match_is_raw_sanitized_not_url_encoded() {
    // The exact-match fast path returns the RAW (control-stripped) credential,
    // NOT URL-encoded (used for header/body values).
    let c = companions(&[]);
    assert_eq!(
        TestApi.interpolate("{{match}}", "a+b/c=d", &c),
        "a+b/c=d",
        "bare {{match}} must NOT url-encode"
    );
    // Control bytes still stripped on this path.
    assert_eq!(TestApi.interpolate("{{match}}", "tok\r\nen", &c), "token");
}

#[test]
fn interpolate_match_inside_url_is_url_encoded() {
    // When embedded in a larger template the value IS url-encoded.
    let c = companions(&[]);
    assert_eq!(
        TestApi.interpolate("https://api.example.com/v1/{{match}}", "a+b/c", &c),
        "https://api.example.com/v1/a%2Bb%2Fc",
        "embedded {{match}} must be percent-encoded"
    );
}

#[test]
fn interpolate_url_context_embedded_match_is_url_encoded() {
    let c = companions(&[]);
    assert_eq!(
        TestApi.interpolate_url("https://api.example.com/v1/{{match}}", "a+b/c=d", &c),
        "https://api.example.com/v1/a%2Bb%2Fc%3Dd"
    );
}

#[test]
fn interpolate_http_value_context_embedded_match_is_raw_sanitized() {
    let c = companions(&[]);
    assert_eq!(
        TestApi.interpolate_http_value("Bearer {{match}}", "a+b/c=d", &c),
        "Bearer a+b/c=d",
        "header/body interpolation must not percent-encode valid credential bytes"
    );
    assert_eq!(
        TestApi.interpolate_http_value("Bearer {{match}}", "tok\r\nen", &c),
        "Bearer token",
        "HTTP value interpolation still strips control bytes"
    );
}

#[test]
fn interpolate_bare_companion_is_raw_sanitized() {
    let c = companions(&[("secret", "a+b/c")]);
    assert_eq!(
        TestApi.interpolate("{{companion.secret}}", "cred", &c),
        "a+b/c",
        "bare {{companion.x}} returns raw control-stripped value"
    );
}

#[test]
fn interpolate_companion_inside_template_is_url_encoded() {
    let c = companions(&[("secret", "a b")]);
    assert_eq!(
        TestApi.interpolate("k={{companion.secret}}&z=1", "cred", &c),
        "k=a%20b&z=1"
    );
}

#[test]
fn interpolate_http_value_context_embedded_companion_is_raw_sanitized() {
    let c = companions(&[("secret", "a+b/c=d")]);
    assert_eq!(
        TestApi.interpolate_http_value("X-Key {{companion.secret}}", "cred", &c),
        "X-Key a+b/c=d"
    );
}

#[test]
fn interpolate_missing_companion_renders_empty() {
    let c = companions(&[]);
    assert_eq!(
        TestApi.interpolate("x={{companion.absent}}", "cred", &c),
        "x="
    );
}

#[test]
fn interpolate_multiple_companions() {
    let c = companions(&[("a", "1"), ("b", "2")]);
    assert_eq!(
        TestApi.interpolate("{{companion.a}}-{{companion.b}}", "cred", &c),
        "1-2"
    );
}

#[test]
fn interpolate_no_placeholders_is_identity() {
    let c = companions(&[]);
    assert_eq!(
        TestApi.interpolate("https://static.example.com/health", "cred", &c),
        "https://static.example.com/health"
    );
}

#[test]
fn interpolate_oob_host_token_substituted_and_sanitized() {
    // The OOB host token is substituted WITHOUT url-encoding but IS
    // DNS-charset sanitized.
    let mut c = companions(&[]);
    c.insert(
        OOB_COMPANION_HOST.to_string(),
        "abc.oob-server.example".to_string(),
    );
    assert_eq!(
        TestApi.interpolate("https://{{interactsh}}/cb", "cred", &c),
        "https://abc.oob-server.example/cb"
    );
}

#[test]
fn interpolate_oob_host_hostile_punctuation_is_stripped() {
    // A hostile host carrying structural punctuation is cleaned at the
    // substitution boundary.
    let mut c = companions(&[]);
    c.insert(
        OOB_COMPANION_HOST.to_string(),
        "abc.evil.com/@inject".to_string(),
    );
    assert_eq!(
        TestApi.interpolate("https://{{interactsh.host}}/cb", "cred", &c),
        "https://abc.evil.cominject/cb",
        "structural punctuation in the OOB host must be dropped"
    );
}

#[test]
fn interpolate_oob_url_keeps_scheme_sanitizes_host() {
    let mut c = companions(&[]);
    c.insert(
        OOB_COMPANION_URL.to_string(),
        "https://abc.OOB.example/Path".to_string(),
    );
    // Scheme preserved; host lowercased + path-punct stripped after the host.
    assert_eq!(
        TestApi.interpolate("{{interactsh.url}}", "cred", &c),
        "https://abc.oob.examplepath"
    );
}

// ===========================================================================
// companions_with_oob + constants
// ===========================================================================

#[test]
fn companions_with_oob_injects_three_reserved_keys() {
    let base = companions(&[("existing", "kept")]);
    let out =
        TestApi.companions_with_oob(&base, "host.example", "https://host.example/u", "corrid");
    assert_eq!(out.get("existing").map(String::as_str), Some("kept"));
    assert_eq!(
        out.get(OOB_COMPANION_HOST).map(String::as_str),
        Some("host.example")
    );
    assert_eq!(
        out.get(OOB_COMPANION_URL).map(String::as_str),
        Some("https://host.example/u")
    );
    assert_eq!(
        out.get(OOB_COMPANION_ID).map(String::as_str),
        Some("corrid")
    );
}

#[test]
fn oob_companion_constants_are_reserved_names() {
    assert_eq!(OOB_COMPANION_URL, "__keyhog_oob_url");
    assert_eq!(OOB_COMPANION_HOST, "__keyhog_oob_host");
    assert_eq!(OOB_COMPANION_ID, "__keyhog_oob_id");
}

#[test]
fn companions_with_oob_does_not_mutate_base() {
    let base = companions(&[("k", "v")]);
    let _ = TestApi.companions_with_oob(&base, "h", "u", "i");
    assert_eq!(base.len(), 1, "the base map must be left untouched");
    assert!(!base.contains_key(OOB_COMPANION_HOST));
}
