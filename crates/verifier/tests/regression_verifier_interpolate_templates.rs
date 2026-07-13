//! Regression coverage for the verifier's template-EXPANSION edge cases in
//! `interpolate::interpolate{,_url,_http_value}`.
//!
//! Distinct from `new_verifier_interpolate.rs` (which pins the per-context
//! encoding of a single token) and from the iter3 allowlist tests: this file
//! nails the *structural* expansion contract
//!   * multiple / adjacent / repeated `{{var}}` tokens expand independently,
//!   * an empty-VALUE companion expands to the empty string (not the token),
//!   * an UNDEFINED / unrecognized token is preserved VERBATIM (recall-safe;
//!     the interpolator never errors: LAW10), and
//!   * a literal `{{` with no closing `}}` and a `{{}}` empty token survive
//!     unchanged, and a token-shaped *value* is never re-expanded (one-pass).
//!
//! Every assertion pins an EXACT rendered string. `url_encode` uses the
//! `NON_ALPHANUMERIC` set, so a space -> `%20`, `/` -> `%2F` in URL context;
//! header/body context control-strips but does not percent-encode.

use keyhog_verifier::testing::{TestApi, VerifierTestApi};
use std::collections::HashMap;

const OOB_COMPANION_ID: &str = <TestApi as VerifierTestApi>::OOB_COMPANION_ID;

fn companions(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

// ===========================================================================
// Multiple / adjacent / repeated tokens expand independently
// ===========================================================================

#[test]
fn adjacent_match_tokens_each_expand_url_encoded() {
    // `{{match}}{{match}}` is NOT the exact-equality fast path, so it goes
    // through the general URL loop and each token is percent-encoded.
    let c = companions(&[]);
    assert_eq!(
        TestApi.interpolate("{{match}}{{match}}", "a b", &c),
        "a%20ba%20b",
        "two adjacent {{match}} tokens each url-encode the same credential"
    );
}

#[test]
fn adjacent_companion_tokens_expand_independently() {
    let c = companions(&[("a", "x/y"), ("b", "z w")]);
    assert_eq!(
        TestApi.interpolate("{{companion.a}}{{companion.b}}", "cred", &c),
        "x%2Fyz%20w",
        "adjacent companion tokens with no separator each expand + url-encode"
    );
}

#[test]
fn distinct_match_and_companion_expand_in_url() {
    // A URL with a match segment AND a companion query value: both are
    // url-encoded, the literal path/query text is left untouched.
    let c = companions(&[("a", "v 1")]);
    assert_eq!(
        TestApi.interpolate("https://h/{{match}}?k={{companion.a}}", "m/1", &c),
        "https://h/m%2F1?k=v%201"
    );
}

#[test]
fn repeated_same_companion_expands_each_occurrence() {
    let c = companions(&[("a", "Z")]);
    assert_eq!(
        TestApi.interpolate(
            "{{companion.a}}-{{companion.a}}-{{companion.a}}",
            "cred",
            &c
        ),
        "Z-Z-Z"
    );
}

#[test]
fn tail_text_after_last_token_is_preserved() {
    // The remainder after the final resolved token must be copied verbatim.
    let c = companions(&[]);
    assert_eq!(
        TestApi.interpolate("{{match}}/suffix/path", "a b", &c),
        "a%20b/suffix/path"
    );
}

#[test]
fn match_with_trailing_char_is_not_fast_path_and_is_url_encoded() {
    // Only the EXACT template `{{match}}` hits the raw fast path; one extra
    // byte forces the general (url-encoding) loop.
    let c = companions(&[]);
    assert_eq!(
        TestApi.interpolate("{{match}}x", "a/b", &c),
        "a%2Fbx",
        "trailing byte defeats the exact-match fast path -> value is url-encoded"
    );
}

// ===========================================================================
// Empty-VALUE vars expand to empty (not to the token text)
// ===========================================================================

#[test]
fn empty_value_companion_renders_empty_in_url_context() {
    let c = companions(&[("e", "")]);
    assert_eq!(
        TestApi.interpolate("p={{companion.e}}&q=1", "cred", &c),
        "p=&q=1",
        "a present-but-empty companion expands to the empty string in URL context"
    );
}

#[test]
fn empty_value_companion_renders_empty_in_http_value_context() {
    let c = companions(&[("e", "")]);
    assert_eq!(
        TestApi.interpolate_http_value("X-Token: {{companion.e}}", "cred", &c),
        "X-Token: "
    );
}

#[test]
fn bare_empty_value_companion_fast_path_is_empty_string() {
    // The bare-companion fast path (`{{companion.e}}` verbatim) returns the
    // raw value; an empty value yields exactly "".
    let c = companions(&[("e", "")]);
    assert_eq!(TestApi.interpolate("{{companion.e}}", "cred", &c), "");
}

// ===========================================================================
// UNDEFINED / unrecognized tokens are preserved VERBATIM (never error)
// ===========================================================================

#[test]
fn undefined_companion_renders_empty_not_error() {
    // An undefined companion is NOT an error (it expands to empty (recall-safe)).
    let c = companions(&[("present", "v")]);
    assert_eq!(
        TestApi.interpolate("a={{companion.absent}}!", "cred", &c),
        "a=!",
        "undefined companion collapses to empty; surrounding literals survive"
    );
}

#[test]
fn unrecognized_token_kept_verbatim() {
    // A token that is neither match / companion.* / interactsh.* is emitted
    // unchanged, braces intact.
    let c = companions(&[]);
    assert_eq!(
        TestApi.interpolate("a{{unknown}}b", "cred", &c),
        "a{{unknown}}b"
    );
}

#[test]
fn token_name_is_case_sensitive() {
    // `{{Match}}` is not `{{match}}`; it is an unrecognized token, kept verbatim.
    let c = companions(&[]);
    assert_eq!(
        TestApi.interpolate("{{Match}}", "secretcred", &c),
        "{{Match}}",
        "token matching is case-sensitive; wrong case is not expanded"
    );
}

#[test]
fn interactsh_subtoken_not_a_companion_is_verbatim() {
    // `interactsh.foo` is not a recognized OOB token and does not start with
    // `companion.`, so it is left verbatim.
    let c = companions(&[]);
    assert_eq!(
        TestApi.interpolate("cb={{interactsh.foo}}", "cred", &c),
        "cb={{interactsh.foo}}"
    );
}

// ===========================================================================
// Escapes / degenerate braces survive unchanged
// ===========================================================================

#[test]
fn empty_token_braces_kept_verbatim() {
    // `{{}}` has an empty inner name -> unrecognized -> preserved.
    let c = companions(&[]);
    assert_eq!(TestApi.interpolate("x{{}}y", "cred", &c), "x{{}}y");
}

#[test]
fn unterminated_open_brace_preserved_as_literal() {
    // A `{{` with no closing `}}` terminates the scan and the whole remainder
    // (including the `{{`) is copied verbatim (nothing is dropped).
    let c = companions(&[]);
    assert_eq!(
        TestApi.interpolate("cost is {{ dollars", "cred", &c),
        "cost is {{ dollars"
    );
}

#[test]
fn spaced_match_token_is_not_recognized() {
    // Whitespace inside the braces (`{{ match }}`) is not the `match` token.
    let c = companions(&[]);
    assert_eq!(
        TestApi.interpolate("{{ match }}", "leakme", &c),
        "{{ match }}",
        "inner whitespace defeats token recognition; kept verbatim, no leak"
    );
}

// ===========================================================================
// One-pass: a token-shaped VALUE is never re-expanded (no companion cross-leak)
// ===========================================================================

#[test]
fn token_shaped_value_is_not_re_expanded() {
    // A companion whose VALUE looks like another `{{companion.*}}` token must
    // stay literal, the single left-to-right pass never re-reads substituted
    // output, so `secret` cannot leak.
    let c = companions(&[("inj", "{{companion.secret}}"), ("secret", "TOPSECRET")]);
    let out = TestApi.interpolate_http_value("X: {{companion.inj}}", "cred", &c);
    assert_eq!(
        out, "X: {{companion.secret}}",
        "the substituted value is inert; the inner token is not re-expanded"
    );
    assert!(
        !out.contains("TOPSECRET"),
        "the second companion secret must never leak into the output"
    );
}

// ===========================================================================
// OOB id token expansion + DNS-charset sanitation at the boundary
// ===========================================================================

#[test]
fn interactsh_id_token_expands_and_sanitizes() {
    let mut c = companions(&[]);
    c.insert(OOB_COMPANION_ID.to_string(), "CORR/123".to_string());
    // Uppercase folded to lower, `/` dropped (DNS-hostname charset).
    assert_eq!(
        TestApi.interpolate("id={{interactsh.id}}", "cred", &c),
        "id=corr123"
    );
}
