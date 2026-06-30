//! Template interpolation must be SINGLE-PASS: a substituted value (the scanned
//! credential or a companion — both untrusted, attacker-influenceable content)
//! must never itself be re-scanned for `{{…}}` placeholders.
//!
//! The prior three-phase replace (match → interactsh → companion) ran each phase
//! over the already-substituted string. The header/body context control-strips
//! values but does NOT percent-encode them, so a `{{match}}` whose scanned value
//! was literally `{{companion.other}}` kept its braces and the following
//! companion phase expanded it — exfiltrating a *different* companion secret into
//! the outbound request. The same held for a match value carrying
//! `{{interactsh}}`. These tests pin that no substituted value is ever
//! re-expanded, in both URL and header/body contexts, while locking every
//! legitimate substitution.

use keyhog_verifier::testing::{TestApi, VerifierTestApi};
use std::collections::HashMap;

fn comps(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

// ── second-order expansion is impossible: match value cannot inject a token ──

#[test]
fn match_value_companion_token_not_expanded_http() {
    // The scanned credential literally reads `{{companion.s}}`. It must be
    // emitted as-is, NEVER expanded to the value of companion `s`.
    let out = TestApi.interpolate_http_value(
        "Authorization: Bearer {{match}}",
        "{{companion.s}}",
        &comps(&[("s", "OTHER_SECRET")]),
    );
    assert_eq!(out, "Authorization: Bearer {{companion.s}}");
    assert!(!out.contains("OTHER_SECRET"), "leaked other secret: {out}");
}

#[test]
fn match_value_companion_token_not_expanded_url() {
    // URL context percent-encodes the braces, so the token can never re-form.
    let out = TestApi.interpolate_url(
        "https://api.example.com/?k={{match}}",
        "{{companion.s}}",
        &comps(&[("s", "OTHER_SECRET")]),
    );
    assert_eq!(out, "https://api.example.com/?k=%7B%7Bcompanion%2Es%7D%7D");
    assert!(!out.contains("OTHER_SECRET"), "leaked other secret: {out}");
    assert!(!out.contains("{{"), "raw braces survived in URL: {out}");
}

#[test]
fn match_value_interactsh_token_not_expanded_http() {
    // A match value carrying `{{interactsh}}` must NOT pull in the OOB host.
    // This is the variant the old phased replace expanded (the interactsh phase
    // ran after the match phase).
    let oob = TestApi.companions_with_oob(
        &HashMap::new(),
        "collector.oast.fun",
        "https://collector.oast.fun",
        "abc",
    );
    let out = TestApi.interpolate_http_value("X-H: {{match}}", "{{interactsh}}", &oob);
    assert_eq!(out, "X-H: {{interactsh}}");
    assert!(
        !out.contains("collector.oast.fun"),
        "OOB host leaked: {out}"
    );
}

#[test]
fn match_value_self_token_not_doubly_expanded() {
    // A match value of `{{match}}` is emitted once, literally — never recursed.
    let out = TestApi.interpolate_http_value("X: {{match}}", "{{match}}", &HashMap::new());
    assert_eq!(out, "X: {{match}}");
}

#[test]
fn companion_value_companion_token_not_expanded_http() {
    // Companion `a` resolves to `{{companion.b}}`; `b` must NOT then expand.
    let out = TestApi.interpolate_http_value(
        "X: {{companion.a}}",
        "cred",
        &comps(&[("a", "{{companion.b}}"), ("b", "LEAK")]),
    );
    assert_eq!(out, "X: {{companion.b}}");
    assert!(!out.contains("LEAK"), "chained companion leaked: {out}");
}

#[test]
fn companion_value_interactsh_token_not_expanded_http() {
    let mut base = comps(&[("a", "{{interactsh}}")]);
    let oob = TestApi.companions_with_oob(
        &std::mem::take(&mut base),
        "collector.oast.fun",
        "https://collector.oast.fun",
        "abc",
    );
    let out = TestApi.interpolate_http_value("X: {{companion.a}}", "cred", &oob);
    assert_eq!(out, "X: {{interactsh}}");
    assert!(
        !out.contains("collector.oast.fun"),
        "OOB host leaked: {out}"
    );
}

// ── legitimate substitutions still work (HttpValue context) ─────────────────

#[test]
fn http_value_plain_match_substituted() {
    let out = TestApi.interpolate_http_value("Bearer {{match}}", "tok123", &HashMap::new());
    assert_eq!(out, "Bearer tok123");
}

#[test]
fn http_value_embedded_match_control_stripped() {
    // CR/LF inside an embedded match value are stripped (header-injection guard).
    let out = TestApi.interpolate_http_value("X: {{match}} Y", "a\r\nb", &HashMap::new());
    assert_eq!(out, "X: ab Y");
}

#[test]
fn http_value_companion_substituted() {
    let out = TestApi.interpolate_http_value("X: {{companion.s}}", "c", &comps(&[("s", "v")]));
    assert_eq!(out, "X: v");
}

#[test]
fn http_value_missing_companion_is_empty() {
    let out = TestApi.interpolate_http_value("X: {{companion.none}}", "c", &HashMap::new());
    assert_eq!(out, "X: ");
}

#[test]
fn http_value_unknown_token_left_literal() {
    let out = TestApi.interpolate_http_value("X: {{unknown}}", "c", &HashMap::new());
    assert_eq!(out, "X: {{unknown}}");
}

#[test]
fn http_value_multiple_tokens_all_resolve() {
    let out =
        TestApi.interpolate_http_value("{{match}}:{{companion.s}}", "u", &comps(&[("s", "p")]));
    assert_eq!(out, "u:p");
}

#[test]
fn http_value_whole_template_match_control_stripped() {
    // Whole-template fast path: not percent-encoded, control-stripped only.
    let out = TestApi.interpolate_http_value("{{match}}", "a\r\nb", &HashMap::new());
    assert_eq!(out, "ab");
}

// ── legitimate substitutions still work (URL context) ───────────────────────

#[test]
fn url_match_percent_encoded() {
    let out = TestApi.interpolate_url("k={{match}}", "a b", &HashMap::new());
    assert_eq!(out, "k=a%20b");
}

#[test]
fn url_alphanumeric_match_unchanged() {
    let out = TestApi.interpolate_url("k={{match}}", "abc123", &HashMap::new());
    assert_eq!(out, "k=abc123");
}

// ── OOB token substitutions (unchanged charset enforcement) ─────────────────

fn legit_oob() -> HashMap<String, String> {
    TestApi.companions_with_oob(
        &HashMap::new(),
        "deadbeef.oast.fun",
        "https://deadbeef.oast.fun",
        "deadbeef",
    )
}

#[test]
fn interactsh_host_substituted() {
    let out = TestApi.interpolate_http_value("H={{interactsh.host}}", "c", &legit_oob());
    assert_eq!(out, "H=deadbeef.oast.fun");
}

#[test]
fn interactsh_url_scheme_preserved() {
    let out = TestApi.interpolate_http_value("U={{interactsh.url}}", "c", &legit_oob());
    assert_eq!(out, "U=https://deadbeef.oast.fun");
}

#[test]
fn interactsh_id_substituted() {
    let out = TestApi.interpolate_http_value("I={{interactsh.id}}", "c", &legit_oob());
    assert_eq!(out, "I=deadbeef");
}

#[test]
fn bare_interactsh_aliases_host() {
    let out = TestApi.interpolate_http_value("https://{{interactsh}}/p", "c", &legit_oob());
    assert_eq!(out, "https://deadbeef.oast.fun/p");
}

#[test]
fn interactsh_host_strips_structural_punctuation() {
    let oob = TestApi.companions_with_oob(
        &HashMap::new(),
        "abc.evil.com/x?q=1\"",
        "https://abc.evil.com/x?q=1\"",
        "abc",
    );
    let out = TestApi.interpolate_http_value("H={{interactsh.host}}", "c", &oob);
    // Only `[a-z0-9.-]` survives; the path/query/quote are dropped.
    assert_eq!(out, "H=abc.evil.comxq1");
    assert!(!out.contains('/'), "slash leaked: {out}");
    assert!(!out.contains('?'), "query leaked: {out}");
    assert!(!out.contains('"'), "quote leaked: {out}");
}

#[test]
fn interactsh_host_token_drops_scheme_separator() {
    // A host token never carries a scheme, so `://` must be stripped (unlike the
    // url token, which preserves a purely-alphabetic scheme). This is tighter
    // than the old shared scheme-split path that preserved `evil://x` verbatim.
    let oob =
        TestApi.companions_with_oob(&HashMap::new(), "evil://x", "https://evil.example", "id");
    let out = TestApi.interpolate_http_value("H={{interactsh.host}}", "c", &oob);
    assert_eq!(out, "H=evilx");
    assert!(!out.contains("://"), "scheme separator survived: {out}");
}

#[test]
fn interactsh_url_no_scheme_sanitized_whole() {
    // A minted url lacking `://` is reduced wholesale to the host charset.
    let oob = TestApi.companions_with_oob(
        &HashMap::new(),
        "host.example.com",
        "host.example.com/x?y=1",
        "id",
    );
    let out = TestApi.interpolate_http_value("U={{interactsh.url}}", "c", &oob);
    assert_eq!(out, "U=host.example.comxy1");
}

// ── structural / boundary edges ─────────────────────────────────────────────

#[test]
fn unterminated_token_left_literal() {
    let out = TestApi.interpolate_http_value("X: {{match", "c", &HashMap::new());
    assert_eq!(out, "X: {{match");
}

#[test]
fn empty_template_is_empty() {
    let out = TestApi.interpolate_http_value("", "c", &HashMap::new());
    assert_eq!(out, "");
}

#[test]
fn adjacent_match_tokens_both_resolve() {
    let out = TestApi.interpolate_http_value("{{match}}{{match}}", "ab", &HashMap::new());
    assert_eq!(out, "abab");
}

#[test]
fn unknown_token_then_match_both_handled() {
    // Interleaved unknown + known tokens: unknown stays literal, match resolves.
    let out = TestApi.interpolate_http_value("{{#if}} {{match}}", "v", &HashMap::new());
    assert_eq!(out, "{{#if}} v");
}

#[test]
fn literal_text_between_tokens_preserved() {
    let out = TestApi.interpolate_http_value(
        "a {{match}} b {{companion.s}} c",
        "M",
        &comps(&[("s", "S")]),
    );
    assert_eq!(out, "a M b S c");
}
