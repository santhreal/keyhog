//! Migrated from src/interpolate.rs (KH-GAP-004): OOB-host sanitization at the
//! interpolation boundary - structural punctuation must be stripped so a
//! hostile `--oob-server` cannot escape a JSON/URL/header template, while a
//! legal host passes through unchanged.

use keyhog_verifier::interpolate::{companions_with_oob, interpolate};
use keyhog_verifier::testing::sanitize_oob_value;
use std::collections::HashMap;

// disc audit (security.LOW.interpolate): a hostile `--oob-server` whose host
// carries structural punctuation must not be injected verbatim into a
// body/header/URL template. The substitution boundary enforces the
// `[a-z0-9.-]` invariant the no-encode comment relies on.
#[test]
fn oob_host_structural_chars_stripped() {
    // Operator-supplied collector host carrying a path-break, query, and quote
    // that would otherwise escape the JSON string / URL structure.
    let hostile_host = "abc123.evil.com/x?q=1\"";
    let comps = companions_with_oob(
        &HashMap::new(),
        hostile_host,
        &format!("https://{hostile_host}"),
        "abc123",
    );

    let body = interpolate("{\"u\":\"https://{{interactsh}}/cb\"}", "cred", &comps);
    // No structural byte from the hostile host survives into the output.
    assert!(!body.contains('?'), "query separator leaked: {body}");
    assert!(!body.contains("?q=1"), "query string leaked: {body}");
    // Exactly the template's own 4 quotes remain; none injected by the host.
    assert_eq!(
        body.matches('"').count(),
        4,
        "stray quote leaked into JSON: {body}"
    );
    // The slash present in the output is only the template's own `/cb`, never
    // the injected `/x`.
    assert!(!body.contains("/x"), "injected path leaked: {body}");
    assert!(
        body.contains("abc123.evil.com"),
        "legit host bytes dropped: {body}"
    );

    let url = interpolate("{{interactsh.url}}/cb", "cred", &comps);
    // Scheme preserved; the host is sanitized to the DNS charset by DROPPING
    // out-of-set bytes (not truncating - see sanitize_oob_value_charset), so the
    // injected `/x?q=1"` collapses to harmless host bytes and the template's own
    // `/cb` is the only path. The security property is "no structural byte
    // (`/ ? "`) from the hostile host survives into URL structure", not a
    // specific truncated host string.
    assert!(
        url.starts_with("https://abc123.evil.com"),
        "scheme/host malformed: {url}"
    );
    assert!(url.ends_with("/cb"), "template path lost: {url}");
    assert!(!url.contains('?'), "query separator leaked into url: {url}");
    assert!(!url.contains("/x"), "injected path leaked into url: {url}");
    assert!(!url.contains('"'), "quote leaked into url: {url}");
}

// Positive twin: a well-formed collector host and id pass through the no-encode
// path unchanged (sanitization is identity on legal input).
#[test]
fn oob_legit_host_passes_through() {
    let comps = companions_with_oob(
        &HashMap::new(),
        "deadbeefcafe0.oast.fun",
        "https://deadbeefcafe0.oast.fun",
        "deadbeefcafe0",
    );
    assert_eq!(
        interpolate("h={{interactsh.host}}", "cred", &comps),
        "h=deadbeefcafe0.oast.fun"
    );
    assert_eq!(
        interpolate("u={{interactsh.url}}", "cred", &comps),
        "u=https://deadbeefcafe0.oast.fun"
    );
    assert_eq!(
        interpolate("id={{interactsh.id}}", "cred", &comps),
        "id=deadbeefcafe0"
    );
    assert_eq!(
        interpolate("https://{{interactsh}}/p", "cred", &comps),
        "https://deadbeefcafe0.oast.fun/p"
    );
}

#[test]
fn sanitize_oob_value_charset() {
    // Folds case, keeps `[a-z0-9.-]`, drops everything else.
    assert_eq!(sanitize_oob_value("AbC-1.2_x/y@z "), "abc-1.2xyz");
    assert_eq!(
        sanitize_oob_value("good.host-1.oast.fun"),
        "good.host-1.oast.fun"
    );
    assert_eq!(sanitize_oob_value("\u{0}\u{7f}<>'\""), "");
}
