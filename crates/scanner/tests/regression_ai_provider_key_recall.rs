//! AI-provider API-key recall + precision lock: OpenAI and Anthropic, the two
//! most commonly leaked modern credential families, which had no dedicated recall
//! test (only a single OpenAI HTML-comment bug regression existed).
//!
//! OpenAI (`openai-api-key`) has four shapes: `sk-proj-`, `sk-svcacct-`,
//! `sk-admin-` (url-safe bodies, 40+ chars) and a legacy `sk-`+48-alnum form.
//!
//! Anthropic (`anthropic-api-key`) has TWO patterns that together cover the whole
//! family without overlap:
//!   1. `sk-ant-api03-<80..120 url-safe>`: the documented api03 form.
//!   2. a "modern" `sk-ant-<80..120 url-safe>` form whose alternation deliberately
//!      EXCLUDES bodies beginning `api03-` (so pattern 1 owns those). This second
//!      pattern was added because the api03 regex matched zero of 40 modern
//!      `sk-ant-` fixtures (i.e. it is itself a recall fix worth locking).
//! Neither family is checksum-gated (no `sk-`/`sk-ant-` validator), so fabricated
//! high-entropy fixtures surface; the precision floors are pure length/charset.

mod support;
use support::contracts::{make_chunk, scanner};

use keyhog_core::Chunk;
use keyhog_scanner::CompiledScanner;

/// Deterministic high-entropy string of length `n` over `charset` (seeded LCG)
/// avoids dictionary/low-entropy suppression that would mask a real recall gap.
fn gen(n: usize, seed: usize, charset: &[u8]) -> String {
    let m = charset.len() as u64;
    let mut s = (seed as u64)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0x2C91_7E03);
    (0..n)
        .map(|_| {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            charset[((s >> 33) % m) as usize] as char
        })
        .collect()
}
fn alnum(n: usize, seed: usize) -> String {
    gen(
        n,
        seed,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    )
}
fn b64url(n: usize, seed: usize) -> String {
    gen(
        n,
        seed,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
    )
}

/// A modern (non-api03) Anthropic key body: a leading uppercase char keeps it out
/// of the `a…`/`api03-` alternation branches, so it matches pattern 2 cleanly.
fn anthropic_modern(body_len: usize, seed: usize) -> String {
    format!("sk-ant-M{}", b64url(body_len - 1, seed))
}

fn scan(text: &str) -> Vec<(String, String)> {
    let s: &CompiledScanner = &scanner();
    let chunk: Chunk = make_chunk(text, "source", "ai.env");
    s.clear_fragment_cache();
    s.scan(&chunk)
        .into_iter()
        .map(|m| (m.detector_id.to_string(), m.credential.to_string()))
        .collect()
}
fn surfaces_under(text: &str, detector: &str, needle: &str) -> bool {
    scan(text)
        .iter()
        .any(|(id, cred)| id == detector && cred.contains(needle))
}
fn fires(text: &str, detector: &str) -> bool {
    scan(text).iter().any(|(id, _)| id == detector)
}

// ── OpenAI key forms ──────────────────────────────────────────────────────────

#[test]
fn openai_project_key_surfaces() {
    let t = format!("sk-proj-{}", b64url(48, 1));
    assert!(
        surfaces_under(&t, "openai-api-key", &t),
        "sk-proj- key must surface"
    );
}

#[test]
fn openai_service_account_key_surfaces() {
    let t = format!("sk-svcacct-{}", b64url(48, 2));
    assert!(
        surfaces_under(&t, "openai-api-key", &t),
        "sk-svcacct- key must surface"
    );
}

#[test]
fn openai_admin_key_surfaces() {
    let t = format!("sk-admin-{}", b64url(48, 3));
    assert!(
        surfaces_under(&t, "openai-api-key", &t),
        "sk-admin- key must surface"
    );
}

#[test]
fn openai_legacy_48_char_key_surfaces() {
    let t = format!("sk-{}", alnum(48, 4));
    assert!(
        surfaces_under(&t, "openai-api-key", &t),
        "legacy sk-<48 alnum> key must surface"
    );
}

#[test]
fn openai_project_key_env_anchor_surfaces() {
    let t = format!("sk-proj-{}", b64url(48, 5));
    assert!(surfaces_under(
        &format!("OPENAI_API_KEY={t}"),
        "openai-api-key",
        &t
    ));
}

#[test]
fn openai_project_key_in_yaml_surfaces() {
    let t = format!("sk-proj-{}", b64url(48, 6));
    assert!(surfaces_under(
        &format!("openai:\n  api_key: {t}\n"),
        "openai-api-key",
        &t
    ));
}

// ── OpenAI boundaries ─────────────────────────────────────────────────────────

#[test]
fn openai_project_key_min_40_surfaces() {
    let t = format!("sk-proj-{}", b64url(40, 7)); // 40 = pattern minimum
    assert!(surfaces_under(&t, "openai-api-key", &t));
}

#[test]
fn openai_project_key_max_164_surfaces() {
    let t = format!("sk-proj-{}", b64url(164, 8)); // 164 = proj maximum
    assert!(surfaces_under(&t, "openai-api-key", &t));
}

#[test]
fn openai_service_account_key_max_200_surfaces() {
    let t = format!("sk-svcacct-{}", b64url(200, 9)); // 200 = svcacct maximum
    assert!(surfaces_under(&t, "openai-api-key", &t));
}

// ── OpenAI precision: near-misses must not fire ───────────────────────────────

#[test]
fn openai_legacy_47_char_does_not_fire() {
    // The legacy form is exactly 48 alnum after `sk-`; 47 is one short, and the
    // url-safe `proj/svcacct/admin` patterns need their literal prefixes.
    let t = format!("sk-{}", alnum(47, 10));
    assert!(!fires(&t, "openai-api-key"));
}

#[test]
fn openai_project_below_40_does_not_fire() {
    let t = format!("sk-proj-{}", b64url(30, 11)); // 30 < 40 minimum
    assert!(!fires(&t, "openai-api-key"));
}

#[test]
fn openai_sk_prose_mention_does_not_fire() {
    assert!(!fires(
        "Paste your sk- secret key from the OpenAI dashboard here.",
        "openai-api-key"
    ));
}

// ── Anthropic api03 form (pattern 1) ──────────────────────────────────────────

#[test]
fn anthropic_api03_key_surfaces() {
    let t = format!("sk-ant-api03-{}", b64url(90, 12));
    assert!(
        surfaces_under(&t, "anthropic-api-key", &t),
        "sk-ant-api03- key must surface"
    );
}

#[test]
fn anthropic_api03_key_env_anchor_surfaces() {
    let t = format!("sk-ant-api03-{}", b64url(90, 13));
    assert!(surfaces_under(
        &format!("ANTHROPIC_API_KEY={t}"),
        "anthropic-api-key",
        &t
    ));
}

#[test]
fn anthropic_api03_key_in_json_surfaces() {
    let t = format!("sk-ant-api03-{}", b64url(90, 14));
    assert!(surfaces_under(
        &format!("{{\"anthropic_api_key\":\"{t}\"}}"),
        "anthropic-api-key",
        &t
    ));
}

#[test]
fn anthropic_api03_min_80_surfaces() {
    let t = format!("sk-ant-api03-{}", b64url(80, 15)); // 80 = pattern minimum
    assert!(surfaces_under(&t, "anthropic-api-key", &t));
}

#[test]
fn anthropic_api03_max_120_surfaces() {
    let t = format!("sk-ant-api03-{}", b64url(120, 16)); // 120 = pattern maximum
    assert!(surfaces_under(&t, "anthropic-api-key", &t));
}

// ── Anthropic modern form (pattern 2, the api03-excluding recall fix) ──────────

#[test]
fn anthropic_modern_key_surfaces() {
    let t = anthropic_modern(90, 17);
    assert!(
        surfaces_under(&t, "anthropic-api-key", &t),
        "modern sk-ant- key must surface"
    );
}

#[test]
fn anthropic_modern_key_env_anchor_surfaces() {
    let t = anthropic_modern(90, 18);
    assert!(surfaces_under(
        &format!("ANTHROPIC_API_KEY={t}"),
        "anthropic-api-key",
        &t
    ));
}

#[test]
fn anthropic_modern_min_80_surfaces() {
    let t = anthropic_modern(80, 19); // body = 80 (pattern-2 minimum)
    assert!(surfaces_under(&t, "anthropic-api-key", &t));
}

#[test]
fn anthropic_api03_prefix_without_dash_surfaces_via_modern() {
    // `sk-ant-api03X…` (6th body char is NOT `-`) is owned by pattern 2's `api03`
    // alternation branch, NOT pattern 1 (this pins that branch specifically).
    let t = format!("sk-ant-api03M{}", b64url(74, 20)); // body = api03M(6) + 74 = 80
    assert!(surfaces_under(&t, "anthropic-api-key", &t));
}

// ── Anthropic precision: near-misses under BOTH patterns must not fire ─────────

#[test]
fn anthropic_api03_below_80_does_not_fire() {
    // body 60 < 80: pattern 1 needs {80,120}; and `api03-…` is excluded from
    // pattern 2's alternation, so neither matches.
    let t = format!("sk-ant-api03-{}", b64url(60, 21));
    assert!(!fires(&t, "anthropic-api-key"));
}

#[test]
fn anthropic_modern_79_body_does_not_fire() {
    let t = anthropic_modern(79, 22); // body 79 < 80 pattern-2 minimum
    assert!(!fires(&t, "anthropic-api-key"));
}

#[test]
fn anthropic_api03_broken_by_space_does_not_fire() {
    // A space at offset 40 truncates the contiguous url-safe run below both the
    // pattern-1 (80) and pattern-2 (80) minimums.
    let body = b64url(90, 23);
    let broken = format!("{} {}", &body[..40], &body[41..]);
    assert!(!fires(
        &format!("sk-ant-api03-{broken}"),
        "anthropic-api-key"
    ));
}

// ── cross: OpenAI + Anthropic co-surface in one chunk ─────────────────────────

#[test]
fn openai_and_anthropic_api03_cosurface() {
    let o = format!("sk-proj-{}", b64url(48, 24));
    let a = format!("sk-ant-api03-{}", b64url(90, 25));
    let text = format!("OPENAI_API_KEY={o}\nANTHROPIC_API_KEY={a}\n");
    assert!(
        surfaces_under(&text, "openai-api-key", &o),
        "openai surfaces alongside anthropic"
    );
    assert!(
        surfaces_under(&text, "anthropic-api-key", &a),
        "anthropic surfaces alongside openai"
    );
}

#[test]
fn openai_legacy_and_anthropic_modern_cosurface() {
    let o = format!("sk-{}", alnum(48, 26));
    let a = anthropic_modern(90, 27);
    let text = format!("legacy={o}\nmodern={a}\n");
    assert!(
        surfaces_under(&text, "openai-api-key", &o),
        "legacy openai surfaces alongside modern anthropic"
    );
    assert!(
        surfaces_under(&text, "anthropic-api-key", &a),
        "modern anthropic surfaces alongside legacy openai"
    );
}
