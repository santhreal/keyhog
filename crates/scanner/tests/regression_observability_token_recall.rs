//! Observability/error-tracking token recall + precision lock: Sentry auth
//! tokens — both the modern `sntrys_`-prefixed base64 form and the legacy
//! context-anchored 64-hex form. `sentry-auth-token` had only a single
//! adversarial reference and no recall lock. Neither form is checksum-gated, so
//! fabricated high-entropy fixtures surface; this pins both patterns across
//! context plus the precision floors (length, charset, and the legacy form's
//! required `sentry…token` anchor that keeps a bare 64-hex from false-firing).

mod support;
use support::contracts::{make_chunk, scanner};

use keyhog_core::Chunk;
use keyhog_scanner::CompiledScanner;

fn gen(n: usize, seed: usize, charset: &[u8]) -> String {
    let m = charset.len() as u64;
    let mut s = (seed as u64)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0x6F1B_2D44);
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
fn hex(n: usize, seed: usize) -> String {
    gen(n, seed, b"0123456789abcdef")
}

fn scan(text: &str) -> Vec<(String, String)> {
    let s: &CompiledScanner = &scanner();
    let chunk: Chunk = make_chunk(text, "source", "sentry.env");
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
fn surfaces_any(text: &str, needle: &str) -> bool {
    scan(text).iter().any(|(_, cred)| cred.contains(needle))
}
fn fires(text: &str, detector: &str) -> bool {
    scan(text).iter().any(|(id, _)| id == detector)
}

// ── modern sntrys_ form: sntrys_ + 64..128 base64 chars ───────────────────────

#[test]
fn sentry_modern_token_surfaces() {
    let t = format!("sntrys_{}", alnum(64, 1));
    assert!(
        surfaces_under(&t, "sentry-auth-token", &t),
        "sntrys_ token must surface"
    );
}

#[test]
fn sentry_modern_token_max_128_surfaces() {
    let t = format!("sntrys_{}", alnum(128, 2)); // 128 = pattern maximum
    assert!(surfaces_under(&t, "sentry-auth-token", &t));
}

#[test]
fn sentry_modern_token_env_anchor_surfaces() {
    let t = format!("sntrys_{}", alnum(80, 3));
    assert!(surfaces_under(
        &format!("SENTRY_AUTH_TOKEN={t}"),
        "sentry-auth-token",
        &t
    ));
}

#[test]
fn sentry_modern_token_in_yaml_surfaces() {
    let t = format!("sntrys_{}", alnum(72, 4));
    assert!(surfaces_any(&format!("sentry:\n  auth_token: {t}\n"), &t));
}

#[test]
fn sentry_modern_token_bare_prefix_surfaces() {
    // The sntrys_ prefix literal alone triggers the prefilter (no context needed).
    let t = format!("sntrys_{}", alnum(64, 5));
    assert!(surfaces_under(&t, "sentry-auth-token", &t));
}

#[test]
fn sentry_modern_token_63_body_does_not_fire() {
    // 63 < 64 minimum for the base64 body.
    let t = format!("sntrys_{}", alnum(63, 6));
    assert!(!fires(&t, "sentry-auth-token"));
}

#[test]
fn sentry_modern_wrong_prefix_does_not_fire() {
    let t = format!("sntry_{}", alnum(80, 7)); // sntry_ (missing the trailing s)
    assert!(!fires(&t, "sentry-auth-token"));
}

// ── legacy context-anchored form: sentry…token=<64 hex> ───────────────────────

#[test]
fn sentry_legacy_hex_uppercase_anchor_surfaces() {
    let h = hex(64, 8);
    assert!(surfaces_under(
        &format!("SENTRY_AUTH_TOKEN={h}"),
        "sentry-auth-token",
        &h
    ));
}

#[test]
fn sentry_legacy_hex_lowercase_anchor_surfaces() {
    let h = hex(64, 9);
    assert!(surfaces_under(
        &format!("sentry_auth_token={h}"),
        "sentry-auth-token",
        &h
    ));
}

#[test]
fn sentry_legacy_hex_dotted_anchor_surfaces() {
    let h = hex(64, 10);
    assert!(surfaces_under(
        &format!("sentry.token: \"{h}\""),
        "sentry-auth-token",
        &h
    ));
}

#[test]
fn sentry_legacy_hex_63_does_not_fire() {
    let h = hex(63, 11); // 63 < 64 hex
    assert!(!fires(
        &format!("SENTRY_AUTH_TOKEN={h}"),
        "sentry-auth-token"
    ));
}

#[test]
fn sentry_legacy_bare_64_hex_without_anchor_does_not_fire() {
    // No sentry context and no sntrys_ prefix: the legacy pattern needs the
    // anchor, so a bare 64-hex must not surface UNDER sentry-auth-token.
    let h = hex(64, 12);
    assert!(!fires(&h, "sentry-auth-token"));
}

// ── cross / co-surfacing ──────────────────────────────────────────────────────

#[test]
fn sentry_modern_and_legacy_cosurface() {
    let m = format!("sntrys_{}", alnum(96, 13));
    let h = hex(64, 14);
    let text = format!("SENTRY_DSN_TOKEN={m}\nSENTRY_AUTH_TOKEN={h}\n");
    assert!(
        surfaces_under(&text, "sentry-auth-token", &m),
        "modern token surfaces"
    );
    assert!(
        surfaces_under(&text, "sentry-auth-token", &h),
        "legacy hex token surfaces"
    );
}

#[test]
fn sentry_modern_token_min_64_exact_surfaces() {
    let t = format!("sntrys_{}", alnum(64, 15)); // 64 = exact minimum
    assert!(surfaces_under(&t, "sentry-auth-token", &t));
}

#[test]
fn sentry_modern_token_json_value_surfaces() {
    let t = format!("sntrys_{}", alnum(70, 16));
    assert!(surfaces_any(&format!("{{\"sentry_token\":\"{t}\"}}"), &t));
}

#[test]
fn sentry_legacy_hex_with_quotes_anchor_surfaces() {
    let h = hex(64, 17);
    assert!(surfaces_under(
        &format!("SENTRY_AUTH_TOKEN=\"{h}\""),
        "sentry-auth-token",
        &h
    ));
}

#[test]
fn sentry_legacy_short_anchor_token_form_surfaces() {
    let h = hex(64, 18);
    assert!(surfaces_under(
        &format!("sentry-token={h}"),
        "sentry-auth-token",
        &h
    ));
}

#[test]
fn sentry_modern_token_with_underscore_prefix_only_does_not_fire() {
    // A bare `sntrys_` with too-short tail must not fire (guards the floor).
    let t = format!("sntrys_{}", alnum(40, 19));
    assert!(!fires(&t, "sentry-auth-token"));
}

#[test]
fn sentry_legacy_uppercase_hex_anchor_surfaces() {
    // Detector regexes compile case-insensitively, so an uppercase hex value
    // under the anchor still surfaces.
    let h = hex(64, 20).to_uppercase();
    assert!(surfaces_under(
        &format!("SENTRY_AUTH_TOKEN={h}"),
        "sentry-auth-token",
        &h
    ));
}

#[test]
fn sentry_modern_token_90_body_surfaces() {
    let t = format!("sntrys_{}", alnum(90, 21));
    assert!(surfaces_under(&t, "sentry-auth-token", &t));
}
