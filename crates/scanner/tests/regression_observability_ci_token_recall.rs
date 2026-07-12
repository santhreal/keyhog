//! Observability + CI/CD vendor credential recall + precision lock: Datadog
//! (api key 32-hex, application key 40-hex + verify companion), New Relic
//! (license key 40-hex, `NRAK-` user API key), CircleCI (40-hex), Fastly
//! (32-char token), Heroku (UUID api key), and Travis CI (22-char token).
//! These leak via CI env, SDK config, and request headers. Every vendor here is
//! context-anchored hex/alnum (no unique prefix except `NRAK-`), so this pins
//! both that the anchor lifts the body over the confidence floor AND the length
//! boundaries. None is checksum-gated; Datadog's verify companion is optional
//! for surfacing (it only supplies the second header at verification time).

mod support;
use support::contracts::{make_chunk, scanner};

use keyhog_core::Chunk;
use keyhog_scanner::CompiledScanner;

fn gen(n: usize, seed: usize, charset: &[u8]) -> String {
    let m = charset.len() as u64;
    let mut s = (seed as u64)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0x6B2D_11F7);
    (0..n)
        .map(|_| {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            charset[((s >> 33) % m) as usize] as char
        })
        .collect()
}
fn hex(n: usize, seed: usize) -> String {
    gen(n, seed, b"0123456789abcdef")
}
fn alnum(n: usize, seed: usize) -> String {
    gen(
        n,
        seed,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    )
}
fn uppernum(n: usize, seed: usize) -> String {
    gen(n, seed, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
}
fn uuid(seed: usize) -> String {
    format!(
        "{}-{}-{}-{}-{}",
        hex(8, seed),
        hex(4, seed + 1),
        hex(4, seed + 2),
        hex(4, seed + 3),
        hex(12, seed + 4)
    )
}

fn scan(text: &str) -> Vec<(String, String)> {
    let s: &CompiledScanner = &scanner();
    let chunk: Chunk = make_chunk(text, "source", "ci.env");
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

// ── Datadog API key: 32 hex, context-anchored ────────────────────────────────

#[test]
fn datadog_dd_api_key_underscore_surfaces() {
    let k = hex(32, 1);
    assert!(surfaces_under(
        &format!("DD_API_KEY={k}"),
        "datadog-api-key",
        &k
    ));
}

#[test]
fn datadog_full_api_key_surfaces() {
    let k = hex(32, 2);
    assert!(surfaces_under(
        &format!("DATADOG_API_KEY={k}"),
        "datadog-api-key",
        &k
    ));
}

#[test]
fn datadog_api_key_header_dash_form_surfaces() {
    // The regex uses `DD.API.KEY` where `.` matches the `-` of the header name.
    let k = hex(32, 3);
    assert!(surfaces_under(
        &format!("DD-API-Key: {k}"),
        "datadog-api-key",
        &k
    ));
}

// ── Datadog application key: 40 hex ──────────────────────────────────────────

#[test]
fn datadog_application_key_surfaces() {
    let k = hex(40, 4);
    assert!(surfaces_under(
        &format!("DATADOG_APP_KEY={k}"),
        "datadog-application-key",
        &k
    ));
}

#[test]
fn datadog_dd_app_key_underscore_surfaces() {
    let k = hex(40, 5);
    assert!(surfaces_under(
        &format!("DD_APP_KEY={k}"),
        "datadog-application-key",
        &k
    ));
}

#[test]
fn datadog_app_and_api_keys_cosurface() {
    // The application-key detector carries the api key as a verify-only companion,
    // but both must still surface as their own findings in the same file.
    let app = hex(40, 6);
    let api = hex(32, 7);
    let text = format!("DATADOG_APP_KEY={app}\nDD_API_KEY={api}\n");
    assert!(surfaces_under(&text, "datadog-application-key", &app));
    assert!(surfaces_under(&text, "datadog-api-key", &api));
}

#[test]
fn datadog_api_key_31_hex_does_not_fire() {
    let k = hex(31, 8); // 31 < the required 32
    assert!(!fires(&format!("DD_API_KEY={k}"), "datadog-api-key"));
}

// ── New Relic license key: 40 hex ────────────────────────────────────────────

#[test]
fn newrelic_license_key_surfaces() {
    let k = hex(40, 9);
    assert!(surfaces_under(
        &format!("NEW_RELIC_LICENSE_KEY={k}"),
        "newrelic-license-key",
        &k
    ));
}

#[test]
fn newrelic_license_anchor_surfaces() {
    let k = hex(40, 10);
    assert!(surfaces_under(
        &format!("NEWRELIC_LICENSE={k}"),
        "newrelic-license-key",
        &k
    ));
}

#[test]
fn newrelic_license_key_39_hex_does_not_fire() {
    let k = hex(39, 11); // 39 < 40
    assert!(!fires(
        &format!("NEW_RELIC_LICENSE_KEY={k}"),
        "newrelic-license-key"
    ));
}

// ── New Relic user API key: NRAK-<27 [A-Z0-9]> ───────────────────────────────

#[test]
fn newrelic_nrak_user_key_surfaces() {
    let k = format!("NRAK-{}", uppernum(27, 12));
    assert!(
        surfaces_under(&k, "newrelic-user-api-key", &k),
        "NRAK- token must surface"
    );
}

#[test]
fn newrelic_nrak_26_body_does_not_fire() {
    let k = format!("NRAK-{}", uppernum(26, 13)); // 26 < the required 27
    assert!(!fires(&k, "newrelic-user-api-key"));
}

// ── CircleCI: 40 hex ─────────────────────────────────────────────────────────

#[test]
fn circleci_api_token_surfaces() {
    let k = hex(40, 14);
    assert!(surfaces_under(
        &format!("CIRCLECI_API_TOKEN={k}"),
        "circleci-api-token",
        &k
    ));
}

#[test]
fn circleci_circle_token_env_surfaces() {
    let k = hex(40, 15);
    assert!(surfaces_under(
        &format!("CIRCLE_TOKEN={k}"),
        "circleci-api-token",
        &k
    ));
}

// ── Fastly: 32-char token ────────────────────────────────────────────────────

#[test]
fn fastly_api_token_surfaces() {
    let k = alnum(32, 16);
    assert!(surfaces_under(
        &format!("FASTLY_API_TOKEN={k}"),
        "fastly-api-token",
        &k
    ));
}

#[test]
fn fastly_key_header_surfaces() {
    let k = alnum(32, 17);
    assert!(surfaces_under(
        &format!("Fastly-Key: {k}"),
        "fastly-api-token",
        &k
    ));
}

// ── Heroku: UUID api key ─────────────────────────────────────────────────────

#[test]
fn heroku_api_key_uuid_surfaces() {
    let u = uuid(18);
    assert!(surfaces_under(
        &format!("HEROKU_API_KEY={u}"),
        "heroku-api-key",
        &u
    ));
}

#[test]
fn heroku_camelcase_key_surfaces() {
    let u = uuid(19);
    assert!(surfaces_under(
        &format!("herokuApiKey: \"{u}\""),
        "heroku-api-key",
        &u
    ));
}

#[test]
fn heroku_non_uuid_body_does_not_fire() {
    // A bare 32-hex under the Heroku anchor is not the dashed-UUID key shape.
    let k = hex(32, 20);
    assert!(!fires(&format!("HEROKU_API_KEY={k}"), "heroku-api-key"));
}

// ── Travis CI: 22-char token ─────────────────────────────────────────────────

#[test]
fn travis_token_surfaces() {
    let k = alnum(22, 21);
    assert!(surfaces_under(
        &format!("TRAVIS_TOKEN={k}"),
        "travisci-token",
        &k
    ));
}

#[test]
fn travis_lowercase_anchor_surfaces() {
    let k = alnum(22, 22);
    assert!(surfaces_under(
        &format!("travis_token={k}"),
        "travisci-token",
        &k
    ));
}

#[test]
fn travis_21_char_token_does_not_fire() {
    let k = alnum(21, 23); // 21 < the required 22
    assert!(!fires(&format!("TRAVIS_TOKEN={k}"), "travisci-token"));
}

// ── cross: several observability/CI tokens co-surface ────────────────────────

#[test]
fn multiple_observability_tokens_cosurface() {
    let dd = hex(32, 24);
    let nr = hex(40, 25);
    let cc = hex(40, 26);
    let text = format!("DD_API_KEY={dd}\nNEW_RELIC_LICENSE_KEY={nr}\nCIRCLECI_API_TOKEN={cc}\n");
    assert!(surfaces_under(&text, "datadog-api-key", &dd));
    assert!(surfaces_under(&text, "newrelic-license-key", &nr));
    assert!(surfaces_under(&text, "circleci-api-token", &cc));
}

#[test]
fn ci_and_cdn_tokens_cosurface() {
    let fa = alnum(32, 27);
    let tr = alnum(22, 28);
    let hk = uuid(29);
    let text = format!("FASTLY_API_TOKEN={fa}\nTRAVIS_TOKEN={tr}\nHEROKU_API_KEY={hk}\n");
    assert!(surfaces_under(&text, "fastly-api-token", &fa));
    assert!(surfaces_under(&text, "travisci-token", &tr));
    assert!(surfaces_under(&text, "heroku-api-key", &hk));
}
