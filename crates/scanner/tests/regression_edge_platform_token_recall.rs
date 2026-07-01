//! Edge/serverless platform credential recall + precision lock: Cloudflare
//! (api token 40-char, global api key 37-hex, workers api token 40-char) and
//! Vercel (token 24-char, `vercel_v2_` api token, `BLOB_*` read/write token,
//! `ecfg_` edge-config token). These leak via `.env`, CI config, and request
//! headers. Coverage mixes context-anchored bodies (cloudflare api/global/
//! workers, vercel token/blob) with distinctive bare prefixes (`vercel_v2_`,
//! `ecfg_`). This pins each form plus the length boundaries; none is
//! checksum-gated. The connection-string-shaped kv/postgres/zero-trust
//! detectors are intentionally covered elsewhere (their values collide with
//! generic DB-URL detectors, which is a separate labeling contract).

mod support;
use support::contracts::{make_chunk, scanner};

use keyhog_core::Chunk;
use keyhog_scanner::CompiledScanner;

fn gen(n: usize, seed: usize, charset: &[u8]) -> String {
    let m = charset.len() as u64;
    let mut s = (seed as u64)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0x51C3_6A2D);
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

fn scan(text: &str) -> Vec<(String, String)> {
    let s: &CompiledScanner = &scanner();
    let chunk: Chunk = make_chunk(text, "source", "edge.env");
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

// ── Cloudflare API token: 40 char [a-zA-Z0-9_-], context-anchored ────────────

#[test]
fn cloudflare_api_token_env_surfaces() {
    let k = alnum(40, 1);
    assert!(surfaces_under(
        &format!("CLOUDFLARE_API_TOKEN={k}"),
        "cloudflare-api-token",
        &k
    ));
}

#[test]
fn cloudflare_cf_api_token_surfaces() {
    let k = alnum(40, 2);
    assert!(surfaces_under(&format!("CF_API_TOKEN={k}"), "cloudflare-api-token", &k));
}

#[test]
fn cloudflare_cf_api_token_quoted_surfaces() {
    let k = alnum(40, 3);
    assert!(surfaces_under(
        &format!("CF_API_TOKEN=\"{k}\""),
        "cloudflare-api-token",
        &k
    ));
}

#[test]
fn cloudflare_camelcase_token_surfaces() {
    let k = alnum(40, 4);
    assert!(surfaces_under(
        &format!("cloudflareApiToken: \"{k}\""),
        "cloudflare-api-token",
        &k
    ));
}

#[test]
fn cloudflare_lowercase_anchor_surfaces() {
    let k = alnum(40, 5);
    assert!(surfaces_under(
        &format!("cloudflare_api_token = \"{k}\""),
        "cloudflare-api-token",
        &k
    ));
}

#[test]
fn cloudflare_api_token_39_char_does_not_fire() {
    let k = alnum(39, 6); // 39 < the required 40
    assert!(!fires(&format!("CLOUDFLARE_API_TOKEN={k}"), "cloudflare-api-token"));
}

// ── Cloudflare global API key: 37 hex ────────────────────────────────────────

#[test]
fn cloudflare_global_api_key_surfaces() {
    let k = hex(37, 7);
    assert!(surfaces_under(
        &format!("CLOUDFLARE_API_KEY={k}"),
        "cloudflare-global-api-key",
        &k
    ));
}

#[test]
fn cloudflare_global_x_auth_key_header_surfaces() {
    let k = hex(37, 8);
    assert!(surfaces_under(
        &format!("X-Auth-Key: {k}"),
        "cloudflare-global-api-key",
        &k
    ));
}

#[test]
fn cloudflare_global_36_hex_does_not_fire() {
    let k = hex(36, 9); // 36 < the required 37
    assert!(!fires(&format!("CLOUDFLARE_API_KEY={k}"), "cloudflare-global-api-key"));
}

// ── Cloudflare Workers API token: 40 char ────────────────────────────────────

#[test]
fn cloudflare_workers_api_token_surfaces() {
    let k = alnum(40, 10);
    assert!(surfaces_under(
        &format!("CLOUDFLARE_WORKERS_API_TOKEN={k}"),
        "cloudflare-workers-api-token",
        &k
    ));
}

// ── Vercel token: 24 char [a-zA-Z0-9] ────────────────────────────────────────

#[test]
fn vercel_token_surfaces() {
    let k = alnum(24, 11);
    assert!(surfaces_under(&format!("VERCEL_TOKEN={k}"), "vercel-token", &k));
}

#[test]
fn vercel_token_lowercase_anchor_surfaces() {
    let k = alnum(24, 12);
    assert!(surfaces_under(&format!("vercel_token={k}"), "vercel-token", &k));
}

#[test]
fn vercel_token_23_char_does_not_fire() {
    let k = alnum(23, 13); // 23 < the required 24
    assert!(!fires(&format!("VERCEL_TOKEN={k}"), "vercel-token"));
}

// ── Vercel v2 API token: vercel_v2_<24> bare prefix ──────────────────────────

#[test]
fn vercel_v2_api_token_surfaces() {
    let k = format!("vercel_v2_{}", alnum(24, 14));
    assert!(surfaces_under(&k, "vercel-api-token-v2", &k), "vercel_v2_ token must surface");
}

#[test]
fn vercel_v2_api_token_23_body_does_not_fire() {
    let k = format!("vercel_v2_{}", alnum(23, 15)); // 23 < the required 24
    assert!(!fires(&k, "vercel-api-token-v2"));
}

// ── Vercel Blob read/write token: BLOB_*_TOKEN=<40+> ─────────────────────────

#[test]
fn vercel_blob_read_write_token_surfaces() {
    let k = alnum(48, 16);
    assert!(surfaces_under(
        &format!("BLOB_READ_WRITE_TOKEN={k}"),
        "vercel-blob-credentials",
        &k
    ));
}

#[test]
fn vercel_blob_token_surfaces() {
    let k = alnum(44, 17);
    assert!(surfaces_under(&format!("BLOB_TOKEN={k}"), "vercel-blob-credentials", &k));
}

// ── Vercel edge-config token: ecfg_<64> bare prefix ──────────────────────────

#[test]
fn vercel_edge_config_token_surfaces() {
    let k = format!("ecfg_{}", alnum(64, 18));
    assert!(surfaces_under(&k, "vercel-edge-config-token", &k), "ecfg_ token must surface");
}

#[test]
fn vercel_edge_config_63_body_does_not_fire() {
    let k = format!("ecfg_{}", alnum(63, 19)); // 63 < the required 64
    assert!(!fires(&k, "vercel-edge-config-token"));
}

// ── cross: several edge-platform tokens co-surface ───────────────────────────

#[test]
fn multiple_cloudflare_tokens_cosurface() {
    let api = alnum(40, 20);
    let global = hex(37, 21);
    let workers = alnum(40, 22);
    let text = format!(
        "CLOUDFLARE_API_TOKEN={api}\nCLOUDFLARE_API_KEY={global}\nCLOUDFLARE_WORKERS_API_TOKEN={workers}\n"
    );
    assert!(surfaces_under(&text, "cloudflare-api-token", &api));
    assert!(surfaces_under(&text, "cloudflare-global-api-key", &global));
    assert!(surfaces_under(&text, "cloudflare-workers-api-token", &workers));
}

#[test]
fn multiple_vercel_tokens_cosurface() {
    let tok = alnum(24, 23);
    let blob = alnum(48, 24);
    let ecfg = format!("ecfg_{}", alnum(64, 25));
    let text = format!("VERCEL_TOKEN={tok}\nBLOB_READ_WRITE_TOKEN={blob}\nEDGE_CONFIG={ecfg}\n");
    assert!(surfaces_under(&text, "vercel-token", &tok));
    assert!(surfaces_under(&text, "vercel-blob-credentials", &blob));
    assert!(surfaces_under(&text, "vercel-edge-config-token", &ecfg));
}
