//! Infrastructure-vendor token recall + precision lock: DigitalOcean PAT,
//! Doppler (CLI + service), PlanetScale (api-v2 + service), and Fly.io (access +
//! deploy). These leak constantly via CI env files and `doppler`/`flyctl`/`doctl`
//! configs and had no dedicated recall test. Each has a strong unique prefix
//! literal (so the prefilter triggers without a host keyword) and none is
//! checksum-gated, so fabricated high-entropy fixtures surface. This pins each
//! token form across context plus the precision floors of the variable segments.

mod support;
use support::contracts::{make_chunk, scanner};

use keyhog_core::Chunk;
use keyhog_scanner::CompiledScanner;

fn gen(n: usize, seed: usize, charset: &[u8]) -> String {
    let m = charset.len() as u64;
    let mut s = (seed as u64)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0x1D3B_55F1);
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
fn hex(n: usize, seed: usize) -> String {
    gen(n, seed, b"0123456789abcdef")
}

fn scan(text: &str) -> Vec<(String, String)> {
    let s: &CompiledScanner = &scanner();
    let chunk: Chunk = make_chunk(text, "source", "infra.env");
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

// ── DigitalOcean PAT: dop_v1_ + 64 hex ────────────────────────────────────────

#[test]
fn digitalocean_pat_surfaces() {
    let t = format!("dop_v1_{}", hex(64, 1));
    assert!(
        surfaces_under(&t, "digitalocean-pat", &t),
        "dop_v1_ PAT must surface"
    );
}

#[test]
fn digitalocean_pat_env_anchor_surfaces() {
    let t = format!("dop_v1_{}", hex(64, 2));
    assert!(surfaces_under(
        &format!("DIGITALOCEAN_ACCESS_TOKEN={t}"),
        "digitalocean-pat",
        &t
    ));
}

#[test]
fn digitalocean_pat_in_yaml_surfaces() {
    let t = format!("dop_v1_{}", hex(64, 3));
    assert!(surfaces_any(&format!("digitalocean:\n  token: {t}\n"), &t));
}

#[test]
fn digitalocean_pat_63_hex_does_not_fire() {
    // The tail is exactly 64 hex; 63 can never reach the count.
    let t = format!("dop_v1_{}", hex(63, 4));
    assert!(!fires(&t, "digitalocean-pat"));
}

#[test]
fn digitalocean_pat_non_hex_tail_does_not_fire() {
    // `g` is outside [a-f0-9]; the run breaks before 64.
    let t = format!("dop_v1_g{}", hex(63, 5));
    assert!(!fires(&t, "digitalocean-pat"));
}

// ── Doppler CLI: dp.(ct|pt|sa). + 44 alnum ────────────────────────────────────

#[test]
fn doppler_cli_config_token_surfaces() {
    let t = format!("dp.ct.{}", alnum(44, 6));
    assert!(
        surfaces_under(&t, "doppler-cli-token", &t),
        "dp.ct. CLI token must surface"
    );
}

#[test]
fn doppler_cli_personal_token_surfaces() {
    let t = format!("dp.pt.{}", alnum(44, 7));
    assert!(
        surfaces_under(&t, "doppler-cli-token", &t),
        "dp.pt. personal token must surface"
    );
}

#[test]
fn doppler_cli_service_account_token_surfaces() {
    let t = format!("dp.sa.{}", alnum(44, 8));
    assert!(
        surfaces_under(&t, "doppler-cli-token", &t),
        "dp.sa. SA token must surface"
    );
}

#[test]
fn doppler_cli_43_alnum_does_not_fire() {
    let t = format!("dp.ct.{}", alnum(43, 9)); // 43 < 44 exact length
    assert!(!fires(&t, "doppler-cli-token"));
}

#[test]
fn doppler_cli_unknown_segment_does_not_fire() {
    let t = format!("dp.zz.{}", alnum(44, 10)); // zz is not ct|pt|sa
    assert!(!fires(&t, "doppler-cli-token"));
}

// ── Doppler service: dp.st. + 40+ alnum ───────────────────────────────────────

#[test]
fn doppler_service_token_surfaces() {
    let t = format!("dp.st.{}", alnum(40, 11));
    assert!(
        surfaces_under(&t, "doppler-service-token", &t),
        "dp.st. service token must surface"
    );
}

#[test]
fn doppler_service_token_env_anchor_surfaces() {
    let t = format!("dp.st.{}", alnum(48, 12));
    assert!(surfaces_under(
        &format!("DOPPLER_TOKEN={t}"),
        "doppler-service-token",
        &t
    ));
}

#[test]
fn doppler_service_token_39_alnum_does_not_fire() {
    let t = format!("dp.st.{}", alnum(39, 13)); // 39 < 40 minimum
    assert!(!fires(&t, "doppler-service-token"));
}

// ── PlanetScale: pscale_tkn_ + 32+/43 ─────────────────────────────────────────

#[test]
fn planetscale_api_token_v2_surfaces() {
    let t = format!("pscale_tkn_{}", b64url(50, 14));
    assert!(
        surfaces_under(&t, "planetscale-api-token-v2", &t),
        "pscale_tkn_ must surface"
    );
}

#[test]
fn planetscale_api_token_v2_contextual_surfaces() {
    let t = format!("pscale_tkn_{}", b64url(40, 15));
    assert!(surfaces_under(
        &format!("PLANETSCALE_API_TOKEN={t}"),
        "planetscale-api-token-v2",
        &t
    ));
}

#[test]
fn planetscale_service_token_43_surfaces() {
    // A 43-char body satisfies the service detector's exact `{43}` length.
    let t = format!("pscale_tkn_{}", b64url(43, 16));
    assert!(
        surfaces_under(&t, "planetscale-service-token", &t),
        "43-char pscale_tkn_ is a service token"
    );
}

#[test]
fn planetscale_short_body_is_v2_only_not_service() {
    // 42 < 43 escapes the service detector but still satisfies api-v2's {32,}.
    let t = format!("pscale_tkn_{}", b64url(42, 17));
    assert!(
        surfaces_under(&t, "planetscale-api-token-v2", &t),
        "still an api-v2 token"
    );
    assert!(
        !fires(&t, "planetscale-service-token"),
        "42 chars is below the service {{43}} floor"
    );
}

#[test]
fn planetscale_below_32_does_not_fire() {
    let t = format!("pscale_tkn_{}", b64url(20, 18)); // 20 < 32 minimum
    assert!(!fires(&t, "planetscale-api-token-v2"));
}

// ── Fly.io: fm2_ access (43) + fo1_ deploy (40..80) ───────────────────────────

#[test]
fn flyio_access_token_surfaces() {
    let t = format!("fm2_{}", b64url(43, 19));
    assert!(
        surfaces_under(&t, "flyio-access-token", &t),
        "fm2_ access token must surface"
    );
}

#[test]
fn flyio_access_token_42_does_not_fire() {
    let t = format!("fm2_{}", b64url(42, 20)); // 42 < 43 exact length
    assert!(!fires(&t, "flyio-access-token"));
}

#[test]
fn flyio_deploy_token_surfaces() {
    let t = format!("fo1_{}", b64url(50, 21));
    assert!(
        surfaces_under(&t, "flyio-deploy-token", &t),
        "fo1_ deploy token must surface"
    );
}

#[test]
fn flyio_deploy_token_contextual_surfaces() {
    let t = format!("fo1_{}", b64url(45, 22));
    assert!(surfaces_under(
        &format!("FLY_DEPLOY_TOKEN={t}"),
        "flyio-deploy-token",
        &t
    ));
}

#[test]
fn flyio_deploy_token_min_40_surfaces() {
    let t = format!("fo1_{}", b64url(40, 23)); // 40 = minimum
    assert!(surfaces_under(&t, "flyio-deploy-token", &t));
}

#[test]
fn flyio_deploy_token_39_does_not_fire() {
    let t = format!("fo1_{}", b64url(39, 24)); // 39 < 40 minimum
    assert!(!fires(&t, "flyio-deploy-token"));
}

// ── cross: several infra tokens co-surface in one env file ────────────────────

#[test]
fn multiple_infra_tokens_cosurface() {
    let d = format!("dop_v1_{}", hex(64, 25));
    let s = format!("dp.st.{}", alnum(44, 26));
    let p = format!("pscale_tkn_{}", b64url(50, 27));
    let f = format!("fm2_{}", b64url(43, 28));
    let text = format!("DIGITALOCEAN_ACCESS_TOKEN={d}\nDOPPLER_TOKEN={s}\nPLANETSCALE_API_TOKEN={p}\nFLY_API_TOKEN={f}\n");
    assert!(surfaces_under(&text, "digitalocean-pat", &d));
    assert!(surfaces_under(&text, "doppler-service-token", &s));
    assert!(surfaces_under(&text, "planetscale-api-token-v2", &p));
    assert!(surfaces_under(&text, "flyio-access-token", &f));
}
