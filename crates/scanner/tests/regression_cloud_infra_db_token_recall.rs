//! Cloud-infrastructure + database provider credential recall + precision lock:
//! DigitalOcean (`dop_v1_`), PlanetScale (`pscale_tkn_`, two overlapping
//! detectors), Fly.io (`fm2_` access / `fo1_` deploy), Render (`rnd_`), Fauna
//! (`fnAE`/`fnAC`), CockroachDB (segmented), Neon (`neon_api_`), Scaleway
//! (`SCW…`), Linode (context 64-hex), Vultr (context 36-char), Hetzner (context
//! 64-hex), and Railway (context UUID). These leak from IaC, deploy configs, and
//! CI env. Built on the shared `support::vendorgen` harness; none is
//! checksum-gated.
//!
//! `pscale_tkn_<43>` matches BOTH `planetscale-service-token` (exact 43) and
//! `planetscale-api-token-v2` (`{32,}`); value-dedup keeps one label, so it is
//! asserted with `surfaces_under_any`. Linode/Hetzner capture a bare 64-hex and
//! Railway a bare UUID under a named anchor — the shape-collision carve-out keeps
//! them surfacing under the vendor label rather than a generic one.

mod support;
use support::vendorgen::{
    alnum, fires, fires_any, hex, surfaces_under, surfaces_under_any, uppernum, uuid,
};

const PLANETSCALE: &[&str] = &["planetscale-service-token", "planetscale-api-token-v2"];

// ── DigitalOcean: dop_v1_<64hex> ─────────────────────────────────────────────

#[test]
fn digitalocean_pat_surfaces() {
    let k = format!("dop_v1_{}", hex(64, 1));
    assert!(
        surfaces_under(&k, "digitalocean-pat", &k),
        "dop_v1_ PAT must surface"
    );
}

#[test]
fn digitalocean_pat_63_hex_does_not_fire() {
    let k = format!("dop_v1_{}", hex(63, 2)); // 63 < the required 64
    assert!(!fires(&k, "digitalocean-pat"));
}

// ── PlanetScale: pscale_tkn_ (two overlapping detectors) ─────────────────────

#[test]
fn planetscale_service_token_surfaces() {
    let k = format!("pscale_tkn_{}", alnum(43, 3));
    assert!(
        surfaces_under_any(&k, PLANETSCALE, &k),
        "pscale_tkn_ must surface"
    );
}

#[test]
fn planetscale_token_31_body_does_not_fire() {
    // 31 < 32, below the minimum of BOTH planetscale detectors.
    let k = format!("pscale_tkn_{}", alnum(31, 4));
    assert!(!fires_any(&k, PLANETSCALE));
}

// ── Fly.io: fm2_ access / fo1_ deploy ────────────────────────────────────────

#[test]
fn flyio_access_token_surfaces() {
    let k = format!("fm2_{}", alnum(43, 5));
    assert!(
        surfaces_under(&k, "flyio-access-token", &k),
        "fm2_ token must surface"
    );
}

#[test]
fn flyio_access_token_42_body_does_not_fire() {
    let k = format!("fm2_{}", alnum(42, 6)); // 42 < the required 43
    assert!(!fires(&k, "flyio-access-token"));
}

#[test]
fn flyio_deploy_token_surfaces() {
    let k = format!("fo1_{}", alnum(50, 7));
    assert!(
        surfaces_under(&k, "flyio-deploy-token", &k),
        "fo1_ token must surface"
    );
}

#[test]
fn flyio_deploy_token_39_body_does_not_fire() {
    let k = format!("fo1_{}", alnum(39, 8)); // 39 < the required 40
    assert!(!fires(&k, "flyio-deploy-token"));
}

// ── Render: rnd_<24> ─────────────────────────────────────────────────────────

#[test]
fn render_api_key_surfaces() {
    let k = format!("rnd_{}", alnum(24, 9));
    assert!(
        surfaces_under(&k, "render-api-key", &k),
        "rnd_ key must surface"
    );
}

#[test]
fn render_api_key_23_body_does_not_fire() {
    let k = format!("rnd_{}", alnum(23, 10)); // 23 < the required 24
    assert!(!fires(&k, "render-api-key"));
}

// ── Fauna: fnAE / fnAC <32+>[_-]<16+> ────────────────────────────────────────

#[test]
fn fauna_fnae_secret_surfaces() {
    let k = format!("fnAE{}_{}", alnum(40, 11), alnum(20, 12));
    assert!(
        surfaces_under(&k, "fauna-secret-key", &k),
        "fnAE secret must surface"
    );
}

#[test]
fn fauna_fnac_secret_surfaces() {
    let k = format!("fnAC{}_{}", alnum(40, 13), alnum(20, 14));
    assert!(
        surfaces_under(&k, "fauna-secret-key", &k),
        "fnAC secret must surface"
    );
}

// ── CockroachDB: segmented 7_7_7_6_3 upper-alnum ─────────────────────────────

#[test]
fn cockroachdb_api_key_surfaces() {
    let seg = format!(
        "{}_{}_{}_{}_{}",
        uppernum(7, 15),
        uppernum(7, 16),
        uppernum(7, 17),
        uppernum(6, 18),
        uppernum(3, 19)
    );
    assert!(surfaces_under(
        &format!("COCKROACH_API_KEY={seg}"),
        "cockroachdb-api-key",
        &seg
    ));
}

// ── Neon: neon_api_<48> ──────────────────────────────────────────────────────

#[test]
fn neon_api_key_surfaces() {
    let k = format!("neon_api_{}", alnum(48, 20));
    assert!(
        surfaces_under(&k, "neon-api-key", &k),
        "neon_api_ key must surface"
    );
}

#[test]
fn neon_api_key_47_body_does_not_fire() {
    let k = format!("neon_api_{}", alnum(47, 21)); // 47 < the required 48
    assert!(!fires(&k, "neon-api-key"));
}

// ── Scaleway: SCW_SECRET_KEY-anchored UUID (access key is a companion) ────────

#[test]
fn scaleway_secret_key_surfaces() {
    // The primary Scaleway pattern is the SCW_SECRET_KEY-anchored UUID secret;
    // the `SCW<20>` access key is a *companion* field surfaced on that finding,
    // never a standalone match, so primary recall is what we lock here.
    let k = uuid(22);
    assert!(surfaces_under(
        &format!("SCW_SECRET_KEY={k}"),
        "scaleway-api-key",
        &k
    ));
}

#[test]
fn scaleway_bare_access_key_is_not_a_standalone_match() {
    // Without the SCW_SECRET_KEY primary within range, the `SCW<20>` access key
    // is a companion with nothing to attach to and must not fire on its own.
    let access = format!("SCW{}", uppernum(20, 33));
    assert!(!fires(
        &format!("SCALEWAY_ACCESS_KEY={access}"),
        "scaleway-api-key"
    ));
}

// ── Linode: context 64-hex ───────────────────────────────────────────────────

#[test]
fn linode_pat_surfaces() {
    let k = hex(64, 23);
    assert!(surfaces_under(
        &format!("LINODE_TOKEN={k}"),
        "linode-pat",
        &k
    ));
}

// ── Vultr: context 36 upper-alnum ────────────────────────────────────────────

#[test]
fn vultr_api_key_surfaces() {
    let k = uppernum(36, 24);
    assert!(surfaces_under(
        &format!("VULTR_API_KEY={k}"),
        "vultr-api-key",
        &k
    ));
}

// ── Hetzner: context 64-hex ──────────────────────────────────────────────────

#[test]
fn hetzner_api_token_surfaces() {
    let k = hex(64, 25);
    assert!(surfaces_under(
        &format!("HCLOUD_TOKEN={k}"),
        "hetzner-api-token",
        &k
    ));
}

// ── Railway: context UUID ────────────────────────────────────────────────────

#[test]
fn railway_api_token_surfaces() {
    let k = uuid(26);
    assert!(surfaces_under(
        &format!("RAILWAY_API_TOKEN={k}"),
        "railway-api-token",
        &k
    ));
}

// ── cross: several infra tokens co-surface ───────────────────────────────────

#[test]
fn digitalocean_flyio_render_cosurface() {
    let doc = format!("dop_v1_{}", hex(64, 27));
    let fly = format!("fm2_{}", alnum(43, 28));
    let rnd = format!("rnd_{}", alnum(24, 29));
    let text = format!("DIGITALOCEAN_TOKEN={doc}\nFLY_TOKEN={fly}\nRENDER_KEY={rnd}\n");
    assert!(surfaces_under(&text, "digitalocean-pat", &doc));
    assert!(surfaces_under(&text, "flyio-access-token", &fly));
    assert!(surfaces_under(&text, "render-api-key", &rnd));
}

#[test]
fn neon_linode_hetzner_cosurface() {
    let neon = format!("neon_api_{}", alnum(48, 30));
    let lin = hex(64, 31);
    let het = hex(64, 32);
    let text = format!("NEON={neon}\nLINODE_TOKEN={lin}\nHCLOUD_TOKEN={het}\n");
    assert!(surfaces_under(&text, "neon-api-key", &neon));
    assert!(surfaces_under(&text, "linode-pat", &lin));
    assert!(surfaces_under(&text, "hetzner-api-token", &het));
}
