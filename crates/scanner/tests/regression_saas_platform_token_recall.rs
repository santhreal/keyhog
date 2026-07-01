//! High-real-world-value SaaS/cloud platform credential recall + precision lock:
//! Google API key (`AIza…`, the single most common real-world leak), Notion
//! (`ntn_` / `secret_`), Dropbox (`sl.` access token), Figma (`figd_` PAT),
//! Linear (`lin_api_`), Airtable (`pat….<64hex>`), Algolia (admin key), and
//! Contentful (delivery token). These dominate real credential corpora, so
//! locking their recall directly serves the CredData real-recall gap. Built on
//! the shared `support::vendorgen` harness.
//!
//! `secret_<43>` (Notion's legacy form) shares a generic `secret_` shape, so its
//! value can carry a generic label after dedup — it is asserted as detected, not
//! by vendor label. The `ntn_` form is the unambiguous Notion lock.

mod support;
use support::vendorgen::{alnum, detected, fires, hex, surfaces_under, surfaces_under_any};

const NOTION: &[&str] = &["notion-api-key", "notion-integration-token"];

// ── Google API key: AIza<35> ─────────────────────────────────────────────────

#[test]
fn google_api_key_bare_surfaces() {
    let k = format!("AIza{}", alnum(35, 1));
    assert!(
        surfaces_under(&k, "google-api-key", &k),
        "AIza key must surface"
    );
}

#[test]
fn google_aizasy_form_surfaces() {
    let k = format!("AIzaSy{}", alnum(33, 2));
    assert!(surfaces_under(&k, "google-api-key", &k));
}

#[test]
fn google_api_key_env_anchor_surfaces() {
    let k = format!("AIza{}", alnum(35, 3));
    assert!(surfaces_under(
        &format!("GOOGLE_API_KEY={k}"),
        "google-api-key",
        &k
    ));
}

#[test]
fn google_cloudfunctions_anchor_surfaces() {
    let k = format!("AIza{}", alnum(35, 4));
    assert!(surfaces_under(
        &format!("CLOUDFUNCTIONS_API_KEY={k}"),
        "google-api-key",
        &k
    ));
}

#[test]
fn google_youtube_anchor_surfaces() {
    let k = format!("AIza{}", alnum(35, 5));
    assert!(surfaces_under(
        &format!("YOUTUBE_API_KEY={k}"),
        "google-api-key",
        &k
    ));
}

#[test]
fn google_api_key_34_body_does_not_fire() {
    // A valid Google key is `AIza` + 35 chars (39 total). 38 total matches neither
    // the `AIza{35}` nor the `AIzaSy{33}` pattern.
    let k = format!("AIza{}", alnum(34, 6));
    assert!(!fires(&k, "google-api-key"));
}

// ── Notion: ntn_ (distinctive) + secret_ (generic-shape) ─────────────────────

#[test]
fn notion_ntn_token_surfaces() {
    let k = format!("ntn_{}", alnum(45, 7));
    assert!(
        surfaces_under(&k, "notion-integration-token", &k),
        "ntn_ token must surface"
    );
}

#[test]
fn notion_secret_token_is_detected() {
    // `secret_<43>` is Notion's legacy shape but also a generic secret shape;
    // dedup may keep a generic label, so assert recall (detected), not the label.
    let k = format!("secret_{}", alnum(43, 8));
    assert!(detected(&k, &k) || surfaces_under_any(&k, NOTION, &k));
}

#[test]
fn notion_ntn_42_body_does_not_fire() {
    let k = format!("ntn_{}", alnum(42, 9)); // 42 < the required 43
    assert!(!fires(&k, "notion-integration-token"));
}

// ── Dropbox: sl.<100+> ───────────────────────────────────────────────────────

#[test]
fn dropbox_access_token_surfaces() {
    let k = format!("sl.{}", alnum(110, 10));
    assert!(
        surfaces_under(&k, "dropbox-access-token", &k),
        "sl. token must surface"
    );
}

#[test]
fn dropbox_99_body_does_not_fire() {
    let k = format!("sl.{}", alnum(99, 11)); // 99 < the required 100
    assert!(!fires(&k, "dropbox-access-token"));
}

// ── Figma: figd_<20..50> ─────────────────────────────────────────────────────

#[test]
fn figma_pat_surfaces() {
    let k = format!("figd_{}", alnum(30, 12));
    assert!(
        surfaces_under(&k, "figma-pat", &k),
        "figd_ token must surface"
    );
}

#[test]
fn figma_pat_19_body_does_not_fire() {
    let k = format!("figd_{}", alnum(19, 13)); // 19 < the required 20
    assert!(!fires(&k, "figma-pat"));
}

// ── Linear: lin_api_<40> ─────────────────────────────────────────────────────

#[test]
fn linear_api_key_surfaces() {
    let k = format!("lin_api_{}", alnum(40, 14));
    assert!(
        surfaces_under(&k, "linear-api-key", &k),
        "lin_api_ key must surface"
    );
}

#[test]
fn linear_api_key_39_body_does_not_fire() {
    let k = format!("lin_api_{}", alnum(39, 15)); // 39 < the required 40
    assert!(!fires(&k, "linear-api-key"));
}

// ── Airtable: pat<14>.<64hex> ────────────────────────────────────────────────

#[test]
fn airtable_pat_surfaces() {
    let k = format!("pat{}.{}", alnum(14, 16), hex(64, 17));
    assert!(
        surfaces_under(&k, "airtable-api-key", &k),
        "airtable pat token must surface"
    );
}

#[test]
fn airtable_pat_63_hex_does_not_fire() {
    let k = format!("pat{}.{}", alnum(14, 18), hex(63, 19)); // 63 < the required 64
    assert!(!fires(&k, "airtable-api-key"));
}

// ── Algolia admin key: context 32-hex ────────────────────────────────────────

#[test]
fn algolia_admin_key_surfaces() {
    let k = hex(32, 20);
    assert!(surfaces_under(
        &format!("ALGOLIA_ADMIN_KEY={k}"),
        "algolia-admin-api-key",
        &k
    ));
}

#[test]
fn algolia_admin_api_key_anchor_surfaces() {
    let k = hex(32, 21);
    assert!(surfaces_under(
        &format!("admin_api_key={k}"),
        "algolia-admin-api-key",
        &k
    ));
}

// ── Contentful delivery token: context 43-char ───────────────────────────────

#[test]
fn contentful_delivery_token_surfaces() {
    let k = alnum(43, 22);
    assert!(surfaces_under(
        &format!("CONTENTFUL_DELIVERY_TOKEN={k}"),
        "contentful-delivery-token",
        &k
    ));
}

#[test]
fn contentful_access_token_variant_surfaces() {
    let k = alnum(43, 23);
    assert!(surfaces_under(
        &format!("CONTENTFUL_ACCESS_TOKEN={k}"),
        "contentful-delivery-token",
        &k
    ));
}

// ── cross: several SaaS tokens co-surface ────────────────────────────────────

#[test]
fn multiple_saas_tokens_cosurface() {
    let g = format!("AIza{}", alnum(35, 24));
    let n = format!("ntn_{}", alnum(45, 25));
    let d = format!("sl.{}", alnum(110, 26));
    let text = format!("GOOGLE_API_KEY={g}\nNOTION_TOKEN={n}\nDROPBOX_TOKEN={d}\n");
    assert!(surfaces_under(&text, "google-api-key", &g));
    assert!(surfaces_under(&text, "notion-integration-token", &n));
    assert!(surfaces_under(&text, "dropbox-access-token", &d));
}

#[test]
fn figma_linear_airtable_cosurface() {
    let f = format!("figd_{}", alnum(30, 27));
    let l = format!("lin_api_{}", alnum(40, 28));
    let a = format!("pat{}.{}", alnum(14, 29), hex(64, 30));
    let text = format!("FIGMA_PAT={f}\nLINEAR_API_KEY={l}\nAIRTABLE_API_KEY={a}\n");
    assert!(surfaces_under(&text, "figma-pat", &f));
    assert!(surfaces_under(&text, "linear-api-key", &l));
    assert!(surfaces_under(&text, "airtable-api-key", &a));
}
