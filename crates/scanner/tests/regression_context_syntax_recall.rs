//! Context-syntax recall lock for anchor-gated body detectors. These detectors
//! have a generic body (UUID / 20-/24-/32-64-hex) and rely entirely on a
//! distinctive vendor anchor, matched case-insensitively across every documented
//! config syntax: UPPER/lower/camelCase/kebab env vars, `_`/space/dotted
//! separators, `=` vs `:`, quoted vs unquoted, and multiple key-nouns
//! (API_KEY/KEY/TOKEN/IDENTIFIER/PROPERTY_ID). The recall contract is that ALL of
//! these fire (via case-insensitive keywords + the Hyperscan trigger union that
//! also surfaces non-keyword pattern literals such as Heroku's `heroku.api.key`),
//! while the bare body with NO anchor stays suppressed (the anchor is the whole
//! precision story). Heroku is the exemplar; crisp/helpscout/tawkto are siblings.
//!
//! Built on the shared `support::vendorgen` harness. Bodies are UUID/hex, which
//! are generic shapes; the named vendor anchor wins value-dedup (shape-collision
//! carve-out), so `surfaces_under` holds rather than relabeling to a generic id.

mod support;
use support::vendorgen::{fires, hex, surfaces_under, uuid};

// ── Heroku (UUID body, DET-18 floor override): every documented syntax ───────

#[test]
fn heroku_env_upper_fires() {
    let u = uuid(1);
    assert!(surfaces_under(
        &format!("HEROKU_API_KEY={u}"),
        "heroku-api-key",
        &u
    ));
}

#[test]
fn heroku_env_lower_fires() {
    let u = uuid(2);
    assert!(surfaces_under(
        &format!("heroku_api_key={u}"),
        "heroku-api-key",
        &u
    ));
}

#[test]
fn heroku_camel_case_fires() {
    let u = uuid(3);
    assert!(surfaces_under(
        &format!("herokuApiKey={u}"),
        "heroku-api-key",
        &u
    ));
}

#[test]
fn heroku_kebab_colon_fires() {
    let u = uuid(4);
    assert!(surfaces_under(
        &format!("heroku-api-key: {u}"),
        "heroku-api-key",
        &u
    ));
}

#[test]
fn heroku_dotted_ini_fires_via_hs_union() {
    // `heroku.api.key` is deliberately NOT in the keyword list; it fires only
    // because the Hyperscan trigger union surfaces the pattern's literal.
    let u = uuid(5);
    assert!(surfaces_under(
        &format!("heroku.api.key = {u}"),
        "heroku-api-key",
        &u
    ));
}

#[test]
fn heroku_quoted_value_fires() {
    let u = uuid(6);
    assert!(surfaces_under(
        &format!("HEROKU_API_KEY=\"{u}\""),
        "heroku-api-key",
        &u
    ));
}

#[test]
fn heroku_mixed_case_fires() {
    // (?i) makes the anchor case-insensitive.
    let u = uuid(7);
    assert!(surfaces_under(
        &format!("Heroku_Api_Key={u}"),
        "heroku-api-key",
        &u
    ));
}

#[test]
fn heroku_bare_uuid_without_anchor_is_suppressed() {
    // The body is a plain UUID; with no Heroku anchor it must not fire.
    let u = uuid(8);
    assert!(!fires(&u, "heroku-api-key"));
}

// ── Crisp (UUID body): key-noun + separator variety ──────────────────────────

#[test]
fn crisp_api_key_underscore_fires() {
    let u = uuid(9);
    assert!(surfaces_under(
        &format!("CRISP_API_KEY={u}"),
        "crisp-api-key",
        &u
    ));
}

#[test]
fn crisp_key_space_separator_fires() {
    let u = uuid(10);
    assert!(surfaces_under(
        &format!("crisp key: {u}"),
        "crisp-api-key",
        &u
    ));
}

#[test]
fn crisp_identifier_noun_fires() {
    let u = uuid(11);
    assert!(surfaces_under(
        &format!("CRISP_IDENTIFIER={u}"),
        "crisp-api-key",
        &u
    ));
}

#[test]
fn crisp_token_lower_fires() {
    let u = uuid(12);
    assert!(surfaces_under(
        &format!("crisp_token={u}"),
        "crisp-api-key",
        &u
    ));
}

// ── Helpscout (20-hex body) ──────────────────────────────────────────────────

#[test]
fn helpscout_api_key_fires() {
    let k = hex(20, 13);
    assert!(surfaces_under(
        &format!("HELPSCOUT_API_KEY={k}"),
        "helpscout-api-key",
        &k
    ));
}

#[test]
fn helpscout_underscored_anchor_fires() {
    let k = hex(20, 14);
    assert!(surfaces_under(
        &format!("HELP_SCOUT_KEY={k}"),
        "helpscout-api-key",
        &k
    ));
}

#[test]
fn helpscout_lower_fires() {
    let k = hex(20, 15);
    assert!(surfaces_under(
        &format!("helpscout_api_key={k}"),
        "helpscout-api-key",
        &k
    ));
}

#[test]
fn helpscout_19_hex_does_not_fire() {
    let k = hex(19, 16); // 19 < the required 20
    assert!(!fires(
        &format!("HELPSCOUT_API_KEY={k}"),
        "helpscout-api-key"
    ));
}

// ── Tawk.to (32-64-hex key, 24-hex property/site companion id) ──────────────

#[test]
fn tawkto_api_key_fires() {
    let k = hex(40, 17);
    assert!(surfaces_under(
        &format!("TAWK_API_KEY={k}"),
        "tawkto-api-key",
        &k
    ));
}

#[test]
fn tawkto_property_id_alone_is_companion_context() {
    let k = hex(24, 18);
    assert!(!fires(&format!("TAWKTO_PROPERTY_ID={k}"), "tawkto-api-key"));
}

#[test]
fn tawkto_token_lower_fires() {
    let k = hex(50, 19);
    assert!(surfaces_under(
        &format!("tawk_to_token={k}"),
        "tawkto-api-key",
        &k
    ));
}

#[test]
fn tawkto_site_id_alone_is_companion_context() {
    let k = hex(24, 20);
    assert!(!fires(&format!("TAWKTO_SITE_ID={k}"), "tawkto-api-key"));
}

// ── cross: several anchor-gated bodies co-surface ────────────────────────────

#[test]
fn heroku_crisp_tawkto_cosurface() {
    let h = uuid(21);
    let c = uuid(22);
    let t = hex(40, 23);
    let text = format!("HEROKU_API_KEY={h}\nCRISP_API_KEY={c}\nTAWK_API_KEY={t}\n");
    assert!(surfaces_under(&text, "heroku-api-key", &h));
    assert!(surfaces_under(&text, "crisp-api-key", &c));
    assert!(surfaces_under(&text, "tawkto-api-key", &t));
}
