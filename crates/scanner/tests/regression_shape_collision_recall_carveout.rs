//! Shape-collision recall carve-out: named vendor anchors exempt their canonical
//! token shape from the *generic* shape suppressions.
//!
//! keyhog deliberately suppresses three generic value shapes that flood real
//! code with false positives when they appear bare:
//!   * UUID v4 (`8-4-4-4-12` hex), request ids, session ids, record ids;
//!   * 40-hex, git SHA-1, MD5+pad, ETag, content hash;
//!   * 64-hex: SHA-256 digests / content addresses.
//! Those suppressions live in the *generic* lane (bare value, or value under a
//! bare/ambiguous `key`/`id`/`secret_key` anchor). They are **anchor-gated**:
//! when the SAME byte shape carries a vendor-specific anchor that a named
//! detector recognises, the named detector surfaces it. That asymmetry is the
//! whole reason keyhog can ship UUID-shaped (Heroku), 40-hex (CircleCI, Datadog,
//! New Relic, Deepgram) and 64-hex (DigitalOcean, Brevo, Airtable) detectors
//! *without* the generic shape suppressions eating their recall.
//!
//! The per-detector contracts each prove their own positive in isolation. They
//! do NOT prove the cross-cutting invariant this file locks:
//!   1. the EXACT bytes that surface under a vendor anchor STAY suppressed when
//!      bare or under a generic `key`/`id`/`secret_key` anchor (the carve-out is
//!      real, not an accident of differing values), and
//!   2. two shape-colliders co-surface in one file with no mutual suppression
//!      (resolution does not let one shape-colliding finding evict another).
//!
//! A regression that widened the generic UUID/40-hex/64-hex suppression to fire
//! regardless of anchor would crater the recall of every detector named above
//! while every per-detector contract still passed (each plants its own value in
//! its own file). This file is the guard against exactly that.
//!
//! Every token body below is copied verbatim from the detector's shipped
//! contract positive, so each "surfaces" assertion exercises a value already
//! proven to be detectable, the test isolates the anchor variable, not the
//! value. Assertions check the exact surfaced/absent credential bytes via the
//! shared `surfaces` / `nothing_surfaces` helpers (never `!is_empty`).

mod support;
use support::contracts::{make_chunk, scanner};

use keyhog_core::Chunk;
use keyhog_scanner::CompiledScanner;

/// All surfaced (detector_id, credential) pairs for `text`, scanned on disk.
fn matches(s: &CompiledScanner, chunk: &Chunk) -> Vec<(String, String)> {
    s.clear_fragment_cache();
    s.scan(chunk)
        .into_iter()
        .map(|m| (m.detector_id.to_string(), m.credential.as_str().to_string()))
        .collect()
}

/// True iff SOME surfaced match carries exactly `credential` (the whole value).
fn surfaces(text: &str, credential: &str) -> bool {
    let s = scanner();
    let chunk = make_chunk(text, "source", "probe.conf");
    matches(&s, &chunk)
        .iter()
        .any(|(_, cred)| cred == credential)
}

/// True iff the surfaced match carrying exactly `credential` came from `detector`.
fn surfaces_under(text: &str, detector: &str, credential: &str) -> bool {
    let s = scanner();
    let chunk = make_chunk(text, "source", "probe.conf");
    matches(&s, &chunk)
        .iter()
        .any(|(id, cred)| id == detector && cred == credential)
}

/// True iff NOTHING surfaces the exact `credential` value (under any detector).
fn nothing_surfaces(text: &str, credential: &str) -> bool {
    let s = scanner();
    let chunk = make_chunk(text, "source", "probe.conf");
    !matches(&s, &chunk)
        .iter()
        .any(|(_, cred)| cred == credential)
}

// Canonical, contract-proven token bodies (verbatim from each detector's
// shipped contract positive). Reused across the surfacing positive and the
// bare/generic-anchor suppression negative so the test varies ONLY the anchor.
const HEROKU_UUID: &str = "9a3b7c2e-4d1f-6a8b-0c5d-9e3f7a1b4c2d"; // UUID-v4 shape
const CIRCLE_H40: &str = "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d8e6a2b9f"; // 40-hex / git-SHA shape
const CIRCLE_H40_LC: &str = "4c9a8f6e3b7d1a2c5e8f0b9d6a3c4e1f7b2d9c5a"; // 40-hex
const DATADOG_H40: &str = "3b70df2c347b7e02b642198793dc0b8a9827bb4c"; // 40-hex
const NEWRELIC_H40: &str = "5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3ea9e2f5b8"; // 40-hex
                                                                       // DigitalOcean PAT = `dop_v1_` + this 64-hex core (SHA-256 shape).
const DO_H64_CORE: &str = "9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b";
const DO_PAT: &str = "dop_v1_9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b";
// Brevo key = `xkeysib-` + 64-hex; Airtable PAT = `pat<14 alnum>.` + 64-hex.
const BREVO_KEY: &str = "xkeysib-7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d";
const AIRTABLE_PAT: &str =
    "pat9X3kQp7VbT2hYR.9a3b7c2e4d1f6a8b0c5d9e3f7a1b4c2d8e6f0a1b3c4d5e6f7a8b9c0d1e2f3a4b";

// ── UUID-v4 shape: Heroku anchor surfaces, bare / generic anchors suppress ────

#[test]
fn heroku_env_anchor_surfaces_uuid_body() {
    assert!(
        surfaces_under(
            &format!("HEROKU_API_KEY={HEROKU_UUID}"),
            "heroku-api-key",
            HEROKU_UUID
        ),
        "a UUID body under the HEROKU_API_KEY anchor must surface as heroku-api-key"
    );
}

#[test]
fn heroku_yaml_anchor_surfaces_uuid_body() {
    assert!(
        surfaces(&format!("heroku_api_key: {HEROKU_UUID}"), HEROKU_UUID),
        "the lowercase YAML `heroku_api_key:` anchor must surface the UUID body"
    );
}

#[test]
fn heroku_dotted_property_anchor_surfaces_uuid_body() {
    assert!(
        surfaces(&format!("heroku.api.key = {HEROKU_UUID}"), HEROKU_UUID),
        "the dotted-property `heroku.api.key =` anchor must surface the UUID body"
    );
}

#[test]
fn same_uuid_bare_stays_suppressed() {
    assert!(
        nothing_surfaces(HEROKU_UUID, HEROKU_UUID),
        "the SAME UUID with no Heroku anchor is a generic identifier and must stay \
         suppressed: the carve-out is anchor-gated, not value-gated"
    );
}

#[test]
fn same_uuid_under_record_id_stays_suppressed() {
    assert!(
        nothing_surfaces(&format!("id = {HEROKU_UUID}"), HEROKU_UUID),
        "the SAME UUID under a bare record `id =` is an identifier, not a secret"
    );
}

#[test]
fn same_uuid_under_session_id_stays_suppressed() {
    assert!(
        nothing_surfaces(&format!("session_id={HEROKU_UUID}"), HEROKU_UUID),
        "the SAME UUID under `session_id=` is a session identifier, not a credential"
    );
}

// ── 40-hex (git-SHA) shape: vendor anchors surface, bare / `key` suppress ─────

#[test]
fn circleci_env_anchor_surfaces_hex40_body() {
    assert!(
        surfaces_under(
            &format!("CIRCLE_TOKEN={CIRCLE_H40}"),
            "circleci-api-token",
            CIRCLE_H40
        ),
        "a 40-hex body under CIRCLE_TOKEN must surface as circleci-api-token"
    );
}

#[test]
fn circleci_lowercase_anchor_surfaces_hex40_body() {
    assert!(
        surfaces(&format!("circleci_token={CIRCLE_H40_LC}"), CIRCLE_H40_LC),
        "the lowercase `circleci_token=` anchor must surface its 40-hex body"
    );
}

#[test]
fn datadog_app_key_anchor_surfaces_hex40_body() {
    assert!(
        surfaces_under(
            &format!("DATADOG_APP_KEY={DATADOG_H40}"),
            "datadog-application-key",
            DATADOG_H40
        ),
        "a 40-hex body under DATADOG_APP_KEY must surface as datadog-application-key"
    );
}

#[test]
fn newrelic_license_key_anchor_surfaces_hex40_body() {
    assert!(
        surfaces_under(
            &format!("NEW_RELIC_LICENSE_KEY={NEWRELIC_H40}"),
            "newrelic-license-key",
            NEWRELIC_H40
        ),
        "a 40-hex body under NEW_RELIC_LICENSE_KEY must surface as newrelic-license-key"
    );
}

#[test]
fn deepgram_api_key_anchor_surfaces_hex40_body() {
    // Same 40-hex byte shape as the bare-suppressed value below, under the
    // Deepgram vendor anchor.
    assert!(
        surfaces(&format!("deepgram_api_key={CIRCLE_H40_LC}"), CIRCLE_H40_LC),
        "a 40-hex body under the `deepgram_api_key=` anchor must surface"
    );
}

#[test]
fn same_hex40_under_bare_key_stays_suppressed() {
    assert!(
        nothing_surfaces(&format!("key = {CIRCLE_H40}"), CIRCLE_H40),
        "the SAME 40-hex under a bare `key =` must stay suppressed, bare 40-hex \
         is indistinguishable from a git SHA-1 / ETag / content hash"
    );
}

#[test]
fn same_hex40_bare_line_stays_suppressed() {
    assert!(
        nothing_surfaces(&format!("    {CIRCLE_H40}\n"), CIRCLE_H40),
        "a bare 40-hex line with no vendor anchor must surface nothing"
    );
}

// ── 64-hex (SHA-256) shape: prefixed vendor tokens surface, bare suppress ─────

#[test]
fn digitalocean_prefixed_token_surfaces() {
    assert!(
        surfaces_under(&format!("token = {DO_PAT}"), "digitalocean-pat", DO_PAT),
        "the `dop_v1_`-prefixed 64-hex DigitalOcean PAT must surface whole"
    );
}

#[test]
fn digitalocean_env_assignment_surfaces() {
    assert!(
        surfaces(&format!("DIGITALOCEAN_TOKEN={DO_PAT}"), DO_PAT),
        "the DigitalOcean PAT under a DIGITALOCEAN_TOKEN env assignment must surface"
    );
}

#[test]
fn brevo_prefixed_token_surfaces() {
    assert!(
        surfaces_under(&format!("api-key: {BREVO_KEY}"), "brevo-api-key", BREVO_KEY),
        "the `xkeysib-`-prefixed 64-hex Brevo key must surface whole"
    );
}

#[test]
fn airtable_prefixed_token_surfaces() {
    assert!(
        surfaces_under(
            &format!("AIRTABLE_API_KEY={AIRTABLE_PAT}"),
            "airtable-api-key",
            AIRTABLE_PAT
        ),
        "the `pat<14>.<64hex>` Airtable PAT must surface whole"
    );
}

#[test]
fn same_hex64_core_under_strong_secret_anchor_stays_suppressed() {
    // The DigitalOcean PAT's 64-hex core, stripped of the `dop_v1_` prefix and
    // placed under a strong `secret_key` anchor, is a SHA-256 shape trap and
    // must stay suppressed (only the vendor prefix promotes these bytes).
    assert!(
        nothing_surfaces(&format!("secret_key = {DO_H64_CORE}"), DO_H64_CORE),
        "the bare 64-hex core under `secret_key =` must stay suppressed (sha256 trap)"
    );
}

#[test]
fn same_hex64_core_bare_line_stays_suppressed() {
    assert!(
        nothing_surfaces(&format!("    {DO_H64_CORE}\n"), DO_H64_CORE),
        "a bare 64-hex line (no vendor prefix) must surface nothing"
    );
}

// ── No mutual suppression: shape-colliders co-surface in one file ─────────────

#[test]
fn heroku_uuid_and_circleci_hex40_cosurface() {
    let text = format!("HEROKU_API_KEY={HEROKU_UUID}\nCIRCLE_TOKEN={CIRCLE_H40}\n");
    assert!(
        surfaces(&text, HEROKU_UUID),
        "heroku UUID must surface alongside circleci"
    );
    assert!(
        surfaces(&text, CIRCLE_H40),
        "circleci 40-hex must surface alongside heroku"
    );
}

#[test]
fn digitalocean_and_brevo_tokens_cosurface() {
    let text = format!("DIGITALOCEAN_TOKEN={DO_PAT}\nBREVO_API_KEY={BREVO_KEY}\n");
    assert!(
        surfaces(&text, DO_PAT),
        "digitalocean PAT must surface alongside brevo"
    );
    assert!(
        surfaces(&text, BREVO_KEY),
        "brevo key must surface alongside digitalocean"
    );
}

#[test]
fn all_three_collision_shapes_cosurface_in_one_file() {
    // One file carrying a UUID-shaped, a 40-hex and a 64-hex vendor token: all
    // three surface, none evicts another, and none of the three generic shape
    // suppressions fires because each value carries a recognised vendor anchor.
    let text = format!(
        "HEROKU_API_KEY={HEROKU_UUID}\nDATADOG_APP_KEY={DATADOG_H40}\nAIRTABLE_API_KEY={AIRTABLE_PAT}\n"
    );
    assert!(
        surfaces(&text, HEROKU_UUID),
        "UUID-shaped vendor token must surface"
    );
    assert!(
        surfaces(&text, DATADOG_H40),
        "40-hex vendor token must surface"
    );
    assert!(
        surfaces(&text, AIRTABLE_PAT),
        "64-hex vendor token must surface"
    );
}
