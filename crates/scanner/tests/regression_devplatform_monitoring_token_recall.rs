//! Dev-platform + monitoring vendor credential recall + precision lock:
//! Databricks (`dapi`), LaunchDarkly (`api-<uuid>`), Grafana Cloud
//! (`glc_`/`glsa_`), PagerDuty (context 32-char), Buildkite agent token
//! (context 40-char), Okta (`00…` support token), Intercom (`dG9r…` base64),
//! Segment (context token), ClickUp (`pk_`), Algolia search key (context
//! 32-hex), Asana (`1/<id>/<token>` PAT), and Doppler CLI (`dp.ct/pt/sa.`).
//! These leak via CI env, SDK config, and monitoring agents. Built on the shared
//! `support::vendorgen` harness; none is checksum-gated.

mod support;
use support::vendorgen::{alnum, digits, fires, hex, lcnum, surfaces_under, uuid};

// ── Databricks: dapi<32+ hex> ────────────────────────────────────────────────

#[test]
fn databricks_token_surfaces() {
    let k = format!("dapi{}", hex(32, 1));
    assert!(
        surfaces_under(&k, "databricks-token", &k),
        "dapi token must surface"
    );
}

#[test]
fn databricks_31_hex_does_not_fire() {
    let k = format!("dapi{}", hex(31, 2)); // 31 < the required 32
    assert!(!fires(&k, "databricks-token"));
}

// ── LaunchDarkly: api-<uuid> ─────────────────────────────────────────────────

#[test]
fn launchdarkly_api_token_surfaces() {
    let k = format!("api-{}", uuid(3));
    assert!(
        surfaces_under(&k, "launchdarkly-api-token", &k),
        "api-<uuid> must surface"
    );
}

#[test]
fn launchdarkly_non_uuid_does_not_fire() {
    // `api-` followed by a bare 32-hex (no UUID grouping) is not the token shape.
    let k = format!("api-{}", hex(32, 4));
    assert!(!fires(&k, "launchdarkly-api-token"));
}

// ── Grafana Cloud: glc_ / glsa_ ──────────────────────────────────────────────

#[test]
fn grafana_glc_token_surfaces() {
    let k = format!("glc_{}", alnum(50, 5));
    assert!(
        surfaces_under(&k, "grafana-cloud-api-key", &k),
        "glc_ token must surface"
    );
}

#[test]
fn grafana_glsa_token_surfaces() {
    let k = format!("glsa_{}_{}", alnum(32, 6), hex(8, 7));
    assert!(
        surfaces_under(&k, "grafana-cloud-api-key", &k),
        "glsa_ token must surface"
    );
}

#[test]
fn grafana_glc_39_body_does_not_fire() {
    let k = format!("glc_{}", alnum(39, 8)); // 39 < the required 40
    assert!(!fires(&k, "grafana-cloud-api-key"));
}

// ── PagerDuty: context 32-char [a-z0-9] ──────────────────────────────────────

#[test]
fn pagerduty_api_key_surfaces() {
    let k = lcnum(32, 9);
    assert!(surfaces_under(
        &format!("PAGERDUTY_API_KEY={k}"),
        "pagerduty-api-key",
        &k
    ));
}

#[test]
fn pagerduty_31_char_does_not_fire() {
    let k = lcnum(31, 10); // 31 < the required 32
    assert!(!fires(
        &format!("PAGERDUTY_API_KEY={k}"),
        "pagerduty-api-key"
    ));
}

// ── Buildkite agent token: context 40-char ───────────────────────────────────

#[test]
fn buildkite_agent_token_surfaces() {
    let k = alnum(40, 11);
    assert!(surfaces_under(
        &format!("BUILDKITE_AGENT_TOKEN={k}"),
        "buildkite-agent-token",
        &k
    ));
}

#[test]
fn buildkite_39_char_does_not_fire() {
    let k = alnum(39, 12); // 39 < the required 40
    assert!(!fires(
        &format!("BUILDKITE_AGENT_TOKEN={k}"),
        "buildkite-agent-token"
    ));
}

// ── Okta: 00<38..50> support token ───────────────────────────────────────────

#[test]
fn okta_support_token_surfaces() {
    let t = format!("00{}", alnum(40, 13));
    assert!(surfaces_under(
        &format!("OKTA_TOKEN={t}"),
        "okta-support-token",
        &t
    ));
}

#[test]
fn okta_short_token_does_not_fire() {
    let t = format!("00{}", alnum(37, 14)); // 37 < the required 38
    assert!(!fires(&format!("OKTA_TOKEN={t}"), "okta-support-token"));
}

// ── Intercom: dG9r<100+> base64 ──────────────────────────────────────────────

#[test]
fn intercom_access_token_surfaces() {
    let t = format!("dG9r{}", alnum(105, 15));
    assert!(surfaces_under(
        &format!("INTERCOM_TOKEN={t}"),
        "intercom-access-token",
        &t
    ));
}

#[test]
fn intercom_99_body_does_not_fire() {
    let t = format!("dG9r{}", alnum(99, 16)); // 99 < the required 100
    assert!(!fires(
        &format!("INTERCOM_TOKEN={t}"),
        "intercom-access-token"
    ));
}

// ── Segment: context token ───────────────────────────────────────────────────

#[test]
fn segment_api_token_surfaces() {
    let k = alnum(40, 17);
    assert!(surfaces_under(
        &format!("SEGMENT_API_TOKEN={k}"),
        "segment-sources-api-token",
        &k
    ));
}

// ── ClickUp: pk_<20..40> ─────────────────────────────────────────────────────

#[test]
fn clickup_token_surfaces() {
    let k = format!("pk_{}", alnum(25, 18));
    assert!(
        surfaces_under(&k, "clickup-api-token", &k),
        "pk_ token must surface"
    );
}

#[test]
fn clickup_19_body_does_not_fire() {
    let k = format!("pk_{}", alnum(19, 19)); // 19 < the required 20
    assert!(!fires(&k, "clickup-api-token"));
}

// ── Algolia search key: context 32-hex ───────────────────────────────────────

#[test]
fn algolia_search_key_surfaces() {
    let k = hex(32, 20);
    assert!(surfaces_under(
        &format!("algolia_search_key={k}"),
        "algolia-search-key",
        &k
    ));
}

#[test]
fn algolia_search_only_key_anchor_surfaces() {
    let k = hex(32, 21);
    assert!(surfaces_under(
        &format!("search_only_api_key={k}"),
        "algolia-search-key",
        &k
    ));
}

// ── Asana: 1/<id>/<token> PAT ────────────────────────────────────────────────

#[test]
fn asana_pat_surfaces() {
    let t = format!("1/{}/{}", digits(18, 22), alnum(40, 23));
    assert!(surfaces_under(&format!("ASANA_PAT={t}"), "asana-pat", &t));
}

#[test]
fn asana_short_id_does_not_fire() {
    let t = format!("1/{}/{}", digits(15, 24), alnum(40, 25)); // 15 < the required 16
    assert!(!fires(&format!("ASANA_PAT={t}"), "asana-pat"));
}

// ── Doppler CLI token: dp.<ct|pt|sa>.<44> ────────────────────────────────────

#[test]
fn doppler_cli_token_surfaces() {
    let k = format!("dp.ct.{}", alnum(44, 26));
    assert!(
        surfaces_under(&k, "doppler-cli-token", &k),
        "dp.ct. token must surface"
    );
}

#[test]
fn doppler_cli_43_body_does_not_fire() {
    let k = format!("dp.ct.{}", alnum(43, 27)); // 43 < the required 44
    assert!(!fires(&k, "doppler-cli-token"));
}

// ── cross: several dev-platform tokens co-surface ────────────────────────────

#[test]
fn databricks_grafana_okta_cosurface() {
    let db = format!("dapi{}", hex(32, 28));
    let gr = format!("glc_{}", alnum(50, 29));
    let ok = format!("00{}", alnum(40, 30));
    let text = format!("DATABRICKS_TOKEN={db}\nGRAFANA_KEY={gr}\nOKTA_TOKEN={ok}\n");
    assert!(surfaces_under(&text, "databricks-token", &db));
    assert!(surfaces_under(&text, "grafana-cloud-api-key", &gr));
    assert!(surfaces_under(&text, "okta-support-token", &ok));
}

#[test]
fn buildkite_segment_doppler_cosurface() {
    let bk = alnum(40, 31);
    let sg = alnum(40, 32);
    let dp = format!("dp.pt.{}", alnum(44, 33));
    let text = format!("BUILDKITE_AGENT_TOKEN={bk}\nSEGMENT_API_TOKEN={sg}\nDOPPLER={dp}\n");
    assert!(surfaces_under(&text, "buildkite-agent-token", &bk));
    assert!(surfaces_under(&text, "segment-sources-api-token", &sg));
    assert!(surfaces_under(&text, "doppler-cli-token", &dp));
}
