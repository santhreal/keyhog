//! Precision negative-twin for the vendor recall locks. Every recall lock proves
//! a real credential surfaces; this proves the mirror image — that the same
//! detectors do NOT fire on the lookalike non-secrets that share a shape but
//! lack the vendor's anchor or prefix. Context-anchored detectors must ignore
//! bare git SHAs / UUIDs / hashes (no anchor → no fire), and distinctive-prefix
//! detectors must ignore near-miss prefixes and sub-minimum bodies. A regression
//! that dropped an anchor or widened a prefix would turn any of these into a
//! false positive; this file is the guard.

mod support;
use support::vendorgen::{alnum, fires, fires_any, hex, uuid};

const HF: &[&str] = &[
    "huggingface-api-key",
    "huggingface-org-token",
    "huggingface-user-token",
];

// ── context-anchored detectors must ignore bare 40-hex (git SHA / hash) ──────

#[test]
fn bare_40_hex_does_not_fire_sonarcloud() {
    assert!(!fires(&hex(40, 1), "sonarcloud-token"));
}

#[test]
fn bare_40_hex_does_not_fire_sonarqube() {
    assert!(!fires(&hex(40, 2), "sonarqube-token"));
}

#[test]
fn bare_40_hex_does_not_fire_newrelic_license() {
    assert!(!fires(&hex(40, 3), "newrelic-license-key"));
}

#[test]
fn bare_40_hex_does_not_fire_circleci() {
    assert!(!fires(&hex(40, 4), "circleci-api-token"));
}

#[test]
fn bare_40_hex_does_not_fire_datadog_application() {
    assert!(!fires(&hex(40, 5), "datadog-application-key"));
}

#[test]
fn bare_40_hex_does_not_fire_cloudflare_global() {
    // Cloudflare's global key is 37-hex AND anchored; a bare 40-hex is neither.
    assert!(!fires(&hex(40, 6), "cloudflare-global-api-key"));
}

// ── context-anchored detectors must ignore bare UUIDs ────────────────────────

#[test]
fn bare_uuid_does_not_fire_snyk() {
    assert!(!fires(&uuid(7), "snyk-api-token"));
}

#[test]
fn bare_uuid_does_not_fire_heroku() {
    assert!(!fires(&uuid(8), "heroku-api-key"));
}

#[test]
fn bare_uuid_does_not_fire_postmark() {
    assert!(!fires(&uuid(9), "postmark-server-token"));
}

// ── context-anchored detectors must ignore bare 32-hex / 20-hex ──────────────

#[test]
fn bare_32_hex_does_not_fire_datadog_api() {
    assert!(!fires(&hex(32, 10), "datadog-api-key"));
}

#[test]
fn bare_32_hex_does_not_fire_mailchimp() {
    assert!(!fires(&hex(32, 11), "mailchimp-api-key"));
}

#[test]
fn bare_32_hex_does_not_fire_pusher() {
    assert!(!fires(&hex(32, 12), "pusher-app-key"));
}

#[test]
fn bare_24_alnum_does_not_fire_vercel_token() {
    assert!(!fires(&alnum(24, 13), "vercel-token"));
}

// ── near-miss prefixes must not fire distinctive-prefix detectors ────────────

#[test]
fn wrong_jfrog_prefix_does_not_fire() {
    // `AKCp9` is not the `AKCp8` JFrog prefix.
    let k = format!("AKCp9{}", alnum(40, 14));
    assert!(!fires(&k, "jfrog-api-key"));
}

#[test]
fn hyphenated_hf_prefix_does_not_fire() {
    // HuggingFace is `hf_`, not `hf-`.
    let k = format!("hf-{}", alnum(34, 15));
    assert!(!fires_any(&k, HF));
}

#[test]
fn hyphenated_groq_prefix_does_not_fire() {
    // Groq is `gsk_`, not `gsk-`.
    let k = format!("gsk-{}", alnum(52, 16));
    assert!(!fires(&k, "groq-api-key"));
}

#[test]
fn underscored_perplexity_prefix_does_not_fire() {
    // Perplexity is `pplx-`, not `pplx_`.
    let k = format!("pplx_{}", alnum(32, 17));
    assert!(!fires(&k, "perplexity-api-key"));
}

#[test]
fn wrong_replicate_prefix_does_not_fire() {
    // Replicate is `r8_`, not `r9_`.
    let k = format!("r9_{}", alnum(37, 18));
    assert!(!fires(&k, "replicate-api-key"));
}

#[test]
fn typo_dockerhub_prefix_does_not_fire() {
    // Docker Hub is `dckr_pat_`, not `dckr_pta_`.
    let k = format!("dckr_pta_{}", alnum(40, 19));
    assert!(!fires(&k, "dockerhub-pat"));
}

// ── sub-minimum bodies under the right anchor/prefix must not fire ───────────

#[test]
fn pypi_prefix_with_short_body_does_not_fire() {
    // The `pypi-` prefix triggers the prefilter, but a 10-char body is far below
    // the 100-char minimum, so the pattern cannot match.
    let k = format!("pypi-{}", alnum(10, 20));
    assert!(!fires(&k, "pypi-api-token"));
}

#[test]
fn sonarcloud_anchor_with_short_token_does_not_fire() {
    // The SONAR anchor is present but a 20-hex body is below the 40-hex length.
    let k = hex(20, 21);
    assert!(!fires(&format!("SONAR_CLOUD_TOKEN={k}"), "sonarcloud-token"));
}

#[test]
fn openrouter_anchor_with_short_body_does_not_fire() {
    // OpenRouter needs `sk-or-v1-` + >=48 hex; 20 hex is far short.
    let k = format!("sk-or-v1-{}", hex(20, 22));
    assert!(!fires(&k, "openrouter-api-key"));
}
