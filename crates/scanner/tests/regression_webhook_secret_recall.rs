//! Webhook secret recall lock: incoming-webhook URLs that embed a secret token
//! (Slack / Discord / Zapier) and webhook SIGNING secrets (Stripe / GitHub /
//! Shopify). A leaked incoming-webhook URL lets anyone post into the channel;
//! a leaked signing secret lets an attacker forge authentic webhook deliveries.
//! These detectors ship but had no dedicated recall test, this pins that the
//! exact secret-bearing bytes surface, and that host/shape precision holds.

mod support;
use support::contracts::{make_chunk, scanner};

use keyhog_core::Chunk;
use keyhog_scanner::CompiledScanner;

/// Deterministic, diverse alphanumeric of length `n` (seeded LCG → flat
/// distribution, above the entropy floor) for the token segments.
fn alnum(n: usize, seed: usize) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut s = (seed as u64)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0x0BAD_F00D);
    (0..n)
        .map(|_| {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            A[((s >> 33) % 62) as usize] as char
        })
        .collect()
}

/// Deterministic near-uniform lowercase hex of length `n`.
fn hex(n: usize, seed: usize) -> String {
    const H: &[u8] = b"0123456789abcdef";
    let mut s = (seed as u64)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0x00C0_FFEE);
    (0..n)
        .map(|_| {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            H[((s >> 33) & 0xF) as usize] as char
        })
        .collect()
}

fn scan(text: &str) -> Vec<(String, String)> {
    let s: &CompiledScanner = &scanner();
    let chunk: Chunk = make_chunk(text, "source", "config.yaml");
    s.clear_fragment_cache();
    s.scan(&chunk)
        .into_iter()
        .map(|m| (m.detector_id.to_string(), m.credential.to_string()))
        .collect()
}

/// True iff SOME surfaced credential contains `needle`.
fn surfaces(text: &str, needle: &str) -> bool {
    scan(text).iter().any(|(_, cred)| cred.contains(needle))
}

/// True iff SOME surfaced credential under `detector` contains `needle`.
fn surfaces_under(text: &str, detector: &str, needle: &str) -> bool {
    scan(text)
        .iter()
        .any(|(id, cred)| id == detector && cred.contains(needle))
}

/// True iff `detector` produced at least one match on `text` (id-scoped).
fn fires(text: &str, detector: &str) -> bool {
    scan(text).iter().any(|(id, _)| id == detector)
}

/// A canonical Slack incoming-webhook URL with a 24-char secret segment.
fn slack_url(seed: usize) -> String {
    format!(
        "https://hooks.slack.com/services/T{}/B{}/{}",
        alnum(9, seed),
        alnum(9, seed + 1),
        alnum(24, seed + 2)
    )
}

/// A canonical Discord webhook URL: 18-digit id + 68-char token.
fn discord_url(seed: usize) -> String {
    format!(
        "https://discord.com/api/webhooks/123456789012345678/{}",
        alnum(68, seed)
    )
}

// ── incoming-webhook URLs embed the secret in the path ────────────────────────

#[test]
fn slack_incoming_webhook_url_surfaces() {
    let url = slack_url(1);
    assert!(
        surfaces_under(&url, "slack-webhook-url", &url),
        "a Slack webhook URL must surface"
    );
}

#[test]
fn slack_webhook_url_in_yaml_value_surfaces() {
    let url = slack_url(2);
    let text = format!("notifications:\n  slack_webhook_url: {url}\n");
    assert!(
        surfaces(&text, &url),
        "a Slack webhook URL as a YAML value must surface"
    );
}

#[test]
fn slack_webhook_url_anchored_assignment_surfaces() {
    let url = slack_url(3);
    assert!(
        surfaces(&format!("SLACK_WEBHOOK_URL={url}"), &url),
        "SLACK_WEBHOOK_URL= must surface"
    );
}

#[test]
fn discord_webhook_url_surfaces() {
    let url = discord_url(4);
    assert!(
        surfaces_under(&url, "discord-webhook-credentials", &url),
        "a Discord webhook URL must surface"
    );
}

#[test]
fn discord_webhook_url_in_json_field_surfaces() {
    let url = discord_url(5);
    let text = format!("{{\"discord_webhook\":\"{url}\"}}");
    assert!(
        surfaces(&text, &url),
        "a Discord webhook URL in a JSON field must surface"
    );
}

#[test]
fn zapier_webhook_url_surfaces() {
    let url = format!(
        "https://hooks.zapier.com/hooks/catch/123456789/{}/",
        alnum(16, 6)
    );
    assert!(
        surfaces_under(&url, "zapier-webhook-url", &url),
        "a Zapier webhook URL must surface"
    );
}

// ── webhook SIGNING secrets ──────────────────────────────────────────────────

#[test]
fn stripe_whsec_bare_surfaces() {
    let sec = format!("whsec_{}", alnum(40, 7));
    assert!(
        surfaces_under(&sec, "stripe-webhook-signing-secret", &sec),
        "a bare Stripe whsec_ signing secret must surface"
    );
}

#[test]
fn stripe_whsec_anchored_surfaces() {
    let sec = format!("whsec_{}", alnum(40, 8));
    assert!(
        surfaces(&format!("STRIPE_WEBHOOK_SECRET={sec}"), &sec),
        "an anchored Stripe webhook secret must surface"
    );
}

#[test]
fn github_webhook_secret_surfaces() {
    let sec = alnum(40, 9);
    assert!(
        surfaces_under(
            &format!("GITHUB_WEBHOOK_SECRET={sec}"),
            "github-webhook-secret",
            &sec
        ),
        "a GitHub webhook secret must surface"
    );
}

#[test]
fn github_webhook_secret_lowercase_colon_surfaces() {
    let sec = alnum(40, 10);
    assert!(
        surfaces(&format!("github_webhook_secret: {sec}"), &sec),
        "a lowercase github_webhook_secret with a colon separator must surface"
    );
}

#[test]
fn shopify_webhook_secret_hex_surfaces() {
    let sec = hex(48, 11);
    assert!(
        surfaces_under(
            &format!("SHOPIFY_WEBHOOK_SECRET={sec}"),
            "shopify-webhook-secret",
            &sec
        ),
        "a Shopify webhook HMAC secret (hex) must surface"
    );
}

// ── cross-file: multiple webhook secrets co-surface ───────────────────────────

#[test]
fn slack_and_discord_webhooks_cosurface() {
    let s = slack_url(12);
    let d = discord_url(13);
    let text = format!("slack: {s}\ndiscord: {d}\n");
    assert!(
        surfaces(&text, &s),
        "Slack webhook must surface alongside Discord"
    );
    assert!(
        surfaces(&text, &d),
        "Discord webhook must surface alongside Slack"
    );
}

#[test]
fn stripe_and_github_webhook_secrets_cosurface() {
    let stripe = format!("whsec_{}", alnum(40, 14));
    let gh = alnum(40, 15);
    let text = format!("STRIPE_WEBHOOK_SECRET={stripe}\nGITHUB_WEBHOOK_SECRET={gh}\n");
    assert!(
        surfaces(&text, &stripe),
        "Stripe secret must surface alongside GitHub"
    );
    assert!(
        surfaces(&text, &gh),
        "GitHub secret must surface alongside Stripe"
    );
}

// ── precision: wrong host / shape must NOT fire ───────────────────────────────

#[test]
fn slack_wrong_host_dot_io_does_not_fire() {
    // hooks.slack.IO is not Slack's webhook host (the regex pins hooks.slack.com).
    let url = format!(
        "https://hooks.slack.io/services/T{}/B{}/{}",
        alnum(9, 16),
        alnum(9, 17),
        alnum(24, 18)
    );
    assert!(
        !fires(&url, "slack-webhook-url"),
        "a hooks.slack.io URL must NOT fire the slack-webhook-url detector"
    );
}

#[test]
fn slack_short_secret_segment_does_not_fire() {
    // 20-char trailing segment (not the required 24) is not a Slack webhook secret,
    // and there is no `slack_webhook_url=` anchor for the looser fallback pattern.
    let url = format!(
        "https://hooks.slack.com/services/T{}/B{}/{}",
        alnum(9, 19),
        alnum(9, 20),
        alnum(20, 21)
    );
    assert!(
        !fires(&url, "slack-webhook-url"),
        "a Slack URL with a 20-char (not 24) secret must not fire"
    );
}

#[test]
fn discord_wrong_host_does_not_fire() {
    let url = format!(
        "https://example.com/api/webhooks/123456789012345678/{}",
        alnum(68, 22)
    );
    assert!(
        !fires(&url, "discord-webhook-credentials"),
        "a non-Discord host webhook URL must not fire the Discord detector"
    );
}

#[test]
fn stripe_whsec_below_min_length_does_not_fire() {
    let sec = format!("whsec_{}", alnum(20, 23)); // 20 < 32 minimum
    assert!(
        !fires(&sec, "stripe-webhook-signing-secret"),
        "a whsec_ value shorter than 32 chars must not fire"
    );
}

#[test]
fn shopify_webhook_secret_non_hex_does_not_fire() {
    // Shopify HMAC keys are hex; a non-hex value under the same anchor must not fire
    // the shopify-webhook-secret hex pattern.
    let sec = "ZZZZ_not_hex_value_ZZZZ_not_hex_value_ZZ";
    assert!(
        !fires(
            &format!("SHOPIFY_WEBHOOK_SECRET={sec}"),
            "shopify-webhook-secret"
        ),
        "a non-hex Shopify webhook value must not fire the hex pattern"
    );
}

#[test]
fn slack_host_prose_mention_without_url_does_not_fire() {
    let text = "Post alerts to your hooks.slack.com incoming webhook (see the Slack docs).\n";
    assert!(
        !fires(text, "slack-webhook-url"),
        "prose mentioning the host without a full webhook URL must not fire"
    );
}

#[test]
fn zapier_wrong_path_segment_does_not_fire() {
    // The Zapier host with a non-`catch` path is not an incoming-webhook URL.
    let url = "https://hooks.zapier.com/hooks/poll/123456789/abcDEF/";
    assert!(
        !fires(url, "zapier-webhook-url"),
        "a hooks.zapier.com URL outside /hooks/catch/ must not fire"
    );
}

#[test]
fn github_webhook_below_min_length_does_not_fire() {
    let sec = alnum(15, 24); // 15 < 20 minimum group length
    assert!(
        !fires(
            &format!("GITHUB_WEBHOOK_SECRET={sec}"),
            "github-webhook-secret"
        ),
        "a GitHub webhook secret shorter than 20 chars must not fire"
    );
}

// ── boundary + host-alias positives ───────────────────────────────────────────

#[test]
fn discordapp_com_host_alias_surfaces() {
    let url = format!(
        "https://discordapp.com/api/webhooks/123456789012345678/{}",
        alnum(68, 25)
    );
    assert!(
        surfaces_under(&url, "discord-webhook-credentials", &url),
        "the legacy discordapp.com host alias must also surface"
    );
}

#[test]
fn stripe_whsec_upper_length_boundary_surfaces() {
    let sec = format!("whsec_{}", alnum(64, 26)); // 64 = the documented upper bound
    assert!(
        surfaces_under(&sec, "stripe-webhook-signing-secret", &sec),
        "a 64-char whsec_ secret (upper boundary) must surface"
    );
}
