//! Slack token-family recall + precision lock (xoxb bot / xoxp user / xapp app).
//! These have strong `xox*-`/`xapp-` prefix literals (so, unlike telegram, the
//! URL form is not a gap), but multi-segment formats with precision-relevant
//! segment-length bounds and TWO overlapping patterns per bot/user token. This
//! pins that real tokens surface across both pattern variants and context forms,
//! and that segment-shape near-misses (wrong prefix, short final segment, letters
//! in the numeric id, non-hex user suffix) are rejected. Credential = whole match.

mod support;
use support::contracts::{make_chunk, scanner};

use keyhog_core::Chunk;
use keyhog_scanner::CompiledScanner;

/// Deterministic high-entropy string of length `n` over `charset` (seeded LCG).
fn gen(n: usize, seed: usize, charset: &[u8]) -> String {
    let m = charset.len() as u64;
    let mut s = (seed as u64)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0x51AC_4302);
    (0..n)
        .map(|_| {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            charset[((s >> 33) % m) as usize] as char
        })
        .collect()
}

fn digits(n: usize, seed: usize) -> String {
    gen(n, seed, b"0123456789")
}
fn alnum(n: usize, seed: usize) -> String {
    gen(
        n,
        seed,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    )
}
fn hex(n: usize, seed: usize) -> String {
    gen(n, seed, b"0123456789abcdef")
}

fn scan(text: &str) -> Vec<(String, String)> {
    let s: &CompiledScanner = &scanner();
    let chunk: Chunk = make_chunk(text, "source", "slack.env");
    s.clear_fragment_cache();
    s.scan(&chunk)
        .into_iter()
        .map(|m| (m.detector_id.to_string(), m.credential.to_string()))
        .collect()
}

fn surfaces_under(text: &str, detector: &str, token: &str) -> bool {
    scan(text)
        .iter()
        .any(|(id, cred)| id == detector && cred.contains(token))
}

fn surfaces_any(text: &str, token: &str) -> bool {
    scan(text).iter().any(|(_, cred)| cred.contains(token))
}

fn fires(text: &str, detector: &str) -> bool {
    scan(text).iter().any(|(id, _)| id == detector)
}

// token builders
fn xoxb_4seg(seed: usize) -> String {
    format!(
        "xoxb-{}-{}-{}",
        digits(12, seed),
        digits(12, seed + 1),
        alnum(28, seed + 2)
    )
}
fn xoxb_3seg(seed: usize) -> String {
    format!("xoxb-{}-{}", digits(12, seed), alnum(24, seed + 1))
}
fn xoxp_5seg(seed: usize) -> String {
    format!(
        "xoxp-{}-{}-{}-{}",
        digits(12, seed),
        digits(12, seed + 1),
        digits(12, seed + 2),
        hex(32, seed + 3)
    )
}
fn xoxp_4seg(seed: usize) -> String {
    format!(
        "xoxp-{}-{}-{}",
        digits(12, seed),
        digits(12, seed + 1),
        alnum(28, seed + 2)
    )
}
fn xapp(seed: usize) -> String {
    format!(
        "xapp-1-{}-{}-{}",
        gen(9, seed, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
        digits(10, seed + 1),
        hex(32, seed + 2)
    )
}

// ── positives: both pattern variants per token + context forms ────────────────

#[test]
fn slack_bot_token_4_segment_surfaces() {
    let t = xoxb_4seg(1);
    assert!(
        surfaces_under(&t, "slack-bot-token", &t),
        "xoxb 4-segment must surface"
    );
}

#[test]
fn slack_bot_token_3_segment_surfaces() {
    let t = xoxb_3seg(2);
    assert!(
        surfaces_under(&t, "slack-bot-token", &t),
        "xoxb 3-segment short form must surface"
    );
}

#[test]
fn slack_user_token_5_segment_hex_surfaces() {
    let t = xoxp_5seg(3);
    assert!(
        surfaces_under(&t, "slack-user-token", &t),
        "xoxp 5-segment hex form must surface"
    );
}

#[test]
fn slack_user_token_4_segment_surfaces() {
    let t = xoxp_4seg(4);
    assert!(
        surfaces_under(&t, "slack-user-token", &t),
        "xoxp 4-segment form must surface"
    );
}

#[test]
fn slack_app_token_surfaces() {
    let t = xapp(5);
    assert!(
        surfaces_under(&t, "slack-app-token", &t),
        "xapp app-level token must surface"
    );
}

#[test]
fn slack_bot_token_env_anchor_surfaces() {
    let t = xoxb_4seg(6);
    assert!(surfaces_under(
        &format!("SLACK_BOT_TOKEN={t}"),
        "slack-bot-token",
        &t
    ));
}

#[test]
fn slack_app_token_env_anchor_surfaces() {
    let t = xapp(7);
    assert!(surfaces_under(
        &format!("SLACK_APP_TOKEN={t}"),
        "slack-app-token",
        &t
    ));
}

#[test]
fn slack_bot_token_in_yaml_surfaces() {
    let t = xoxb_4seg(8);
    assert!(surfaces_any(&format!("slack:\n  bot_token: {t}\n"), &t));
}

#[test]
fn slack_user_token_in_json_surfaces() {
    let t = xoxp_5seg(9);
    assert!(surfaces_any(&format!("{{\"slack_token\":\"{t}\"}}"), &t));
}

#[test]
fn slack_bot_token_bare_prefix_surfaces() {
    // The xoxb- prefix literal alone triggers the prefilter (no other keyword).
    let t = xoxb_4seg(10);
    assert!(surfaces_under(&t, "slack-bot-token", &t));
}

// ── boundary positives: segment-length edges of the 4-segment bot pattern ─────

#[test]
fn slack_bot_token_24char_final_min_surfaces() {
    let t = format!(
        "xoxb-{}-{}-{}",
        digits(10, 11),
        digits(10, 12),
        alnum(24, 13)
    ); // final = 24 (min)
    assert!(surfaces_under(&t, "slack-bot-token", &t));
}

#[test]
fn slack_bot_token_32char_final_max_surfaces() {
    let t = format!(
        "xoxb-{}-{}-{}",
        digits(13, 14),
        digits(13, 15),
        alnum(32, 16)
    ); // final = 32 (max)
    assert!(surfaces_under(&t, "slack-bot-token", &t));
}

// ── precision: shape near-misses must not fire ────────────────────────────────

#[test]
fn slack_wrong_prefix_xoxz_does_not_fire() {
    let t = format!(
        "xoxz-{}-{}-{}",
        digits(12, 17),
        digits(12, 18),
        alnum(28, 19)
    );
    assert!(!fires(&t, "slack-bot-token") && !fires(&t, "slack-user-token"));
}

#[test]
fn slack_bot_prose_mention_does_not_fire() {
    // The literal `xoxb` keyword may trigger the prefilter, but with no token shape
    // present the regex must not produce a finding.
    assert!(!fires(
        "Set your xoxb bot token in the Slack admin console.",
        "slack-bot-token"
    ));
}

#[test]
fn slack_bot_letter_in_numeric_id_does_not_fire() {
    // The id segments are [0-9]{10,13}; a letter breaks the run below the minimum.
    let t = format!("xoxb-12a4567890-{}-{}", digits(12, 20), alnum(28, 21));
    assert!(!fires(&t, "slack-bot-token"));
}

#[test]
fn slack_bot_short_final_segment_does_not_fire() {
    // 23-char final is one below the 24 minimum of the 4-segment pattern, and the
    // middle `-` prevents the 3-segment pattern from rescuing it.
    let t = format!(
        "xoxb-{}-{}-{}",
        digits(12, 22),
        digits(12, 23),
        alnum(23, 24)
    );
    assert!(!fires(&t, "slack-bot-token"));
}

#[test]
fn slack_bot_truncated_segments_do_not_fire() {
    assert!(!fires("xoxb-12345-67890", "slack-bot-token"));
}

#[test]
fn slack_user_non_hex_5seg_suffix_does_not_fire() {
    // 5-segment user token requires an [a-f0-9]{32} suffix; a suffix containing
    // out-of-hex letters (and the leading `-` blocking the 4-seg fallback) must
    // not fire.
    let suffix = format!("ZZ{}", hex(30, 25)); // 32 chars but starts with non-hex Z
    let t = format!(
        "xoxp-{}-{}-{}-{}",
        digits(12, 26),
        digits(12, 27),
        digits(12, 28),
        suffix
    );
    assert!(!fires(&t, "slack-user-token"));
}

// ── cross: multiple slack tokens co-surface ───────────────────────────────────

#[test]
fn slack_bot_and_user_tokens_cosurface() {
    let b = xoxb_4seg(30);
    let u = xoxp_5seg(31);
    let text = format!("SLACK_BOT_TOKEN={b}\nSLACK_USER_TOKEN={u}\n");
    assert!(
        surfaces_under(&text, "slack-bot-token", &b),
        "bot token surfaces alongside user"
    );
    assert!(
        surfaces_under(&text, "slack-user-token", &u),
        "user token surfaces alongside bot"
    );
}

#[test]
fn slack_bot_and_app_tokens_cosurface() {
    let b = xoxb_3seg(32);
    let a = xapp(33);
    let text = format!("bot={b}\napp={a}\n");
    assert!(surfaces_under(&text, "slack-bot-token", &b));
    assert!(surfaces_under(&text, "slack-app-token", &a));
}
