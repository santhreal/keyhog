//! Chat/messaging vendor credential recall + precision lock: Discord (bot token
//! 3-part base64 snowflake form + webhook URL), Telegram (`<id>:<token>` bot
//! token), Pusher (app key 20-hex / app secret 32-hex), and Pushover (30-char
//! token). Slack is deliberately excluded here: its `xox*`/`xapp-` tokens are
//! checksum-validated, so a fabricated fixture is silently dropped and must be
//! covered with real-checksum vectors elsewhere. This unit pins each non-Slack
//! form plus its length/prefix boundaries; none of these is checksum-gated.

mod support;
use support::contracts::{make_chunk, scanner};

use keyhog_core::Chunk;
use keyhog_scanner::CompiledScanner;

fn gen(n: usize, seed: usize, charset: &[u8]) -> String {
    let m = charset.len() as u64;
    let mut s = (seed as u64)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0x2B9A_7F51);
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
fn lcnum(n: usize, seed: usize) -> String {
    gen(n, seed, b"abcdefghijklmnopqrstuvwxyz0123456789")
}
fn digits(n: usize, seed: usize) -> String {
    gen(n, seed, b"0123456789")
}

/// Discord bot token: `<prefix+20-25>.<6-8>.<27-38>` in base64url.
fn discord_token(prefix: &str, mid_len: usize, tail_len: usize, seed: usize) -> String {
    format!(
        "{}{}.{}.{}",
        prefix,
        alnum(22, seed),
        alnum(mid_len, seed + 1),
        alnum(tail_len, seed + 2)
    )
}

fn scan(text: &str) -> Vec<(String, String)> {
    let s: &CompiledScanner = &scanner();
    let chunk: Chunk = make_chunk(text, "source", "chat.env");
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

// ── Discord bot token: 3-part base64 snowflake form ──────────────────────────

#[test]
fn discord_bot_token_low_prefix_surfaces() {
    // `MTA` is a base64 snowflake prefix (a user id starting "10..").
    let t = discord_token("MTA", 6, 30, 1);
    assert!(
        surfaces_under(&t, "discord-bot-token", &t),
        "MTA-prefixed token must surface"
    );
}

#[test]
fn discord_bot_token_high_prefix_surfaces() {
    // `NzA` covers the 70-99 snowflake prefix range (pattern 2).
    let t = discord_token("NzA", 6, 30, 4);
    assert!(
        surfaces_under(&t, "discord-bot-token", &t),
        "NzA-prefixed token must surface"
    );
}

#[test]
fn discord_bot_token_min_tail_surfaces() {
    let t = discord_token("MTU", 6, 27, 7); // 27 = minimum tail
    assert!(surfaces_under(&t, "discord-bot-token", &t));
}

#[test]
fn discord_bot_token_max_tail_surfaces() {
    let t = discord_token("MjA", 8, 38, 10); // 38 = maximum tail, 8 = max mid
    assert!(surfaces_under(&t, "discord-bot-token", &t));
}

#[test]
fn discord_bot_token_synthetic_form_needs_discord_literal_surfaces() {
    // The non-snowflake shape requires an in-window `discord` literal.
    let t = format!("{}.{}.{}", alnum(25, 13), alnum(7, 14), alnum(30, 15));
    assert!(surfaces_under(
        &format!("discord_token={t}"),
        "discord-bot-token",
        &t
    ));
}

#[test]
fn discord_unlisted_prefix_without_literal_does_not_fire() {
    // No snowflake prefix AND no `discord` literal: neither pattern can trigger.
    let t = discord_token("ZZZ", 6, 30, 16);
    assert!(!fires(&t, "discord-bot-token"));
}

// ── Discord webhook URL ──────────────────────────────────────────────────────

#[test]
fn discord_webhook_url_surfaces() {
    let u = format!(
        "https://discord.com/api/webhooks/{}/{}",
        digits(18, 17),
        alnum(64, 18)
    );
    assert!(surfaces_under(&u, "discord-webhook-credentials", &u));
}

#[test]
fn discord_webhook_context_anchor_surfaces() {
    let u = format!(
        "https://discordapp.com/api/webhooks/{}/{}",
        digits(19, 19),
        alnum(68, 20)
    );
    assert!(surfaces_under(
        &format!("DISCORD_WEBHOOK_URL={u}"),
        "discord-webhook-credentials",
        &u
    ));
}

// ── Telegram bot token: <id>:<35 token> ──────────────────────────────────────

#[test]
fn telegram_bot_token_surfaces() {
    let t = format!("{}:{}", digits(9, 21), alnum(35, 22));
    assert!(surfaces_under(
        &format!("TELEGRAM_BOT_TOKEN={t}"),
        "telegram-bot-token",
        &t
    ));
}

#[test]
fn telegram_lowercase_anchor_surfaces() {
    let t = format!("{}:{}", digits(10, 23), alnum(35, 24));
    assert!(surfaces_under(
        &format!("telegram_bot_token={t}"),
        "telegram-bot-token",
        &t
    ));
}

#[test]
fn telegram_8_digit_id_surfaces() {
    let t = format!("{}:{}", digits(8, 25), alnum(35, 26)); // 8 = minimum id
    assert!(surfaces_under(
        &format!("TELEGRAM_TOKEN={t}"),
        "telegram-bot-token",
        &t
    ));
}

#[test]
fn telegram_34_char_token_does_not_fire() {
    let t = format!("{}:{}", digits(9, 27), alnum(34, 28)); // 34 < the required 35
    assert!(!fires(
        &format!("TELEGRAM_BOT_TOKEN={t}"),
        "telegram-bot-token"
    ));
}

// ── Pusher: app key 20-hex / app secret 32-hex ───────────────────────────────

#[test]
fn pusher_app_key_surfaces() {
    let k = hex(20, 29);
    assert!(surfaces_under(
        &format!("PUSHER_APP_KEY={k}"),
        "pusher-app-key",
        &k
    ));
}

#[test]
fn pusher_app_secret_is_detected() {
    // The 32-hex app SECRET is matched by the pusher detector's secret pattern,
    // but a bare 32-hex under a `SECRET=` anchor is also a generic-secret shape,
    // so value-dedup may keep a generic label instead of `pusher-app-key`. The
    // recall contract is that the secret is detected; the vendor-specific label
    // lock lives on the 20-hex app KEY form (`pusher_app_key_surfaces`), whose
    // shape does not collide with the generic secret detectors.
    let k = hex(32, 30);
    let got = scan(&format!("PUSHER_APP_SECRET={k}"));
    assert!(
        got.iter().any(|(_, cred)| cred.contains(&k)),
        "pusher app secret (32-hex) must be detected; scan returned {got:?}"
    );
}

#[test]
fn pusher_lowercase_anchor_surfaces() {
    let k = hex(20, 31);
    assert!(surfaces_under(
        &format!("pusher_app_key={k}"),
        "pusher-app-key",
        &k
    ));
}

#[test]
fn pusher_19_hex_key_does_not_fire() {
    let k = hex(19, 32); // 19 < the required 20
    assert!(!fires(&format!("PUSHER_APP_KEY={k}"), "pusher-app-key"));
}

// ── Pushover: 30-char [a-z0-9] token ─────────────────────────────────────────

#[test]
fn pushover_token_surfaces() {
    let k = lcnum(30, 33);
    assert!(surfaces_under(
        &format!("PUSHOVER={k}"),
        "pushover-api-token",
        &k
    ));
}

#[test]
fn pushover_colon_form_surfaces() {
    let k = lcnum(30, 34);
    assert!(surfaces_under(
        &format!("PUSHOVER: {k}"),
        "pushover-api-token",
        &k
    ));
}

#[test]
fn pushover_29_char_token_does_not_fire() {
    let k = lcnum(29, 35); // 29 < the required 30
    assert!(!fires(&format!("PUSHOVER={k}"), "pushover-api-token"));
}

// ── cross: several messaging tokens co-surface ───────────────────────────────

#[test]
fn multiple_messaging_tokens_cosurface() {
    let tg = format!("{}:{}", digits(9, 36), alnum(35, 37));
    let pu = hex(32, 38);
    let po = lcnum(30, 39);
    let text = format!("TELEGRAM_BOT_TOKEN={tg}\nPUSHER_APP_SECRET={pu}\nPUSHOVER={po}\n");
    let got = scan(&text);
    assert!(surfaces_under(&text, "telegram-bot-token", &tg));
    // The 32-hex pusher secret can carry a generic-secret label after dedup (see
    // `pusher_app_secret_is_detected`); assert it is detected, not its label.
    assert!(
        got.iter().any(|(_, cred)| cred.contains(&pu)),
        "pusher secret must be detected; got {got:?}"
    );
    assert!(surfaces_under(&text, "pushover-api-token", &po));
}

#[test]
fn discord_bot_and_webhook_cosurface() {
    let bot = discord_token("MTk", 6, 32, 40);
    let hook = format!(
        "https://discord.com/api/webhooks/{}/{}",
        digits(18, 41),
        alnum(64, 42)
    );
    let text = format!("DISCORD_BOT_TOKEN={bot}\nDISCORD_WEBHOOK_URL={hook}\n");
    assert!(surfaces_under(&text, "discord-bot-token", &bot));
    assert!(surfaces_under(&text, "discord-webhook-credentials", &hook));
}
