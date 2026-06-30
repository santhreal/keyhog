//! Telegram bot-token recall + precision lock. The format is a distinctive
//! `{8-10 digit id}:{35-char [A-Za-z0-9_-] token}` (regex
//! `[0-9]{8,10}:[A-Za-z0-9_-]{35}`), keyword-gated on
//! TELEGRAM_BOT_TOKEN / telegram_token / api.telegram.org / bot. The numeric:alnum
//! shape collides with `timestamp:value` and `id:hash`, so this pins that real
//! tokens surface across their context forms (env, API URL, yaml/json/python) and
//! that the format guards (id digit-count 8..=10, exactly-35-char token, charset)
//! reject near-misses. The credential is the whole `id:token` match (no group).
//!
//! Writing this lock surfaced a real recall gap: the canonical
//! `https://api.telegram.org/bot<token>/getMe` URL form was missed entirely (no
//! assignment anchor, and the short `bot` keyword is not an effective trigger).
//! Fixed by adding the precise, zero-FP `api.telegram.org` host keyword to the
//! detector.

mod support;
use support::contracts::{make_chunk, scanner};

use keyhog_core::Chunk;
use keyhog_scanner::CompiledScanner;

/// Deterministic high-entropy string of length `n` over `charset` (seeded LCG).
fn gen(n: usize, seed: usize, charset: &[u8]) -> String {
    let m = charset.len() as u64;
    let mut s = (seed as u64)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0xA17F_42C9);
    (0..n)
        .map(|_| {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            charset[((s >> 33) % m) as usize] as char
        })
        .collect()
}

/// A 35-char Telegram token segment over the full `[A-Za-z0-9_-]` charset.
fn token35(seed: usize) -> String {
    gen(35, seed, b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
}

fn scan(text: &str) -> Vec<(String, String)> {
    let s: &CompiledScanner = &scanner();
    let chunk: Chunk = make_chunk(text, "source", "bot.env");
    s.clear_fragment_cache();
    s.scan(&chunk)
        .into_iter()
        .map(|m| (m.detector_id.to_string(), m.credential.to_string()))
        .collect()
}

/// The telegram-bot-token detector surfaced exactly `token`.
fn surfaces(text: &str, token: &str) -> bool {
    scan(text)
        .iter()
        .any(|(id, cred)| id == "telegram-bot-token" && cred.contains(token))
}

/// Some detector surfaced `token` (recall, regardless of attribution).
fn surfaces_any(text: &str, token: &str) -> bool {
    scan(text).iter().any(|(_, cred)| cred.contains(token))
}

/// The telegram-bot-token detector did NOT fire on `text`.
fn does_not_fire(text: &str) -> bool {
    !scan(text).iter().any(|(id, _)| id == "telegram-bot-token")
}

// ── positives: real tokens surface across their context forms ─────────────────

#[test]
fn telegram_bot_token_env_assignment_surfaces() {
    let tok = format!("123456789:{}", token35(1));
    assert!(surfaces(&format!("TELEGRAM_BOT_TOKEN={tok}"), &tok));
}

#[test]
fn telegram_token_in_api_url_surfaces() {
    // The api.telegram.org/bot<token> form is the CANONICAL appearance of a bot
    // token in code (the getMe/sendMessage call). It carries no assignment anchor,
    // and the short `bot` keyword is not an effective prefilter trigger, so this
    // form was missed entirely until `api.telegram.org` was added as a keyword.
    // Asserting telegram-bot-token specifically fires proves that fix.
    let tok = format!("987654321:{}", token35(2));
    assert!(surfaces(&format!("https://api.telegram.org/bot{tok}/getMe"), &tok));
}

#[test]
fn telegram_bot_token_lowercase_anchor_surfaces() {
    let tok = format!("246813579:{}", token35(3));
    assert!(surfaces(&format!("telegram_bot_token = \"{tok}\""), &tok));
}

#[test]
fn telegram_uppercase_telegram_token_anchor_surfaces() {
    let tok = format!("135792468:{}", token35(4));
    assert!(surfaces(&format!("TELEGRAM_TOKEN={tok}"), &tok));
}

// The `bot_token = ...` / yaml `bot_token:` forms have an assignment anchor but no
// strong telegram keyword, so they surface via the generic assignment path rather
// than telegram-bot-token attribution. Recall is preserved either way, which is
// what these locks assert (surfaces_any).

#[test]
fn telegram_token_python_bot_token_var_surfaces() {
    let tok = format!("112233445:{}", token35(5));
    assert!(surfaces_any(&format!("bot_token = '{tok}'"), &tok));
}

#[test]
fn telegram_token_yaml_field_surfaces() {
    let tok = format!("556677889:{}", token35(6));
    assert!(surfaces_any(&format!("telegram:\n  bot_token: {tok}\n"), &tok));
}

#[test]
fn telegram_token_json_field_surfaces() {
    let tok = format!("778899001:{}", token35(7));
    assert!(surfaces(&format!("{{\"telegram_bot_token\":\"{tok}\"}}"), &tok));
}

#[test]
fn telegram_token_dotenv_export_surfaces() {
    let tok = format!("314159265:{}", token35(8));
    assert!(surfaces(&format!("export TELEGRAM_BOT_TOKEN={tok}"), &tok));
}

// ── boundary positives: id digit-count and token charset edges ────────────────

#[test]
fn telegram_token_8_digit_id_surfaces() {
    let tok = format!("80000001:{}", token35(9)); // 8-digit id (minimum)
    assert!(surfaces(&format!("TELEGRAM_BOT_TOKEN={tok}"), &tok));
}

#[test]
fn telegram_token_10_digit_id_surfaces() {
    let tok = format!("1000000001:{}", token35(10)); // 10-digit id (maximum)
    assert!(surfaces(&format!("TELEGRAM_BOT_TOKEN={tok}"), &tok));
}

#[test]
fn telegram_token_leading_zero_id_surfaces() {
    let tok = format!("012345678:{}", token35(11)); // leading zero is still [0-9]{8,10}
    assert!(surfaces(&format!("TELEGRAM_BOT_TOKEN={tok}"), &tok));
}

#[test]
fn telegram_token_with_underscore_and_dash_surfaces() {
    // Token segment explicitly containing the `_` and `-` charset members,
    // generated to guarantee exactly 35 chars.
    let seg = format!("A_{}-B", gen(31, 12, b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"));
    assert_eq!(seg.len(), 35, "fixture token must be 35 chars");
    let tok = format!("246801357:{seg}");
    assert!(surfaces(&format!("TELEGRAM_BOT_TOKEN={tok}"), &tok));
}

#[test]
fn telegram_token_9_digit_id_surfaces() {
    let tok = format!("900000009:{}", token35(112)); // 9-digit id (mid-range)
    assert!(surfaces(&format!("TELEGRAM_BOT_TOKEN={tok}"), &tok));
}

// ── precision: format near-misses must NOT fire ───────────────────────────────

#[test]
fn telegram_seven_digit_id_does_not_fire() {
    // 7-digit id is below the 8..=10 range.
    let tok = format!("1234567:{}", token35(13));
    assert!(does_not_fire(&format!("TELEGRAM_BOT_TOKEN={tok}")));
}

#[test]
fn telegram_token_no_colon_separator_does_not_fire() {
    // Without the `:` separator the digits and token form one run — no match.
    // (Note: an 11+ digit id IS matched via its 10-digit suffix because the
    // regex is unanchored, so the genuine negative is the missing separator.)
    let tok = format!("123456789X{}", token35(14));
    assert!(does_not_fire(&format!("TELEGRAM_BOT_TOKEN={tok}")));
}

#[test]
fn telegram_token_segment_34_chars_does_not_fire() {
    // 34-char token segment is one short of the required 35.
    let tok = format!("123456789:{}", gen(34, 15, b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"));
    assert!(does_not_fire(&format!("TELEGRAM_BOT_TOKEN={tok}")));
}

#[test]
fn telegram_token_with_letter_in_id_does_not_fire() {
    // The id segment must be pure digits.
    let tok = format!("12345a789:{}", token35(16));
    assert!(does_not_fire(&format!("TELEGRAM_BOT_TOKEN={tok}")));
}

#[test]
fn telegram_token_broken_by_space_does_not_fire() {
    // A space inside the token breaks the 35-char run.
    let token = token35(17);
    let broken = format!("{} {}", &token[..17], &token[18..]);
    assert!(does_not_fire(&format!("TELEGRAM_BOT_TOKEN=123456789:{broken}")));
}

#[test]
fn telegram_token_broken_by_dot_does_not_fire() {
    // `.` is not in [A-Za-z0-9_-]; placed early it prevents any 35-char run.
    assert!(does_not_fire("TELEGRAM_BOT_TOKEN=123456789:ab.cdefghijklmnopqrstuvwxyz0123456"));
}

// ── cross-cutting ─────────────────────────────────────────────────────────────

#[test]
fn two_telegram_tokens_both_surface() {
    // Two distinct bot tokens in one file must both surface (multi-match), not be
    // collapsed to one.
    let a = format!("123456789:{}", token35(18));
    let b = format!("987654321:{}", token35(19));
    let text = format!("PROD_TELEGRAM_BOT_TOKEN={a}\nDEV_TELEGRAM_BOT_TOKEN={b}\n");
    assert!(surfaces(&text, &a), "first telegram token must surface");
    assert!(surfaces(&text, &b), "second telegram token must surface");
}
