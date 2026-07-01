//! Transactional-email vendor credential recall + precision lock: Mailchimp
//! (`<32hex>-us12` datacenter-suffixed key), Postmark (server-token UUID),
//! SparkPost (context-anchored 32-hex), and Mailgun (`key-`+32hex). These leak
//! via CI env, SDK config, and webhook headers and had only adversarial-level
//! coverage. None is checksum-gated or companion-gated. This pins each form
//! across context plus the precision floors (datacenter suffix, UUID shape,
//! hex length).

mod support;
use support::contracts::{make_chunk, scanner};

use keyhog_core::Chunk;
use keyhog_scanner::CompiledScanner;

fn gen(n: usize, seed: usize, charset: &[u8]) -> String {
    let m = charset.len() as u64;
    let mut s = (seed as u64)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0x3C6E_F35F);
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
fn digits(n: usize, seed: usize) -> String {
    gen(n, seed, b"0123456789")
}
fn uuid(seed: usize) -> String {
    format!(
        "{}-{}-{}-{}-{}",
        hex(8, seed),
        hex(4, seed + 1),
        hex(4, seed + 2),
        hex(4, seed + 3),
        hex(12, seed + 4)
    )
}

fn scan(text: &str) -> Vec<(String, String)> {
    let s: &CompiledScanner = &scanner();
    let chunk: Chunk = make_chunk(text, "source", "email.env");
    s.clear_fragment_cache();
    s.scan(&chunk)
        .into_iter()
        .map(|m| (m.detector_id.to_string(), m.credential.to_string()))
        .collect()
}
fn surfaces_under(text: &str, detector: &str, needle: &str) -> bool {
    scan(text).iter().any(|(id, cred)| id == detector && cred.contains(needle))
}
fn surfaces_any(text: &str, needle: &str) -> bool {
    scan(text).iter().any(|(_, cred)| cred.contains(needle))
}
fn fires(text: &str, detector: &str) -> bool {
    scan(text).iter().any(|(id, _)| id == detector)
}

// ── Mailchimp: <32hex>-{us|eu|uk}<1-2 digits> ─────────────────────────────────
//
// The detector deliberately carries `min_confidence = 0.3` (mailchimp-api-key.toml
// lines 11-14): the 32-hex body scores below the 0.40 global entropy floor, so a
// datacenter-suffixed hex is only surfaced when a mailchimp/api-key *context anchor*
// lifts it over the floor. The bare `<32hex>-us12` with no anchor is intentionally
// withheld (a lone hyphenated hex blob is an FP magnet); its value still surfaces
// under generic detectors, just not under the mailchimp label. These tests lock
// that true contract: context forms surface as mailchimp, bare-no-context does not.

#[test]
fn mailchimp_env_anchor_us_surfaces() {
    let k = format!("{}-us{}", hex(32, 1), digits(2, 2));
    assert!(
        surfaces_under(&format!("MAILCHIMP_API_KEY={k}"), "mailchimp-api-key", &k),
        "anchored -us key must surface"
    );
}

#[test]
fn mailchimp_env_anchor_eu_surfaces() {
    let k = format!("{}-eu{}", hex(32, 3), digits(2, 4));
    assert!(surfaces_under(&format!("MAILCHIMP_API_KEY={k}"), "mailchimp-api-key", &k));
}

#[test]
fn mailchimp_env_anchor_uk_surfaces() {
    let k = format!("{}-uk{}", hex(32, 5), digits(2, 6));
    assert!(surfaces_under(&format!("MAILCHIMP_API_KEY={k}"), "mailchimp-api-key", &k));
}

#[test]
fn mailchimp_inline_lowercase_single_digit_dc_surfaces() {
    // Pattern 1 tolerates `mailchimp api_key: "..."` and a single-digit datacenter.
    let k = format!("{}-us{}", hex(32, 7), digits(1, 8));
    assert!(surfaces_under(
        &format!("mailchimp api_key: \"{k}\""),
        "mailchimp-api-key",
        &k
    ));
}

#[test]
fn mailchimp_json_context_eu_surfaces() {
    let k = format!("{}-eu{}", hex(32, 9), digits(2, 10));
    assert!(surfaces_under(
        &format!("{{\"mailchimp_api_key\": \"{k}\"}}"),
        "mailchimp-api-key",
        &k
    ));
}

#[test]
fn mailchimp_bare_datacenter_below_precision_floor() {
    // The documented precision decision: a datacenter-suffixed hex with NO context
    // anchor scores below min_confidence=0.3 and is withheld from the mailchimp
    // label (contrast mailgun's 0.12 floor, where the bare `key-` form surfaces).
    let k = format!("{}-us{}", hex(32, 11), digits(2, 12));
    assert!(
        !fires(&k, "mailchimp-api-key"),
        "bare no-context datacenter hex must stay below the mailchimp floor"
    );
}

#[test]
fn mailchimp_unknown_datacenter_does_not_fire() {
    // `-au` is not one of us/eu/uk, and there is no matching keyword to trigger.
    let k = format!("MAILCHIMP_API_KEY={}-au{}", hex(32, 13), digits(2, 14));
    assert!(!fires(&k, "mailchimp-api-key"));
}

#[test]
fn mailchimp_context_31_hex_does_not_fire() {
    // 31 < the required 32-hex body: even with the anchor, pattern 1 cannot match.
    let k = format!("MAILCHIMP_API_KEY={}-us{}", hex(31, 15), digits(2, 16));
    assert!(!fires(&k, "mailchimp-api-key"));
}

// ── Postmark: server-token UUID ───────────────────────────────────────────────

#[test]
fn postmark_server_token_env_surfaces() {
    let u = uuid(15);
    assert!(surfaces_under(&format!("POSTMARK_SERVER_TOKEN={u}"), "postmark-server-token", &u));
}

#[test]
fn postmark_header_form_surfaces() {
    let u = uuid(16);
    assert!(surfaces_under(&format!("X-Postmark-Server-Token: {u}"), "postmark-server-token", &u));
}

#[test]
fn postmark_lowercase_server_token_anchor_surfaces() {
    let u = uuid(17);
    assert!(surfaces_under(&format!("postmark_server_token={u}"), "postmark-server-token", &u));
}

#[test]
fn postmark_non_uuid_value_does_not_fire() {
    // A bare 32-hex (no UUID hyphen grouping) is not the server-token shape.
    let bad = hex(32, 18);
    assert!(!fires(&format!("POSTMARK_SERVER_TOKEN={bad}"), "postmark-server-token"));
}

#[test]
fn postmark_uppercase_uuid_surfaces() {
    // Detector regexes compile case-insensitively, so an uppercase UUID matches.
    let u = uuid(19).to_uppercase();
    assert!(surfaces_under(&format!("POSTMARK_SERVER_TOKEN={u}"), "postmark-server-token", &u));
}

// ── SparkPost: context-anchored 32-hex ────────────────────────────────────────

#[test]
fn sparkpost_api_key_env_surfaces() {
    let h = hex(32, 20);
    assert!(surfaces_under(&format!("SPARKPOST_API_KEY={h}"), "sparkpost-api-key", &h));
}

#[test]
fn sparkpost_api_key_lowercase_anchor_surfaces() {
    let h = hex(32, 21);
    assert!(surfaces_under(&format!("sparkpost_api_key={h}"), "sparkpost-api-key", &h));
}

#[test]
fn sparkpost_api_key_in_yaml_surfaces() {
    let h = hex(32, 22);
    assert!(surfaces_any(&format!("sparkpost:\n  api_key: {h}\n"), &h));
}

#[test]
fn sparkpost_31_hex_does_not_fire() {
    let h = hex(31, 23); // 31 < 32
    assert!(!fires(&format!("SPARKPOST_API_KEY={h}"), "sparkpost-api-key"));
}

// ── Mailgun: key- + 32 hex ────────────────────────────────────────────────────

#[test]
fn mailgun_key_prefix_surfaces() {
    let k = format!("key-{}", hex(32, 24));
    assert!(surfaces_under(&k, "mailgun-api-key", &k), "mailgun key- token must surface");
}

#[test]
fn mailgun_key_env_anchor_surfaces() {
    let k = format!("key-{}", hex(32, 25));
    assert!(surfaces_under(&format!("MAILGUN_API_KEY={k}"), "mailgun-api-key", &k));
}

#[test]
fn mailgun_key_31_hex_does_not_fire() {
    let k = format!("key-{}", hex(31, 26)); // 31 < 32
    assert!(!fires(&k, "mailgun-api-key"));
}

// ── cross ─────────────────────────────────────────────────────────────────────

#[test]
fn multiple_email_vendor_keys_cosurface() {
    let mc = format!("{}-us{}", hex(32, 27), digits(2, 28));
    let pm = uuid(29);
    let mg = format!("key-{}", hex(32, 30));
    let text = format!("MAILCHIMP_API_KEY={mc}\nPOSTMARK_SERVER_TOKEN={pm}\nMAILGUN_API_KEY={mg}\n");
    assert!(surfaces_under(&text, "mailchimp-api-key", &mc));
    assert!(surfaces_under(&text, "postmark-server-token", &pm));
    assert!(surfaces_under(&text, "mailgun-api-key", &mg));
}
