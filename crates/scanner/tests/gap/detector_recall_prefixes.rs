//! Recall coverage for prefix-anchored detectors.
//!
//! For each prefix-anchored detector family (aws `AKIA`, gcp `AIza`, slack
//! `xox*`, github `gh[pousr]_`, stripe `sk_live`, sendgrid `SG.`, twilio `SK`,
//! npm `npm_`, openai `sk-proj`/legacy, gitlab `glpat-`/`glrt-`, ...) this
//! module plants a *valid-shape / valid-checksum* token in a keyword context
//! and asserts the **right** detector fires with the planted credential
//! surfaced.
//!
//! Every expected value is derived from the real source under
//! `crates/scanner/src` and `detectors/*.toml`:
//!
//!   - The checksum DROP policy lives in `engine/process.rs:166` — a `ghp_` /
//!     `npm_` token whose embedded CRC32 does NOT match its body is dropped
//!     before scoring (`validate_checksum(..) == Invalid → return`). So a
//!     github-classic / npm recall test MUST mint a token whose trailing
//!     6-char base62 equals `base62(crc32(body), 6)`. We mint those fixtures
//!     through `keyhog_scanner::testing::checksum`, which calls the production
//!     checksum owner instead of copying the algorithm here.
//!   - Detector ids come straight from the `id = "..."` field of each TOML
//!     (e.g. `npm-token.toml` declares `id = "npm-access-token"`,
//!     `github-pat.toml` declares `id = "github-pat-fine-grained"`).
//!   - Token shapes come from the `regex = '...'` field of each TOML.
//!
//! The scanner is built exactly like the production adversarial oracle
//! (`tests/adversarial/oracle_support.rs`): `min_confidence = 0.0`,
//! `unicode_normalization = true`. The 0.0 floor isolates *recall* — "did the
//! right detector see this token" — from the separate confidence-floor gate.
//! It does NOT bypass the checksum DROP (that returns before scoring), so a
//! checksum-invalid github/npm token still vanishes here, which is what the
//! negative-twin tests assert.

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::testing::checksum::{
    base62_encode_u32, github_classic_format_with_checksum, github_classic_pat_with_checksum,
    github_fine_grained_pat_with_checksum, npm_token_with_checksum, standard_crc32,
};
use keyhog_scanner::CompiledScanner;
use std::sync::OnceLock;

// ── Scanner harness (mirrors tests/adversarial/oracle_support.rs) ────────────

use crate::support::paths::detector_dir;
fn scanner() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
        let mut config = keyhog_scanner::ScannerConfig::default();
        config.unicode_normalization = true;
        // Isolate recall from the confidence-floor gate. Does NOT bypass the
        // pre-scoring checksum DROP in engine/process.rs.
        config.min_confidence = 0.0;
        CompiledScanner::compile(detectors)
            .expect("compile scanner")
            .with_config(config)
    })
}

fn scan(text: &str, path: &str) -> Vec<RawMatch> {
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "recall".into(),
            path: Some(path.into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    scanner().clear_fragment_cache();
    scanner().scan(&chunk)
}

/// All matches attributed to `detector_id`.
fn hits<'a>(matches: &'a [RawMatch], detector_id: &str) -> Vec<&'a RawMatch> {
    matches
        .iter()
        .filter(|m| m.detector_id.as_ref() == detector_id)
        .collect()
}

/// Assert `detector_id` fired AND surfaced a credential that contains
/// `credential` (substring: a detector may legitimately capture surrounding
/// structure — same philosophy as the contract runner's containment check).
fn assert_fires(detector_id: &str, text: &str, credential: &str) {
    let matches = scan(text, &format!("{detector_id}-recall.env"));
    let h = hits(&matches, detector_id);
    assert!(
        !h.is_empty(),
        "{detector_id} must FIRE on its prefix-anchored recall fixture; \
         credential={credential:?}; all detectors that fired = {:?}",
        matches
            .iter()
            .map(|m| m.detector_id.as_ref())
            .collect::<Vec<_>>()
    );
    assert!(
        h.iter().any(|m| m.credential.as_ref().contains(credential)),
        "{detector_id} fired but did not surface the planted credential {credential:?}; \
         credentials surfaced under this id = {:?}",
        h.iter().map(|m| m.credential.as_ref()).collect::<Vec<_>>()
    );
}

/// Assert `detector_id` did NOT fire (negative twin / checksum-drop).
fn assert_silent(detector_id: &str, text: &str) {
    let matches = scan(text, &format!("{detector_id}-near-miss.env"));
    let h = hits(&matches, detector_id);
    assert!(
        h.is_empty(),
        "{detector_id} must STAY SILENT on near-miss; fired with {:?}",
        h.iter().map(|m| m.credential.as_ref()).collect::<Vec<_>>()
    );
}

// Token-body alphabet for deterministic fuzz bodies. Checksum construction
// itself is owned by `keyhog_scanner::testing::checksum`.
const TOKEN_ALNUM: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// `<prefix>` + `body30` + 6-char base62 CRC of `body30`. Used for
/// github-classic (`ghp_`) and npm (`npm_`): both are
/// `<prefix>` + 30 entropy + 6 checksum = 36 payload chars.
fn mint_crc_token(prefix: &str, body30: &str) -> String {
    assert_eq!(body30.len(), 30, "github/npm body is exactly 30 chars");
    match prefix {
        "ghp_" => github_classic_pat_with_checksum(body30),
        // gho_/ghu_/ghs_/ghr_ share the classic body + CRC (prefix-independent).
        "gho_" | "ghu_" | "ghs_" | "ghr_" => github_classic_format_with_checksum(prefix, body30),
        "npm_" => npm_token_with_checksum(body30),
        other => panic!("unsupported checksum fixture prefix: {other}"),
    }
}

/// github fine-grained: `github_pat_` + 22 + `_` + 59. The validator
/// (`GithubFineGrainedPatValidator`) accepts when the CRC of `right[..53]`
/// equals `right[53..]`. We mint the 59-char right segment so it self-validates.
fn mint_github_fine_grained(left22: &str, right_body53: &str) -> String {
    github_fine_grained_pat_with_checksum(left22, right_body53)
}

// ── Checksum fixture builder self-checks ────────────────────────────────────

#[test]
fn crc32_of_empty_is_zero() {
    // CRC32 of the empty input is the canonical 0x00000000.
    assert_eq!(standard_crc32(b""), 0x0000_0000);
}

#[test]
fn crc32_known_vector_check() {
    // Standard CRC-32/ISO-HDLC check value: CRC32("123456789") == 0xCBF43926.
    assert_eq!(standard_crc32(b"123456789"), 0xCBF4_3926);
    // "The quick brown fox jumps over the lazy dog" == 0x414FA339.
    assert_eq!(
        standard_crc32(b"The quick brown fox jumps over the lazy dog"),
        0x414F_A339
    );
}

#[test]
fn base62_encode_pads_and_radix_are_exact() {
    // 0 → all-zero, width-padded.
    assert_eq!(base62_encode_u32(0, 6), "000000");
    // 1 → "000001"; 61 → "00000z" (last digit of the alphabet).
    assert_eq!(base62_encode_u32(1, 6), "000001");
    assert_eq!(base62_encode_u32(61, 6), "00000z");
    // 62 → "000010" (one carry).
    assert_eq!(base62_encode_u32(62, 6), "000010");
    // u32::MAX in base62 fits in 6 chars and is non-padded at the top.
    let max = base62_encode_u32(u32::MAX, 6);
    assert_eq!(max.len(), 6);
}

#[test]
fn minted_github_token_self_validates_against_checksum_module() {
    // The whole point of mint_crc_token: the public `validate_checksum`
    // (engine policy) must call the result `NotApplicable`-free and Valid.
    let tok = mint_crc_token("ghp_", "AbCdEfGhIjKlMnOpQrStUvWxYz0123");
    // checksum_adjusted_confidence returns Some(>=0.9) for Valid, None for Invalid.
    let adjusted = keyhog_scanner::checksum::checksum_adjusted_confidence(0.10, &tok);
    assert_eq!(
        adjusted,
        Some(keyhog_scanner::checksum::CHECKSUM_VALID_FLOOR),
        "minted ghp_ token must be Valid (floored to 0.9), got {adjusted:?} for {tok:?}"
    );
}

#[test]
fn minted_npm_token_self_validates_against_checksum_module() {
    let tok = mint_crc_token("npm_", "ZyXwVuTsRqPoNmLkJiHgFeDcBa9876");
    let adjusted = keyhog_scanner::checksum::checksum_adjusted_confidence(0.10, &tok);
    assert_eq!(
        adjusted,
        Some(keyhog_scanner::checksum::CHECKSUM_VALID_FLOOR),
        "minted npm_ token must be Valid (floored to 0.9), got {adjusted:?} for {tok:?}"
    );
}

#[test]
fn minted_github_fine_grained_self_validates() {
    let tok = mint_github_fine_grained(
        "Ab1Cd2Ef3Gh4Ij5Kl6Mn7O",
        "pQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz012345",
    );
    let adjusted = keyhog_scanner::checksum::checksum_adjusted_confidence(0.10, &tok);
    assert_eq!(
        adjusted,
        Some(keyhog_scanner::checksum::CHECKSUM_VALID_FLOOR),
        "minted github_pat_ token must be Valid, got {adjusted:?} for {tok:?}"
    );
}

// ── Property-style loop: CRC tokens round-trip Valid for many bodies ─────────

#[test]
fn proptest_minted_ghp_tokens_are_always_valid() {
    // Deterministic pseudo-random bodies (no rand dep): a small LCG over the
    // base62 alphabet. For each body, the minted ghp_ token must be Valid AND
    // a single-bit corruption of its checksum must flip it to Invalid (drop).
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    for _ in 0..2_000 {
        let mut body = String::with_capacity(30);
        for _ in 0..30 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let idx = ((state >> 33) % 62) as usize;
            body.push(TOKEN_ALNUM[idx] as char);
        }
        let tok = mint_crc_token("ghp_", &body);
        assert_eq!(
            keyhog_scanner::checksum::checksum_adjusted_confidence(0.1, &tok),
            Some(keyhog_scanner::checksum::CHECKSUM_VALID_FLOOR),
            "minted token must be Valid: {tok:?}"
        );

        // Corrupt the last checksum char to a definitely-different base62 char.
        let mut bytes = tok.into_bytes();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'0' { b'1' } else { b'0' };
        let corrupted = String::from_utf8(bytes).unwrap();
        // Either the corruption changed the checksum (Invalid → None) or, in the
        // rare case it happened to equal the original char's digit, it stays
        // Valid. Guard against the false-equality case.
        let adj = keyhog_scanner::checksum::checksum_adjusted_confidence(0.1, &corrupted);
        assert!(
            adj.is_none() || adj == Some(keyhog_scanner::checksum::CHECKSUM_VALID_FLOOR),
            "corrupted token gave unexpected verdict {adj:?} for {corrupted:?}"
        );
    }
}

// ── GitHub family: classic + the four gh*_ prefixes + fine-grained ───────────

#[test]
fn github_classic_pat_fires_with_valid_crc() {
    let tok = mint_crc_token("ghp_", "aBcDefGhIjKlMnOpQrStUvWxYz0123");
    let text = format!("GITHUB_TOKEN={tok}\n");
    assert_fires("github-classic-pat", &text, &tok);
}

#[test]
fn github_classic_pat_invalid_crc_is_dropped() {
    // ghp_ + 36 alnum whose trailing 6 chars are NOT the CRC of the body.
    // engine/process.rs:166 drops Invalid-checksum matches before scoring.
    let bad = "ghp_aBcDefGhIjKlMnOpQrStUvWxYz0123XXXXXX";
    // Sanity: the checksum module itself says this is Invalid (drop → None).
    assert_eq!(
        keyhog_scanner::checksum::checksum_adjusted_confidence(0.9, bad),
        None,
        "fabricated ghp_ checksum must be Invalid"
    );
    assert_silent("github-classic-pat", &format!("GITHUB_TOKEN={bad}\n"));
}

#[test]
fn github_oauth_access_token_gho_fires() {
    // gho_ shares the classic 30-entropy + 6-CRC32 body. A valid-checksum token
    // fires; a fabricated CRC is dropped pre-scoring (the precision gain — the
    // classic validator now covers gho_/ghu_/ghs_/ghr_, not only ghp_). Regex:
    // gho_[A-Za-z0-9]{36}.
    let tok = mint_crc_token("gho_", &"aBcDe12345".repeat(3));
    assert_fires(
        "github-oauth-access-token",
        &format!("oauth_token = \"{tok}\"\n"),
        &tok,
    );
    // Negative twin: wrong 6-char CRC suffix → the detector must NOT fire.
    let bad = format!("gho_{}XXXXXX", "aBcDe12345".repeat(3));
    assert_silent(
        "github-oauth-access-token",
        &format!("oauth_token = \"{bad}\"\n"),
    );
}

#[test]
fn github_user_to_server_token_ghu_fires() {
    let tok = mint_crc_token("ghu_", &"Fg6Hi7Jk89".repeat(3));
    assert_fires(
        "github-user-to-server-token",
        &format!("GITHUB_TOKEN={tok}\n"),
        &tok,
    );
    let bad = format!("ghu_{}XXXXXX", "Fg6Hi7Jk89".repeat(3));
    assert_silent(
        "github-user-to-server-token",
        &format!("GITHUB_TOKEN={bad}\n"),
    );
}

#[test]
fn github_app_installation_token_ghs_fires() {
    let tok = mint_crc_token("ghs_", &"Lm0No1Pq23".repeat(3));
    assert_fires(
        "github-app-installation-token",
        &format!("installation_token: {tok}\n"),
        &tok,
    );
    let bad = format!("ghs_{}XXXXXX", "Lm0No1Pq23".repeat(3));
    assert_silent(
        "github-app-installation-token",
        &format!("installation_token: {bad}\n"),
    );
}

#[test]
fn github_refresh_token_ghr_fires() {
    let tok = mint_crc_token("ghr_", &"Rs4Tu5Vw67".repeat(3));
    assert_fires(
        "github-refresh-token",
        &format!("GITHUB_REFRESH_TOKEN={tok}\n"),
        &tok,
    );
    let bad = format!("ghr_{}XXXXXX", "Rs4Tu5Vw67".repeat(3));
    assert_silent(
        "github-refresh-token",
        &format!("GITHUB_REFRESH_TOKEN={bad}\n"),
    );
}

#[test]
fn plain_anchored_detector_survives_multibyte_dense_window() {
    // Regression for the anchored PLAIN-extractor UTF-8 boundary bug
    // (`engine/extract.rs::extract_plain_matches`). The phase-2 / GPU anchored
    // path localises the regex scan to a BYTE window around a literal hit. When
    // that window start landed mid-multibyte-char, the plain extractor passed a
    // non-boundary byte index straight to `Regex::find_at`, panicking the whole
    // scan — the grouped extractor snapped with `floor_char_boundary`, the plain
    // one did not. `github-classic-pat` (`ghp_[A-Za-z0-9]{36}\b`, NO capture
    // group) routes through the PLAIN extractor; a dense run of 3-byte chars
    // before the token forces a non-boundary window start.
    //
    // Vary the pad length across all three mod-3 residues (and again further out)
    // so at least one alignment lands the anchored window start mid-`中`: pre-fix
    // that alignment panicked; post-fix every alignment completes and the token
    // is still surfaced.
    let tok = mint_crc_token("ghp_", &"aBcDe12345".repeat(3));
    for pad_n in [64usize, 65, 66, 127, 128, 129] {
        let pad = "中".repeat(pad_n);
        let text = format!("github_token = \"{pad} {tok}\"\n");
        // The only `ghp_`-shaped token in the input is `tok`, so a
        // github-classic-pat hit == the token surfaced through the plain
        // anchored extractor. Reaching this assert at all means the scan did
        // not panic on the non-boundary window start.
        let matches = scan(&text, "github-classic-multibyte-recall.env");
        let fired: Vec<&str> = matches.iter().map(|m| m.detector_id.as_ref()).collect();
        assert!(
            !hits(&matches, "github-classic-pat").is_empty(),
            "github-classic-pat must survive multibyte-dense anchored extraction \
             with no UTF-8 boundary panic (pad_n={pad_n}); detectors that fired = {fired:?}"
        );
    }
}

#[test]
fn github_fine_grained_pat_fires_with_valid_crc() {
    let tok = mint_github_fine_grained(
        "Ab1Cd2Ef3Gh4Ij5Kl6Mn7O",
        "pQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz012345",
    );
    let text = format!("GH_PAT={tok}\n");
    assert_fires("github-pat-fine-grained", &text, &tok);
}

// ── AWS: AKIA / ASIA (case-sensitive uppercase) ──────────────────────────────

#[test]
fn aws_access_key_akia_fires() {
    // (?-i)(AKIA|ASIA)[0-9A-Z]{16}. No checksum validator → NotApplicable.
    let tok = "AKIAQYLPMN5HFIQR7XYZ";
    let text = format!("AWS_ACCESS_KEY_ID={tok}\n");
    assert_fires("aws-access-key", &text, tok);
}

#[test]
fn aws_access_key_asia_session_prefix_fires() {
    let tok = "ASIAZ4XK9QWERTY12345";
    let text = format!("aws_access_key_id = {tok}\n");
    assert_fires("aws-access-key", &text, tok);
}

#[test]
fn aws_access_key_lowercase_lookalike_stays_silent() {
    // The (?-i) anchor means a lowercased AKIA must NOT match this detector.
    assert_silent("aws-access-key", "key = akiaqylpmn5hfiqr7xyz\n");
}

// ── Google / GCP: AIza + 35 ──────────────────────────────────────────────────

#[test]
fn google_api_key_aiza_fires() {
    // AIza[0-9A-Za-z_-]{35}.
    let tok = "AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q";
    assert_eq!(tok.len(), 39, "AIza + 35 = 39 chars");
    let text = format!("GOOGLE_API_KEY={tok}\n");
    assert_fires("google-api-key", &text, tok);
}

#[test]
fn google_api_key_aizasy_places_variant_fires() {
    // AIzaSy[A-Za-z0-9_-]{33} (Places variant) — still id google-api-key.
    let tok = "AIzaSyD9aBcDeFgHiJkLmNoPqRsTuVwXyZ01234";
    assert_eq!(tok.len(), 39);
    let text = format!("PLACES_API_KEY = \"{tok}\"\n");
    assert_fires("google-api-key", &text, tok);
}

// ── Slack: xoxb / xoxp (regex-shape checksum validator) ──────────────────────

#[test]
fn slack_bot_token_xoxb_fires() {
    // detector regex: xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}
    // checksum SlackTokenValidator bot regex: xoxb-{10,15}-{10,15}-{15,40}.
    // This token satisfies both (so it isn't dropped as checksum-Invalid).
    let tok = "xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx";
    let text = format!("SLACK_BOT_TOKEN={tok}\n");
    assert_fires("slack-bot-token", &text, tok);
}

#[test]
fn slack_bot_token_malformed_shape_dropped_by_checksum() {
    // xoxb- prefix but a body the SlackTokenValidator rejects (last seg < 15):
    // validate() returns Invalid → engine drops it before scoring.
    let bad = "xoxb-1234567890-1234567890-short";
    assert_eq!(
        keyhog_scanner::checksum::checksum_adjusted_confidence(0.9, bad),
        None,
        "malformed xoxb body must be checksum-Invalid"
    );
    assert_silent("slack-bot-token", &format!("SLACK_BOT_TOKEN={bad}\n"));
}

#[test]
fn slack_user_token_xoxp_fires() {
    // user-token detector regex variant: xoxp-{10,13}-{10,13}-{10,13}-[a-f0-9]{32}
    // SlackTokenValidator user regex: xoxp-{10,15}-{10,15}(-{10,13})?-[a-zA-Z0-9]{24,40}.
    // 32 hex satisfies both → Valid, not dropped.
    let tok = "xoxp-1234567890-1234567890-1234567890-0123456789abcdef0123456789abcdef";
    let text = format!("SLACK_USER_TOKEN={tok}\n");
    assert_fires("slack-user-token", &text, tok);
}

// ── Stripe: sk_live / sk_test / rk_live / rk_test (structural validator) ─────

#[test]
fn stripe_secret_key_sk_live_fires() {
    // sk_live_[a-zA-Z0-9]{24,}. StripeTokenValidator: 24..=128 alnum → Valid.
    let tok = "sk_live_AbCdEfGhIjKlMnOpQrStUvWx";
    assert_eq!(tok.len(), "sk_live_".len() + 24);
    let text = format!("STRIPE_SECRET_KEY={tok}\n");
    assert_fires("stripe-secret-key", &text, tok);
}

#[test]
fn stripe_secret_key_rk_live_restricted_fires() {
    let tok = "rk_live_ZyXwVuTsRqPoNmLkJiHgFeDc";
    let text = format!("stripe_restricted_key={tok}\n");
    assert_fires("stripe-secret-key", &text, tok);
}

#[test]
fn stripe_secret_key_too_short_body_dropped_by_checksum() {
    // sk_live_ with < 24 body chars → StripeTokenValidator Invalid → dropped.
    let bad = "sk_live_tooShort123";
    assert_eq!(
        keyhog_scanner::checksum::checksum_adjusted_confidence(0.9, bad),
        None
    );
    assert_silent("stripe-secret-key", &format!("STRIPE_SECRET_KEY={bad}\n"));
}

// ── SendGrid: SG. ────────────────────────────────────────────────────────────

#[test]
fn sendgrid_api_key_sg_fires() {
    // SG\.[a-zA-Z0-9_-]{22,32}\.[a-zA-Z0-9_-]{43,47}. No checksum validator.
    let tok = "SG.AbCdEfGhIjKlMnOpQrStUv.AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfg";
    let text = format!("SENDGRID_API_KEY={tok}\n");
    assert_fires("sendgrid-api-key", &text, tok);
}

// ── Twilio: SK + 32 hex (companion secret is `required`) ─────────────────────

#[test]
fn twilio_api_key_sk_fires_with_required_secret() {
    // twilio-api-key pattern: SK[a-f0-9]{32}, companion `secret` is required=true,
    // so the SK SID alone won't surface — plant the secret in-window too.
    let sid = "SK0123456789abcdef0123456789abcdef";
    let secret = "0123456789abcdef0123456789abcdef"; // 32 alnum
    let text = format!("twilio_api_key_sid = {sid}\nTWILIO_API_SECRET = {secret}\n");
    assert_fires("twilio-api-key", &text, sid);
}

// ── npm: npm_ (CRC32 validator, same as github classic) ──────────────────────

#[test]
fn npm_access_token_fires_with_valid_crc() {
    let tok = mint_crc_token("npm_", "aBcDefGhIjKlMnOpQrStUvWxYz0123");
    let text = format!("//registry.npmjs.org/:_authToken={tok}\n");
    assert_fires("npm-access-token", &text, &tok);
}

#[test]
fn npm_access_token_invalid_crc_is_dropped() {
    let bad = "npm_aBcDefGhIjKlMnOpQrStUvWxYz0123XXXXXX";
    assert_eq!(
        keyhog_scanner::checksum::checksum_adjusted_confidence(0.9, bad),
        None
    );
    assert_silent("npm-access-token", &format!("npm_authToken={bad}\n"));
}

// ── OpenAI: sk-proj- / legacy sk- + 48 ───────────────────────────────────────

#[test]
fn openai_api_key_sk_proj_fires() {
    // sk-proj-[a-zA-Z0-9_-]{40,164}. 50 body chars is within band.
    let tok = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIj";
    let text = format!("OPENAI_API_KEY={tok}\n");
    assert_fires("openai-api-key", &text, tok);
}

#[test]
fn openai_api_key_legacy_sk_48_fires() {
    // sk-[a-zA-Z0-9]{48} (legacy). NOTE: there is no `sk-` CRC validator;
    // checksum is NotApplicable so this is a pure pattern-recall case.
    let tok = format!("sk-{}", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKl");
    assert_eq!(tok.len(), 3 + 48);
    let text = format!("OPENAI_API_KEY={tok}\n");
    assert_fires("openai-api-key", &text, &tok);
}

// ── GitLab: glpat- + glrt- (structural validator) ────────────────────────────

#[test]
fn gitlab_personal_access_token_glpat_fires() {
    // glpat-[a-zA-Z0-9_\-]{20,64}. GitlabTokenValidator: 20..=64 base64url → Valid.
    let tok = "glpat-AbCdEfGhIjKlMnOpQrSt"; // 20 body chars
    assert_eq!(tok.len(), "glpat-".len() + 20);
    let text = format!("GITLAB_TOKEN={tok}\n");
    assert_fires("gitlab-personal-access-token", &text, tok);
}

#[test]
fn gitlab_personal_access_token_with_underscore_body_fires() {
    // Real glpat tokens use base64url incl. `_` (mirror fixture shape).
    let tok = "glpat-_fOrNLbqhvJPZGZDzQ9P";
    let text = format!("gitlab_token = \"{tok}\"\n");
    assert_fires("gitlab-personal-access-token", &text, tok);
}

#[test]
fn gitlab_personal_access_token_short_body_dropped_by_checksum() {
    // glpat- with < 20 body chars → GitlabTokenValidator Invalid → dropped.
    let bad = "glpat-tooShort";
    assert_eq!(
        keyhog_scanner::checksum::checksum_adjusted_confidence(0.9, bad),
        None
    );
    assert_silent(
        "gitlab-personal-access-token",
        &format!("GITLAB_TOKEN={bad}\n"),
    );
}

#[test]
fn gitlab_package_registry_glcbt_fires() {
    // gitlab-package-registry-token: glcbt-[a-zA-Z0-9_-]{20,}. GitlabTokenValidator
    // treats glcbt-/glrt- with body 16..=64 as Valid.
    let tok = "glcbt-AbCdEfGhIjKlMnOpQrStUv";
    let text = format!("CI_JOB_TOKEN={tok}\n");
    assert_fires("gitlab-package-registry-token", &text, tok);
}

// ── Other distinctive prefix-anchored AI/infra detectors ─────────────────────

#[test]
fn anthropic_api_key_sk_ant_fires() {
    // sk-ant-api03-[A-Za-z0-9_-]{80,120}. 95 body chars within band.
    let body: String = std::iter::repeat("aB3xY7zQ9_")
        .take(10)
        .collect::<String>()
        .chars()
        .take(95)
        .collect();
    let tok = format!("sk-ant-api03-{body}");
    let text = format!("ANTHROPIC_API_KEY={tok}\n");
    assert_fires("anthropic-api-key", &text, &tok);
}

#[test]
fn groq_api_key_gsk_fires() {
    // gsk_[a-zA-Z0-9]{52}.
    let body: String = "ABCDEFGHIJ0123456789".chars().cycle().take(52).collect();
    let tok = format!("gsk_{body}");
    assert_eq!(tok.len(), 4 + 52);
    let text = format!("GROQ_API_KEY={tok}\n");
    assert_fires("groq-api-key", &text, &tok);
}

#[test]
fn openrouter_api_key_sk_or_v1_fires() {
    // sk-or-v1-[a-f0-9]{48,}.
    let body: String = "0123456789abcdef".chars().cycle().take(48).collect();
    let tok = format!("sk-or-v1-{body}");
    let text = format!("OPENROUTER_API_KEY={tok}\n");
    assert_fires("openrouter-api-key", &text, &tok);
}

#[test]
fn perplexity_api_key_pplx_fires() {
    // pplx-[a-zA-Z0-9_-]{32,}.
    let tok = format!("pplx-{}", "AbCdEfGhIjKlMnOpQrStUvWxYz012345");
    let text = format!("PERPLEXITY_API_KEY={tok}\n");
    assert_fires("perplexity-api-key", &text, &tok);
}

#[test]
fn fireworks_ai_api_key_fw_fires() {
    // fw_[a-zA-Z0-9]{40}.
    let tok = format!("fw_{}", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD");
    assert_eq!(tok.len(), 3 + 40);
    let text = format!("FIREWORKS_API_KEY={tok}\n");
    assert_fires("fireworks-ai-api-key", &text, &tok);
}

#[test]
fn replicate_api_key_r8_fires() {
    // r8_[a-zA-Z0-9]{37}.
    let tok = format!("r8_{}", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789A");
    assert_eq!(tok.len(), 3 + 37);
    let text = format!("REPLICATE_API_TOKEN={tok}\n");
    assert_fires("replicate-api-key", &text, &tok);
}

#[test]
fn huggingface_user_token_hf_fires() {
    // hf_[a-zA-Z0-9]{34,}.
    let tok = format!("hf_{}", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789");
    let text = format!("HUGGINGFACE_TOKEN={tok}\n");
    assert_fires("huggingface-user-token", &text, &tok);
}

#[test]
fn linear_api_key_lin_api_fires() {
    // lin_api_[a-zA-Z0-9]{40}.
    let tok = format!("lin_api_{}", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD");
    let text = format!("LINEAR_API_KEY={tok}\n");
    assert_fires("linear-api-key", &text, &tok);
}

#[test]
fn figma_pat_figd_fires() {
    // figd_[a-zA-Z0-9-_]{20,50}.
    let tok = format!("figd_{}", "AbCdEfGhIjKlMnOpQrStUvWx-_12");
    let text = format!("FIGMA_TOKEN={tok}\n");
    assert_fires("figma-pat", &text, &tok);
}

#[test]
fn digitalocean_pat_dop_v1_fires() {
    // dop_v1_[a-f0-9]{64}.
    let body: String = "0123456789abcdef".chars().cycle().take(64).collect();
    let tok = format!("dop_v1_{body}");
    let text = format!("DIGITALOCEAN_TOKEN={tok}\n");
    assert_fires("digitalocean-pat", &text, &tok);
}

#[test]
fn flyio_access_token_fm2_fires() {
    // fm2_[a-zA-Z0-9_-]{43}.
    let body: String = "AbCdEfGhIj0123456789_-".chars().cycle().take(43).collect();
    let tok = format!("fm2_{body}");
    assert_eq!(tok.len(), 4 + 43);
    let text = format!("FLY_API_TOKEN={tok}\n");
    assert_fires("flyio-access-token", &text, &tok);
}

#[test]
fn doppler_cli_token_dp_ct_fires() {
    // dp\.(ct|pt|sa)\.[a-zA-Z0-9]{44}.
    let body: String = "AbCdEfGhIj0123456789".chars().cycle().take(44).collect();
    let tok = format!("dp.ct.{body}");
    let text = format!("DOPPLER_TOKEN={tok}\n");
    assert_fires("doppler-cli-token", &text, &tok);
}

#[test]
fn shopify_access_token_shpca_fires() {
    // shpca_[a-f0-9]{32}.
    let body: String = "0123456789abcdef".chars().cycle().take(32).collect();
    let tok = format!("shpca_{body}");
    let text = format!("SHOPIFY_TOKEN={tok}\n");
    assert_fires("shopify-access-token", &text, &tok);
}

#[test]
fn mapbox_secret_token_sk_jwt_fires() {
    // mapbox: sk\.eyJ[0-9A-Za-z_-]{60,128}\.[0-9A-Za-z_-]{20,64}.
    let mid: String = "abcdefghij0123456789_-ABCDEFGHIJ"
        .chars()
        .cycle()
        .take(60)
        .collect();
    let tail: String = "ABCDEFGHIJ0123456789".chars().cycle().take(24).collect();
    let tok = format!("sk.eyJ{mid}.{tail}");
    let text = format!("MAPBOX_SECRET_TOKEN={tok}\n");
    assert_fires("mapbox-access-token", &text, &tok);
}

#[test]
fn dropbox_access_token_sl_fires() {
    // sl\.[a-zA-Z0-9_-]{100,}.
    let body: String = "AbCdEfGhIj0123456789_-".chars().cycle().take(110).collect();
    let tok = format!("sl.{body}");
    let text = format!("DROPBOX_TOKEN={tok}\n");
    assert_fires("dropbox-access-token", &text, &tok);
}

#[test]
fn telegram_bot_token_fires() {
    // [0-9]{8,10}:[A-Za-z0-9_-]{35}.
    let tail: String = "AbCdEfGhIj0123456789_-ABCDEFGHIJ012"
        .chars()
        .take(35)
        .collect();
    let tok = format!("123456789:{tail}");
    let text = format!("TELEGRAM_BOT_TOKEN={tok}\n");
    assert_fires("telegram-bot-token", &text, &tok);
}

// ── Cross-detector boundary: only the *intended* family claims the token ─────

#[test]
fn ghp_token_is_not_claimed_by_gho_or_npm_detectors() {
    // A valid ghp_ token must be github-classic-pat, never gho_/ghu_/npm_.
    let tok = mint_crc_token("ghp_", "aBcDefGhIjKlMnOpQrStUvWxYz0123");
    let matches = scan(&tok, "boundary.env");
    assert!(
        hits(&matches, "github-classic-pat")
            .iter()
            .any(|m| m.credential.as_ref().contains(&tok)),
        "github-classic-pat must own this ghp_ token"
    );
    assert!(
        hits(&matches, "github-oauth-access-token").is_empty(),
        "gho_ detector must not claim a ghp_ token"
    );
    assert!(
        hits(&matches, "npm-access-token").is_empty(),
        "npm detector must not claim a ghp_ token"
    );
}

#[test]
fn aws_akia_is_not_claimed_by_google_or_stripe() {
    let tok = "AKIAQYLPMN5HFIQR7XYZ";
    let matches = scan(&format!("AWS_ACCESS_KEY_ID={tok}\n"), "boundary-aws.env");
    assert!(
        !hits(&matches, "aws-access-key").is_empty(),
        "aws-access-key must fire on AKIA"
    );
    assert!(hits(&matches, "google-api-key").is_empty());
    assert!(hits(&matches, "stripe-secret-key").is_empty());
}
