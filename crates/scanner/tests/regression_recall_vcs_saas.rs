//! Recall + precision regression contract for VCS / SaaS credential detectors.
//!
//! Covers the credential families a source-code scanner must never miss:
//!   * GitHub classic PAT     (`ghp_` + 30-char body + 6-char base62 CRC32)
//!   * GitLab PAT             (`glpat-` + 20-64 base64url chars)
//!   * Slack bot token        (`xoxb-<digits>-<digits>-<alnum>`)
//!   * Stripe secret key      (`sk_live_` / `sk_test_` / `rk_live_` + 24+ alnum)
//!   * Twilio API key + SID   (`SK<32 hex>` with a required secret companion)
//!   * Twilio auth token      (`TWILIO_AUTH_TOKEN=<32 hex>` + AccountSid companion)
//!
//! Every positive asserts the EXACT surfaced `detector_id`, the EXACT credential
//! bytes, and the EXACT 1-based source line. Every negative twin asserts the
//! named detector is ABSENT — never a bare `!is_empty()`.
//!
//! Token authenticity: `ghp_` tokens carry a real CRC32 base62 checksum (an
//! invalid-checksum `ghp_` is DROPPED by the checksum gate, see
//! `crates/scanner/src/checksum/github.rs`), so the positive tokens below were
//! generated with a matching CRC and the negative twin deliberately corrupts it.

mod support;
use support::contracts::{make_chunk, scanner};

use keyhog_core::RawMatch;
use keyhog_scanner::CompiledScanner;

// --- Valid, checksum-correct GitHub classic PATs (CRC32 over the 30-char body,
// base62-encoded 6-char suffix). Generated to satisfy GithubClassicPatValidator.
const GHP_VALID_A: &str = "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";
const GHP_VALID_B: &str = "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";
// Same 30-char body as GHP_VALID_A but with a corrupted 6-char checksum suffix.
const GHP_BAD_CHECKSUM: &str = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O50Zb5XX";

const GLPAT_VALID: &str = "glpat-AbCd1234EfGh5678IjKl"; // 20-char base64url body
const SLACK_BOT_VALID: &str = "xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx";
const STRIPE_LIVE_VALID: &str = "sk_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD";
const STRIPE_TEST_VALID: &str = "sk_test_0123456789abcdefghijABCD"; // 24-char body (min)
const STRIPE_PUBLISHABLE: &str = "pk_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD";

/// All matches for a given detector id whose credential equals `credential`.
fn hits<'a>(matches: &'a [RawMatch], detector_id: &str, credential: &str) -> Vec<&'a RawMatch> {
    matches
        .iter()
        .filter(|m| m.detector_id.as_ref() == detector_id && m.credential.as_ref() == credential)
        .collect()
}

/// Count of matches carrying `detector_id`, regardless of credential.
fn detector_count(matches: &[RawMatch], detector_id: &str) -> usize {
    matches
        .iter()
        .filter(|m| m.detector_id.as_ref() == detector_id)
        .count()
}

fn scan(s: &CompiledScanner, text: &str) -> Vec<RawMatch> {
    s.clear_fragment_cache();
    let chunk = make_chunk(text, "filesystem", "creds.env");
    s.scan(&chunk)
}

// ---------------------------------------------------------------------------
// GitHub classic PAT
// ---------------------------------------------------------------------------

#[test]
fn github_classic_pat_surfaces_with_rule_id_and_line() {
    let s = scanner();
    // Token on line 2 (a comment header occupies line 1).
    let text = format!("# github credentials\nGITHUB_TOKEN={GHP_VALID_A}\n");
    let matches = scan(&s, &text);
    let found = hits(&matches, "github-classic-pat", GHP_VALID_A);
    assert_eq!(
        found.len(),
        1,
        "checksum-valid ghp_ PAT must surface exactly once as github-classic-pat"
    );
    assert_eq!(found[0].credential.as_ref(), GHP_VALID_A);
    assert_eq!(found[0].location.line, Some(2));
    assert_eq!(found[0].service.as_ref(), "github");
}

#[test]
fn github_classic_pat_invalid_checksum_is_dropped() {
    // Negative twin: identical 30-char body, corrupted 6-char CRC suffix. The
    // checksum gate returns Invalid -> the match is dropped, so github-classic-pat
    // must NOT surface for this token.
    let s = scanner();
    let text = format!("GITHUB_TOKEN={GHP_BAD_CHECKSUM}\n");
    let matches = scan(&s, &text);
    assert_eq!(
        hits(&matches, "github-classic-pat", GHP_BAD_CHECKSUM).len(),
        0,
        "ghp_ with a bad CRC32 checksum must be dropped, not reported"
    );
}

#[test]
fn github_classic_pat_short_body_does_not_match() {
    // Boundary: 35-char body (regex demands exactly 36). No github-classic-pat.
    let s = scanner();
    let short = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O50Zb5H"; // ghp_ + 35 chars
    let text = format!("token = {short}\n");
    let matches = scan(&s, &text);
    assert_eq!(
        detector_count(&matches, "github-classic-pat"),
        0,
        "a 35-char body cannot be a classic PAT (needs exactly 36)"
    );
}

#[test]
fn github_classic_pat_right_boundary_rejects_overlong_run() {
    // Adversarial: a valid 36-char token immediately followed by another word
    // char (37-char alnum run). The trailing `\b` fails, so the detector must
    // not surface a truncated 36-char prefix.
    let s = scanner();
    let text = format!("{GHP_VALID_A}X\n"); // one extra trailing word char
    let matches = scan(&s, &text);
    assert_eq!(
        detector_count(&matches, "github-classic-pat"),
        0,
        "ghp_<36>X is not self-delimiting; the right-boundary must reject it"
    );
}

// ---------------------------------------------------------------------------
// GitLab PAT
// ---------------------------------------------------------------------------

#[test]
fn gitlab_pat_surfaces_with_rule_id_and_line() {
    let s = scanner();
    // glpat token on line 3.
    let text = format!("[gitlab]\nhost = gitlab.com\nGITLAB_TOKEN={GLPAT_VALID}\n");
    let matches = scan(&s, &text);
    let found = hits(&matches, "gitlab-personal-access-token", GLPAT_VALID);
    assert_eq!(
        found.len(),
        1,
        "structurally-valid glpat- token must surface once as gitlab-personal-access-token"
    );
    assert_eq!(found[0].credential.as_ref(), GLPAT_VALID);
    assert_eq!(found[0].location.line, Some(3));
    assert_eq!(found[0].service.as_ref(), "gitlab");
}

#[test]
fn gitlab_pat_short_body_does_not_match() {
    // Negative twin: `glpat-` with a 6-char body (below the 20-char floor).
    let s = scanner();
    let text = "GITLAB_TOKEN=glpat-abc123\n";
    let matches = scan(&s, text);
    assert_eq!(
        detector_count(&matches, "gitlab-personal-access-token"),
        0,
        "glpat- with a <20-char body is not a real GitLab PAT"
    );
}

// ---------------------------------------------------------------------------
// Slack bot token
// ---------------------------------------------------------------------------

#[test]
fn slack_bot_token_surfaces_with_rule_id_and_line() {
    let s = scanner();
    let text = format!("slack:\n  bot_token: {SLACK_BOT_VALID}\n");
    let matches = scan(&s, &text);
    let found = hits(&matches, "slack-bot-token", SLACK_BOT_VALID);
    assert_eq!(
        found.len(),
        1,
        "3-segment xoxb- bot token must surface once as slack-bot-token"
    );
    assert_eq!(found[0].credential.as_ref(), SLACK_BOT_VALID);
    assert_eq!(found[0].location.line, Some(2));
    assert_eq!(found[0].service.as_ref(), "slack");
}

#[test]
fn slack_bot_token_short_last_segment_does_not_match() {
    // Negative twin: third segment 10 chars (regex needs 24-32 / 15+ mixed).
    let s = scanner();
    let text = "SLACK_TOKEN=xoxb-1234567890-1234567890-tooShort12\n";
    let matches = scan(&s, text);
    assert_eq!(
        detector_count(&matches, "slack-bot-token"),
        0,
        "xoxb- with a 10-char final segment is malformed and must not surface"
    );
}

// ---------------------------------------------------------------------------
// Stripe secret key
// ---------------------------------------------------------------------------

#[test]
fn stripe_live_secret_key_surfaces_with_rule_id_and_line() {
    let s = scanner();
    let text = format!("[stripe]\nSTRIPE_SECRET_KEY={STRIPE_LIVE_VALID}\n");
    let matches = scan(&s, &text);
    let found = hits(&matches, "stripe-secret-key", STRIPE_LIVE_VALID);
    assert_eq!(
        found.len(),
        1,
        "sk_live_ secret key must surface once as stripe-secret-key"
    );
    assert_eq!(found[0].credential.as_ref(), STRIPE_LIVE_VALID);
    assert_eq!(found[0].location.line, Some(2));
    assert_eq!(found[0].service.as_ref(), "stripe");
}

#[test]
fn stripe_test_secret_key_min_length_surfaces() {
    // Boundary: sk_test_ with exactly the 24-char minimum body.
    let s = scanner();
    let text = format!("key={STRIPE_TEST_VALID}\n");
    let matches = scan(&s, &text);
    let found = hits(&matches, "stripe-secret-key", STRIPE_TEST_VALID);
    assert_eq!(
        found.len(),
        1,
        "sk_test_ key at the 24-char minimum body must surface"
    );
    assert_eq!(found[0].location.line, Some(1));
}

#[test]
fn stripe_publishable_key_is_not_a_secret_key() {
    // Adversarial precision twin: a pk_live_ PUBLISHABLE key is not secret and
    // must never surface as stripe-secret-key (detector matches sk_/rk_ only).
    let s = scanner();
    let text = format!("STRIPE_PUBLISHABLE_KEY={STRIPE_PUBLISHABLE}\n");
    let matches = scan(&s, &text);
    assert_eq!(
        detector_count(&matches, "stripe-secret-key"),
        0,
        "pk_live_ publishable key must not be reported as a Stripe secret key"
    );
}

// ---------------------------------------------------------------------------
// Twilio API key + auth token (companion-gated)
// ---------------------------------------------------------------------------

#[test]
fn twilio_api_key_with_required_secret_companion_surfaces() {
    let s = scanner();
    let sk = format!("SK{}", "0123456789abcdef".repeat(2)); // SK + 32 hex
    let secret = "abcdefghijklmnopqrstuvwxyz012345"; // 32 alnum
                                                     // SID on line 2, its required secret companion on line 3 (within 3 lines).
    let text = format!("# twilio\nTWILIO_API_KEY_SID={sk}\nTWILIO_API_SECRET={secret}\n");
    let matches = scan(&s, &text);
    let found = hits(&matches, "twilio-api-key", &sk);
    assert_eq!(
        found.len(),
        1,
        "Twilio SK API key with its required secret companion must surface"
    );
    assert_eq!(found[0].credential.as_ref(), sk);
    assert_eq!(found[0].location.line, Some(2));
    assert_eq!(found[0].service.as_ref(), "twilio");
}

#[test]
fn twilio_api_key_without_required_companion_is_dropped() {
    // Negative twin: the SK SID alone, with NO secret companion within 3 lines.
    // The required-companion gate must suppress the finding.
    let s = scanner();
    let sk = format!("SK{}", "0123456789abcdef".repeat(2));
    let text = format!("TWILIO_API_KEY_SID={sk}\n# nothing else nearby\n");
    let matches = scan(&s, &text);
    assert_eq!(
        detector_count(&matches, "twilio-api-key"),
        0,
        "Twilio API key with no secret companion must be suppressed (required companion)"
    );
}

#[test]
fn twilio_auth_token_with_account_sid_companion_surfaces() {
    let s = scanner();
    let sid = format!("AC{}", "a".repeat(32)); // AC + 32 hex AccountSid
    let auth = "0123456789abcdef".repeat(2); // 32 hex auth token
                                             // AccountSid companion on line 2, the auth token on line 3.
    let text = format!("# twilio\nTWILIO_ACCOUNT_SID={sid}\nTWILIO_AUTH_TOKEN={auth}\n");
    let matches = scan(&s, &text);
    let found = hits(&matches, "twilio-auth-token", &auth);
    assert_eq!(
        found.len(),
        1,
        "Twilio auth token anchored by its AccountSid companion must surface exactly once"
    );
    assert_eq!(found[0].credential.as_ref(), auth);
    assert_eq!(found[0].location.line, Some(3));
    assert_eq!(found[0].service.as_ref(), "twilio");
}

// ---------------------------------------------------------------------------
// Cross-family: several tokens in one file, each on its own line
// ---------------------------------------------------------------------------

#[test]
fn multiple_vcs_saas_tokens_each_report_their_own_line() {
    let s = scanner();
    // Line 1: comment. Lines 2-5: one token family each.
    let text = format!(
        "# secrets\n\
         github = {GHP_VALID_B}\n\
         gitlab = {GLPAT_VALID}\n\
         slack = {SLACK_BOT_VALID}\n\
         stripe = {STRIPE_LIVE_VALID}\n"
    );
    let matches = scan(&s, &text);

    let gh = hits(&matches, "github-classic-pat", GHP_VALID_B);
    assert_eq!(gh.len(), 1, "github token must surface in mixed chunk");
    assert_eq!(gh[0].location.line, Some(2));

    let gl = hits(&matches, "gitlab-personal-access-token", GLPAT_VALID);
    assert_eq!(gl.len(), 1, "gitlab token must surface in mixed chunk");
    assert_eq!(gl[0].location.line, Some(3));

    let sl = hits(&matches, "slack-bot-token", SLACK_BOT_VALID);
    assert_eq!(sl.len(), 1, "slack token must surface in mixed chunk");
    assert_eq!(sl[0].location.line, Some(4));

    let st = hits(&matches, "stripe-secret-key", STRIPE_LIVE_VALID);
    assert_eq!(st.len(), 1, "stripe token must surface in mixed chunk");
    assert_eq!(st[0].location.line, Some(5));
}
