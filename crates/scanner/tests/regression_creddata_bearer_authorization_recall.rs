//! Recall regression for the CredData "Bearer Authorization" class (~75 labeled
//! positives) — the opaque token following the RFC 6750 `Bearer` scheme keyword,
//! `Authorization: Bearer <token>` / `- Bearer <40-hex>`.
//!
//! keyhog was WHOLLY BLIND to this class (recalled 0 of 75): there was a
//! `basic-auth-credentials` detector for the sibling `Basic <base64>` scheme but
//! none for `Bearer`, and the dominant token shape is a 36-40 char hex /
//! alphanumeric string the generic entropy/shape pipeline suppresses as a bare
//! hash digest. `bearer-authorization` is a STRONG-anchor structural detector
//! (the `is_structural_password_slot_detector` family): the suppression pipeline
//! skips the Tier-B randomness/digest floor (`apply_tier_b == false`), so those
//! bare tokens surface, while precision against placeholders is held by three
//! orthogonal gates that do NOT penalise a random token —
//!   * the `{16,}` value floor drops the short scheme words (`token`, `secret`);
//!   * the regex excludes `<` `>` `$` (templates and shell vars);
//!   * the `dictionary_word_placeholder` gate drops a value the English bigram
//!     model is CONFIDENT is a real word.
//!
//! Each `text` mirrors a real corpus shape. Assertions check the exact surfaced
//! credential bytes via the on-disk scanner — never `!is_empty`.

mod support;
use support::contracts::{make_chunk, scanner};

use keyhog_core::Chunk;
use keyhog_scanner::CompiledScanner;

fn matches(s: &CompiledScanner, chunk: &Chunk) -> Vec<(String, String)> {
    s.clear_fragment_cache();
    s.scan(chunk)
        .into_iter()
        .map(|m| (m.detector_id.to_string(), m.credential.to_string()))
        .collect()
}

/// True iff `credential` surfaces under exactly `detector_id`.
fn surfaces_under(text: &str, detector_id: &str, credential: &str) -> bool {
    let s = scanner();
    let chunk = make_chunk(text, "source", "probe.conf");
    matches(&s, &chunk)
        .iter()
        .any(|(id, cred)| id == detector_id && cred == credential)
}

/// True iff NOTHING surfaces `credential` (under any detector).
fn nothing_surfaces(text: &str, credential: &str) -> bool {
    let s = scanner();
    let chunk = make_chunk(text, "source", "probe.conf");
    !matches(&s, &chunk)
        .iter()
        .any(|(_, cred)| cred == credential)
}

// ── SURFACE: real Bearer token shapes ───────────────────────────────────────

#[test]
fn bearer_40hex_token_surfaces() {
    // The dominant CredData shape: `- Bearer <40-hex>` (YAML list item).
    let cred = "d1fc83f09661bcaf3cb3591ec4b93fe93b07087e";
    let text = format!("  - Bearer {cred}");
    assert!(
        surfaces_under(&text, "bearer-authorization", cred),
        "40-hex Bearer token must surface (it is a bare digest the Tier-B floor \
         would otherwise suppress) — got {:?}",
        {
            let s = scanner();
            matches(&s, &make_chunk(&text, "source", "probe.conf"))
        },
    );
}

#[test]
fn bearer_mixedcase_opaque_token_surfaces() {
    let cred = "r7yzGzH0SW5Xtx1lMFQ5xA6pCS0fZLJlG8P6";
    let text = format!("Authorization: Bearer {cred}");
    assert!(surfaces_under(&text, "bearer-authorization", cred));
}

#[test]
fn bearer_in_curl_header_surfaces() {
    let cred = "a3f9c1e07b42d85f6098ac1de2f3b4c5d6e7f809";
    let text = format!("curl -H 'Authorization: Bearer {cred}' https://api.internal/health");
    assert!(surfaces_under(&text, "bearer-authorization", cred));
}

#[test]
fn lowercase_bearer_scheme_surfaces() {
    // (?i) — a lower-cased scheme keyword must still fire.
    let cred = "a3f9c1e07b42d85f6098ac1de2f3b4c5";
    let text = format!("authorization: bearer {cred}");
    assert!(surfaces_under(&text, "bearer-authorization", cred));
}

// ── SUPPRESS: placeholders / prose / templates ──────────────────────────────

#[test]
fn bearer_angle_bracket_template_is_not_surfaced() {
    // `<` is excluded from the value class — the token run never starts.
    assert!(nothing_surfaces(
        "Authorization: Bearer <access_token>",
        "access_token",
    ));
}

#[test]
fn bearer_shell_var_is_not_surfaced() {
    assert!(nothing_surfaces(
        "req.headers['Authorization'] = 'Bearer ' + $ACCESS_TOKEN",
        "ACCESS_TOKEN",
    ));
}

#[test]
fn bearer_short_scheme_word_is_not_surfaced() {
    // `token` is 5 chars — below the {16,} floor, the regex never matches.
    let s = scanner();
    let chunk = make_chunk(
        "Bearer token required for all authenticated API requests.",
        "source",
        "probe.conf",
    );
    assert!(
        !matches(&s, &chunk)
            .iter()
            .any(|(id, _)| id == "bearer-authorization"),
        "prose `Bearer token` must not fire the detector",
    );
}

#[test]
fn bearer_confident_dictionary_value_is_not_surfaced() {
    // A confident English concatenation must be dropped by the
    // dictionary_word_placeholder gate even though it clears the {16,} floor.
    assert!(nothing_surfaces(
        "Bearer yourtokenvaluehere is a placeholder, replace it.",
        "yourtokenvaluehere",
    ));
}
