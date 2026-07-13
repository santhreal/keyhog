//! Regression: the decode-through "anchor decoded matches" guard.
//!
//! A decoded sub-chunk is SYNTHESIZED content, the bytes that fall out of a
//! base64/hex/url decode, with no surrounding keyword/structural context from the
//! real file. A generic/entropy detector fires on shape/entropy ALONE, so on
//! decoded content its match rests on nothing but the decoded bytes happening to
//! look token-shaped. Decoding ordinary readable text routinely produces exactly
//! that (`InvalidNextTokenException"}`, `max-age...;includeSubdomains`, prose) 
//! on the full CredData tree, decode-through surfaced +264 such generic/entropy
//! hits that are ALL non-secrets, for ~0 real TP (pure precision loss). The guard
//! (`adjudicate::record_decoded_generic_entropy_suppression`, wired into
//! `scan_postprocess`) drops decoded matches from the generic/entropy family;
//! vendor/key detectors on decoded content (genuine encoded secrets) self-anchor
//! on their required literal and are UNAFFECTED.
//!
//! Each assertion checks EXACT credential bytes + detector ids via the on-disk
//! scanner (Law 6), never `!is_empty`. The vendor key surfacing in the combined
//! test proves decode actually ran, so the generic/entropy absence is a real
//! suppression, never a vacuous "decode never triggered" pass.

mod support;
use support::paths::detector_dir;

use base64::Engine;
use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::CompiledScanner;

fn scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    CompiledScanner::compile(detectors).expect("compile scanner")
}

fn b64(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}

fn scan_text(text: String, path: &str) -> Vec<RawMatch> {
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "decode-guard-test".into(),
            path: Some(path.into()),
            ..Default::default()
        },
    };
    scanner().scan(&chunk)
}

fn ids(hits: &[RawMatch]) -> Vec<(String, String)> {
    hits.iter()
        .map(|m| (m.detector_id.to_string(), m.credential.to_string()))
        .collect()
}

/// Thin alias to the canonical predicate the GUARD itself gates on
/// (`keyhog_scanner::is_generic_or_entropy_detector` → `detector_ids::is_generic_or_entropy_detector`),
/// so these assertions validate the EXACT classification the guard uses. ONE
/// definitional home, no drift if the canonical prefix set ever changes.
fn is_generic_or_entropy(detector_id: &str) -> bool {
    keyhog_scanner::is_generic_or_entropy_detector(detector_id)
}

// A bare high-entropy token (mixed-case alphanumeric, no vendor prefix) matchable
// ONLY by the generic/entropy pool, same shape as the CredData decode FP
// `4MwrrncB4YlTYeeBNbC1oGuHG6sFbU1A`. Paired with a `secret` keyword so the
// generic keyword bridge surfaces it (the strongest generic-pool path).
const TOKEN: &str = "4MwrrncB4YlTYeeBNbC1oGuHG6sFbU1A";

/// A PEM RSA key, fires `private-key` with no vendor checksum (a shipped
/// decode-through contract positive, reused from `regression_decode_through_strict`).
const PEM: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
    MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n\
    KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIWPaVgC5bA8AjVWdjxNm\n\
    -----END RSA PRIVATE KEY-----";
const PEM_NEEDLE: &str = "MIIBOgIBAAJBAKj34Gkx";

/// Non-vacuity control: scanned DIRECTLY (no decode), the `api_secret=<token>`
/// shape DOES fire a generic/entropy detector on the token. If this ever stops
/// holding, the suppression assertion below would pass for the wrong reason, so
/// this test is the guardrail that keeps it honest.
#[test]
fn control_token_fires_generic_or_entropy_at_top_level() {
    let hits = scan_text(format!("api_secret={TOKEN}\n"), "config.txt");
    assert!(
        hits.iter().any(|m| {
            m.credential.as_ref().contains(TOKEN) && is_generic_or_entropy(m.detector_id.as_ref())
        }),
        "control: the bare token must fire a generic/entropy detector at top level \
         (else the decode-suppression test is vacuous); got {:?}",
        ids(&hits),
    );
}

/// The guard: one base64 blob carrying BOTH the PEM key and the `api_secret`
/// token. Decode-through recovers both. The vendor key SURFACES under
/// `private-key`: proving decode actually ran, while the token, matchable only
/// by the anchor-less generic/entropy pool, is SUPPRESSED.
#[test]
fn decoded_generic_entropy_is_gated_while_vendor_key_survives() {
    let plaintext = format!("{PEM}\napi_secret={TOKEN}\n");
    let hits = scan_text(format!("blob = \"{}\"\n", b64(&plaintext)), "config.txt");

    // Decode ran + the vendor key survived (proves non-vacuity):
    assert!(
        hits.iter().any(|m| {
            m.credential.as_ref().contains(PEM_NEEDLE) && m.detector_id.as_ref() == "private-key"
        }),
        "decode-through must run and the vendor key must survive the guard \
         (it is scoped to the generic/entropy family only); got {:?}",
        ids(&hits),
    );

    // The decoded generic/entropy match is gated:
    let leaked: Vec<(String, String)> = hits
        .iter()
        .filter(|m| {
            m.credential.as_ref().contains(TOKEN) && is_generic_or_entropy(m.detector_id.as_ref())
        })
        .map(|m| (m.detector_id.to_string(), m.credential.to_string()))
        .collect();
    assert!(
        leaked.is_empty(),
        "a generic/entropy match on DECODED content must be suppressed \
         (it rests on shape alone, no anchor in the synthesized bytes); leaked {leaked:?}",
    );
}

/// Scope proof at top level: the SAME token surfaces normally when NOT decoded 
/// the guard is confined to the decode path and never touches real file context.
#[test]
fn top_level_generic_entropy_is_untouched_by_the_decode_guard() {
    let hits = scan_text(format!("api_secret={TOKEN}\n"), "config.txt");
    assert!(
        hits.iter().any(|m| {
            m.credential.as_ref().contains(TOKEN) && is_generic_or_entropy(m.detector_id.as_ref())
        }),
        "top-level generic/entropy detection must be unaffected by the decode-only \
         guard; got {:?}",
        ids(&hits),
    );
}
