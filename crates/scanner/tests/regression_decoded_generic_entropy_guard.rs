//! Regression: the decode-through "anchor decoded matches" guard.
//!
//! Entropy-only decoded matches remain suppressed because they have no
//! structural evidence. A phase-2 generic assignment is different: the decoded
//! plaintext or parent splice retains a detector-owned keyword, so it is an
//! anchored detection and must survive alongside vendor matches.
//!
//! Each assertion checks EXACT credential bytes + detector ids via the on-disk
//! scanner (Law 6), never `!is_empty`. The vendor key surfacing in the combined
//! test proves decode actually ran, so the generic/entropy absence is a real
//! suppression, never a vacuous "decode never triggered" pass.

mod support;
use support::paths::detector_dir;

use base64::Engine;
use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, RawMatch, Severity};
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
const ENTROPY_ONLY_TOKEN: &str = "qA9zM4nB7vC2xL8pR5tY1uI6oP3sD0fG9hJ2kL7mN4bV8cX1zQ6wE5rT0yU3iO";

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

/// One base64 blob carrying both the PEM key and an anchored `api_secret`
/// token. Decode-through must recover both.
#[test]
fn decoded_generic_assignment_and_vendor_key_both_survive() {
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

    assert!(
        hits.iter().any(|m| {
            m.credential.as_ref().contains(TOKEN) && is_generic_or_entropy(m.detector_id.as_ref())
        }),
        "the decoded api_secret assignment retains its detector-owned anchor; got {:?}",
        ids(&hits),
    );
}

#[test]
fn decoded_entropy_only_token_stays_suppressed_without_an_assignment_detector() {
    let direct = scan_text(
        format!("VALUE={ENTROPY_ONLY_TOKEN}\n"),
        "config/secrets.env",
    );
    assert!(
        direct.iter().any(|m| {
            m.credential.as_ref() == ENTROPY_ONLY_TOKEN
                && keyhog_scanner::is_entropy_detector(m.detector_id.as_ref())
        }),
        "direct entropy control must surface before decode suppression; got {:?}",
        ids(&direct),
    );
    assert!(!direct.iter().any(|m| {
        m.credential.as_ref() == ENTROPY_ONLY_TOKEN
            && is_generic_or_entropy(m.detector_id.as_ref())
            && !keyhog_scanner::is_entropy_detector(m.detector_id.as_ref())
    }));

    let encoded = scan_text(
        format!(
            "blob = \"{}\"\n",
            b64(&format!("VALUE={ENTROPY_ONLY_TOKEN}\n"))
        ),
        "config/secrets.env",
    );
    assert!(
        !encoded.iter().any(|m| {
            m.credential.as_ref() == ENTROPY_ONLY_TOKEN
                && keyhog_scanner::is_entropy_detector(m.detector_id.as_ref())
        }),
        "decoded entropy-only evidence must not survive without an anchored generic detector; got {:?}",
        ids(&encoded),
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

#[test]
fn decoded_named_detector_with_entropy_like_id_uses_the_active_plan() {
    const ID: &str = "entropy-looking-named-detector";
    const CREDENTIAL: &str = "KHCUSTOM_ABCDEF0123456789";
    let scanner = CompiledScanner::compile(vec![DetectorSpec {
        id: ID.into(),
        name: "Entropy Looking Named Detector".into(),
        service: "custom-service".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: r"KHCUSTOM_[A-Z0-9]{16}".into(),
            ..Default::default()
        }],
        keywords: vec!["KHCUSTOM_".into()],
        min_confidence: Some(0.0),
        ..Default::default()
    }])
    .expect("compile custom named detector");
    let chunk = Chunk {
        data: format!("blob = \"{}\"\n", b64(CREDENTIAL)).into(),
        metadata: ChunkMetadata {
            source_type: "decode-active-plan-test".into(),
            path: Some("custom.env".into()),
            ..Default::default()
        },
    };

    let hits = scanner.scan(&chunk);
    assert!(
        hits.iter().any(|matched| {
            matched.detector_id.as_ref() == ID && matched.credential.as_ref() == CREDENTIAL
        }),
        "decoded named finding must follow its compiled class; got {:?}",
        ids(&hits),
    );
}
