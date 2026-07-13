//! Regression: the CORE redaction / preview *policy* at the finding boundary.
//!
//! This complements `regression_sensitive_string_redaction.rs` (which pins the
//! `redact()` arithmetic in isolation). Here the subject is the POLICY that
//! wraps that primitive: `RawMatch::to_redacted()`: the only shape that may
//! cross keyhog's process boundary (kimi-wave1 finding 2.1), plus the redacted
//! `Debug` impls of `RawMatch` and `SensitiveString`.
//!
//! Standalone integration crate: only the public API is reachable. Every
//! assertion is a CONCRETE expected value (exact masked string, exact byte
//! count, exact hash hex, exact bounded length), never `is_empty()` alone.
//!
//! Arithmetic pinned from source (`credential.rs::redact`):
//!   ASCII, `len <= 8`            -> "****"
//!   ASCII, `len  > 8`            -> `s[..edge] + "..." + s[len-edge..]`
//!   non-ASCII gates on char_count (grapheme-safe)
//! with `edge = (count / 8).clamp(1, 4)`. Preview is therefore length-bounded:
//! for any revealed secret the output is `2*edge + 3` chars, max 11.

use std::collections::HashMap;
use std::sync::Arc;

use keyhog_core::{
    hex_encode, redact, sha256_hash, MatchLocation, RawMatch, SensitiveString, Severity,
};

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

fn loc() -> MatchLocation {
    MatchLocation {
        source: Arc::from("filesystem"),
        file_path: Some(Arc::from("config/prod.env")),
        line: Some(7),
        offset: 42,
        commit: None,
        author: None,
        date: None,
    }
}

/// Build a `RawMatch` with an explicit credential, companions, and scores.
/// `credential_hash` is the real SHA-256 of `credential` so hash-preservation
/// assertions check a concrete, reproducible 32-byte value.
fn raw_match(credential: &str, companions: HashMap<String, String>) -> RawMatch {
    RawMatch {
        detector_id: Arc::from("aws-access-key"),
        detector_name: Arc::from("AWS Access Key"),
        service: Arc::from("aws"),
        severity: Severity::Critical,
        credential: SensitiveString::from(credential),
        credential_hash: sha256_hash(credential),
        companions,
        location: loc(),
        entropy: Some(4.5),
        confidence: Some(0.9),
    }
}

// ------------------------------------------------------------------
// redact(): concrete edge values NOT already pinned by the sibling file
// ------------------------------------------------------------------

#[test]
fn redact_realistic_aws_token_reveals_two_char_edges() {
    // 20-byte ASCII token: edge = (20/8).clamp(1,4) = 2 -> first2 + "..." + last2.
    let token = "AKIA1234567890ABCDEF";
    assert_eq!(token.len(), 20);
    let r = redact(token);
    assert_eq!(&*r, "AK...EF");
    // The 16 interior bytes must not survive anywhere in the preview.
    assert!(!r.contains("1234567890"), "interior leaked: {}", &*r);
}

#[test]
fn redact_edge_three_at_len_twentyfour() {
    // 24 bytes: edge = (24/8).clamp(1,4) = 3 -> first3 + "..." + last3.
    // Fills the gap between the sibling file's len-16 (edge 2) and len-32 (edge 4).
    let s = "abcdefghijklmnopqrstuvwx";
    assert_eq!(s.len(), 24);
    let r = redact(s);
    assert_eq!(&*r, "abc...vwx");
    assert_eq!(r.len(), 9); // 3 + 3(dots) + 3
}

#[test]
fn redact_edge_one_at_len_twelve() {
    // 12 bytes: edge = (12/8).clamp(1,4) = 1. Integer floor keeps edge at 1 all
    // the way to len 15; a naive `len/8`-rounds-up would wrongly reveal 2.
    let s = "abcdefghijkl";
    assert_eq!(s.len(), 12);
    let r = redact(s);
    assert_eq!(&*r, "a...l");
}

#[test]
fn redact_preview_length_is_bounded_to_eleven_for_huge_secret() {
    // ADVERSARIAL: a 500-byte secret. edge raw = 62 but .clamp(1,4) pins it at
    // 4, so the preview is EXACTLY "HEAD...TAIL" (11 chars), the preview length
    // is bounded regardless of input size (no proportional leak).
    let s = format!("HEAD{}TAIL", "x".repeat(492));
    assert_eq!(s.len(), 500);
    let r = redact(&s);
    assert_eq!(&*r, "HEAD...TAIL");
    assert_eq!(r.len(), 11);
    // Not one interior 'x' leaks; the middle is fully collapsed to "...".
    assert!(!r.contains('x'), "interior leaked: {}", &*r);
}

#[test]
fn redact_multibyte_emoji_under_char_floor_returns_full_mask() {
    // ADVERSARIAL: three key emoji = 3 chars but 12 BYTES. A byte-length gate
    // would see 12 > 8 and slice mid-codepoint. redact() gates on char_count
    // (3 <= 8) and fully masks.
    let s = "\u{1F511}\u{1F511}\u{1F511}"; // 🔑🔑🔑
    assert_eq!(s.chars().count(), 3);
    assert_eq!(s.len(), 12);
    let r = redact(s);
    assert_eq!(&*r, "****");
}

#[test]
fn redact_sixtyfour_hex_hides_interior_and_shrinks() {
    // A 64-char hex secret: edge clamps at 4 -> first4 + "..." + last4, 11 chars.
    let s = "0123456789abcdef0123456789abcdef0123456789abcdefFEDCBA9876543210";
    assert_eq!(s.len(), 64);
    let r = redact(s);
    assert_eq!(&*r, "0123...3210");
    assert_eq!(r.len(), 11);
    assert!(r.len() < s.len(), "redaction must shrink a long secret");
    assert!(
        !r.contains("456789abcdef"),
        "interior of the hex secret leaked: {}",
        &*r
    );
}

// ------------------------------------------------------------------
// RawMatch::to_redacted(): the boundary policy
// ------------------------------------------------------------------

#[test]
fn to_redacted_credential_uses_exact_masked_form() {
    let rm = raw_match("AKIA1234567890ABCDEF", HashMap::new());
    let red = rm.to_redacted();
    // 20-byte credential -> edge 2 masked preview.
    assert_eq!(&*red.credential_redacted, "AK...EF");
}

#[test]
fn to_redacted_never_carries_plaintext_anywhere() {
    let mut comp = HashMap::new();
    comp.insert(
        "session_token".to_string(),
        "aws_secret_key_1234567890".to_string(),
    );
    let rm = raw_match("AKIA1234567890ABCDEF", comp);
    let red = rm.to_redacted();

    // The masked credential must not equal or contain the raw secret.
    assert_ne!(&*red.credential_redacted, "AKIA1234567890ABCDEF");
    assert!(!red.credential_redacted.contains("1234567890"));

    // No companion VALUE may survive verbatim.
    let comp_val = &red.companions_redacted["session_token"];
    assert!(
        !comp_val.contains("aws_secret_key_1234567890"),
        "companion plaintext leaked into redacted finding: {comp_val}"
    );
}

#[test]
fn to_redacted_redacts_companion_value_but_preserves_key() {
    let mut comp = HashMap::new();
    // 25-byte value: edge = (25/8).clamp(1,4) = 3 -> "aws...890".
    comp.insert(
        "session_token".to_string(),
        "aws_secret_key_1234567890".to_string(),
    );
    let rm = raw_match("AKIA1234567890ABCDEF", comp);
    let red = rm.to_redacted();

    // Key is preserved verbatim; value is masked to the exact edge-3 form.
    assert_eq!(red.companions_redacted.len(), 1);
    assert_eq!(
        red.companions_redacted
            .get("session_token")
            .map(String::as_str),
        Some("aws...890")
    );
}

#[test]
fn to_redacted_short_companion_is_fully_masked() {
    let mut comp = HashMap::new();
    comp.insert("region".to_string(), "env".to_string()); // 3 bytes <= 8 -> "****"
    let rm = raw_match("AKIA1234567890ABCDEF", comp);
    let red = rm.to_redacted();
    assert_eq!(
        red.companions_redacted.get("region").map(String::as_str),
        Some("****")
    );
}

#[test]
fn to_redacted_preserves_hash_severity_and_scores_exactly() {
    let rm = raw_match("AKIA1234567890ABCDEF", HashMap::new());
    let red = rm.to_redacted();

    // Hash bytes are copied through untouched (one-way SHA-256, correlation key).
    let expected_hash = sha256_hash("AKIA1234567890ABCDEF");
    assert_eq!(red.credential_hash, expected_hash);
    assert_eq!(red.credential_hash, rm.credential_hash);
    // ...and it is NOT the all-zero sentinel.
    assert!(!red.credential_hash.is_zero());

    // Non-secret metadata rides through verbatim.
    assert_eq!(red.severity, Severity::Critical);
    assert_eq!(&*red.detector_id, "aws-access-key");
    assert_eq!(red.entropy, Some(4.5));
    assert_eq!(red.confidence, Some(0.9));
    assert_eq!(red.location.line, Some(7));
    assert_eq!(red.location.offset, 42);
}

// ------------------------------------------------------------------
// RawMatch / SensitiveString redacted Debug
// ------------------------------------------------------------------

#[test]
fn rawmatch_debug_redacts_credential_and_companion_count() {
    let mut comp = HashMap::new();
    comp.insert(
        "session_token".to_string(),
        "aws_secret_key_1234567890".to_string(),
    );
    let rm = raw_match("AKIA1234567890ABCDEF", comp);
    let dbg = format!("{rm:?}");

    // Credential collapsed to a byte count (20 bytes), companions to a count.
    assert!(dbg.contains("<redacted 20 bytes>"), "dbg: {dbg}");
    assert!(dbg.contains("<1 redacted companions>"), "dbg: {dbg}");
    // Neither the credential nor the companion value may appear.
    assert!(
        !dbg.contains("AKIA1234567890ABCDEF"),
        "credential leaked: {dbg}"
    );
    assert!(
        !dbg.contains("aws_secret_key_1234567890"),
        "companion leaked: {dbg}"
    );
    // Non-secret identity is still present for triage.
    assert!(dbg.contains("aws-access-key"), "detector id missing: {dbg}");
}

#[test]
fn rawmatch_debug_preserves_hash_hex_not_plaintext() {
    let rm = raw_match("AKIA1234567890ABCDEF", HashMap::new());
    let dbg = format!("{rm:?}");
    // The one-way SHA-256 hex is deliberately preserved for correlation.
    let expected_hex = hex_encode(sha256_hash("AKIA1234567890ABCDEF"));
    assert_eq!(expected_hex.len(), 64);
    assert!(
        dbg.contains(&expected_hex),
        "hash hex missing from debug: {dbg}"
    );
}

#[test]
fn sensitive_string_debug_masks_adversarial_quoted_secret() {
    // ADVERSARIAL: quotes/newline in the secret must not break out of the
    // redacted form or reveal any content. Debug reports only a byte count.
    let secret = "secret\"with\nquotes";
    let ss = SensitiveString::from(secret);
    let dbg = format!("{ss:?}");
    assert_eq!(
        dbg,
        format!("SensitiveString(<redacted {} bytes>)", secret.len())
    );
    // Concretely: 18 bytes.
    assert_eq!(dbg, "SensitiveString(<redacted 18 bytes>)");
    assert!(!dbg.contains("secret"), "leak: {dbg}");
    assert!(!dbg.contains("quotes"), "leak: {dbg}");
}
