//! Gap test: the strong-keyword-anchored encoded-text-secret gate.
//!
//! `is_strong_keyword_anchored_encoded_text_secret(keyword, value)` lets a
//! base64-wrapped printable secret under a credential keyword reach the scorer
//! while keeping random binary/base64 blobs suppressed. The contract:
//!   - a value containing `.` or shorter than 24 bytes is rejected up front;
//!   - the keyword must normalize and be a strong anchor: either it carries a
//!     secret suffix, OR it is one of the encoded-text-secret anchors
//!     (`password`/`passwd`/`pwd`/`passphrase`/`token`/`secret`/`credential`)
//!     and `credential`/`passphrase` reach ownership ONLY through that second
//!     disjunct, since they do not match the secret-suffix family;
//!   - and the value must decode to printable text (a binary base64 payload is
//!     rejected even under a strong anchor).
//!
//! The decode-true and decode-false values reuse the constructions proven by the
//! `decodes_to_printable_text` unit tests, so the decode result is known.

use base64::Engine as _;
use keyhog_scanner::testing::is_strong_keyword_anchored_encoded_text_secret_for_test as strong_anchored;

fn decodable_printable_value() -> String {
    base64::engine::general_purpose::STANDARD.encode(b"hello-world-this-is-a-secret-value")
}

fn binary_value() -> String {
    // 24 high non-printable bytes -> printable_ratio 0 -> not printable text.
    let raw: Vec<u8> = (128u8..=151).collect();
    base64::engine::general_purpose::STANDARD.encode(raw)
}

#[test]
fn a_short_value_or_a_value_with_a_dot_is_rejected_up_front() {
    assert!(!strong_anchored("password", "shorty"));
    assert!(!strong_anchored(
        "password",
        "this.value.has.dots.and.is.long.enough"
    ));
}

#[test]
fn a_non_anchor_or_unnormalizable_keyword_is_rejected() {
    // `username` is neither a secret suffix nor an encoded-text-secret anchor, so
    // the decode is never even consulted.
    assert!(!strong_anchored("username", &decodable_printable_value()));
    // `===` does not normalize.
    assert!(!strong_anchored("===", &decodable_printable_value()));
}

#[test]
fn a_secret_suffix_anchor_with_printable_text_is_accepted() {
    assert!(strong_anchored("api_secret", &decodable_printable_value()));
}

#[test]
fn an_encoded_text_secret_anchor_is_accepted_via_the_second_disjunct() {
    // `credential` does not carry a secret suffix, so it reaches ownership only
    // through the encoded-text-secret anchor list.
    assert!(strong_anchored("credential", &decodable_printable_value()));
}

#[test]
fn a_strong_anchor_with_a_binary_value_is_rejected_by_the_decode_gate() {
    assert!(!strong_anchored("password", &binary_value()));
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin one example per branch; these SWEEP the three gates. The
// value gate (`.`-free AND ≥24 chars) and the anchor gate (secret-suffix OR the
// encoded-text-secret anchor list) and the decode gate (must decode to printable
// text) are each isolated: base64 of an alphanumeric payload is `.`-free, ≥24
// chars, and decodes to printable text, so it isolates the anchor gate; the binary
// helper isolates the decode gate. Traced against the three-gate contract. No
// proptest before.

use proptest::prelude::*;

/// Keywords accepted via the second disjunct (the encoded-text-secret anchor list).
const ENCODED_TEXT_ANCHORS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "token",
    "secret",
    "credential",
];
/// Secret-suffix families that make `<pre>_<suffix>` a strong anchor.
const SECRET_SUFFIXES: &[&str] = &["secret", "key", "token", "password"];
/// Keywords that are neither a secret suffix nor an encoded-text anchor.
const NON_ANCHORS: &[&str] = &["username", "hello", "field", "value", "name"];

fn b64(payload: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(payload.as_bytes())
}

/// A decodable printable-TEXT payload that is NOT a binary payload: it starts with
/// `'s'` (byte 0x73, low 3 bits = 3 → protobuf wire type 3, so `parse_protobuf_wire`
/// rejects at the first tag and `is_binary_payload` stays false) and carries no
/// magic header. `decodes_to_printable_text` needs decoded_len≥8, printable≥0.85,
/// and NOT a binary payload (this satisfies all three for any suffix).
fn printable_text_payload(suffix: &str) -> String {
    format!("secret-value-{suffix}")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1_000))]

    /// A value containing `.` or shorter than 24 chars is rejected up front, even
    /// under a strong anchor.
    #[test]
    fn short_or_dotted_value_is_rejected(
        dotted in any::<bool>(),
        a in "[a-zA-Z0-9]{12,20}",
        b in "[a-zA-Z0-9]{12,20}",
        short in "[a-zA-Z0-9]{1,23}",
    ) {
        let value = if dotted { format!("{a}.{b}") } else { short };
        prop_assert!(!strong_anchored("password", &value));
    }

    /// A non-anchor keyword is rejected even with a decodable printable value (the
    /// decode is never consulted).
    #[test]
    fn non_anchor_keyword_is_rejected(
        ni in 0usize..NON_ANCHORS.len(),
        payload in "[a-zA-Z0-9]{24,40}",
    ) {
        let value = b64(&payload);
        prop_assert!(!strong_anchored(NON_ANCHORS[ni], &value));
    }

    /// A secret-suffix anchor with printable base64 text is accepted.
    #[test]
    fn secret_suffix_anchor_with_printable_text_is_accepted(
        pre in "[a-z]{1,8}",
        si in 0usize..SECRET_SUFFIXES.len(),
        payload in "[a-zA-Z0-9]{24,40}",
    ) {
        let keyword = format!("{pre}_{}", SECRET_SUFFIXES[si]);
        let value = b64(&printable_text_payload(&payload));
        prop_assert!(strong_anchored(&keyword, &value));
    }

    /// Each encoded-text-secret anchor (incl. `credential`/`passphrase`, which lack
    /// a secret suffix) is accepted via the second disjunct.
    #[test]
    fn encoded_text_anchor_is_accepted(
        ai in 0usize..ENCODED_TEXT_ANCHORS.len(),
        suffix in "[a-zA-Z0-9]{16,32}",
    ) {
        let value = b64(&printable_text_payload(&suffix));
        prop_assert!(strong_anchored(ENCODED_TEXT_ANCHORS[ai], &value));
    }

    /// A strong anchor with a binary (non-printable) payload is rejected by the
    /// decode gate.
    #[test]
    fn binary_value_is_rejected_by_decode_gate(ai in 0usize..ENCODED_TEXT_ANCHORS.len()) {
        prop_assert!(!strong_anchored(ENCODED_TEXT_ANCHORS[ai], &binary_value()));
    }
}
