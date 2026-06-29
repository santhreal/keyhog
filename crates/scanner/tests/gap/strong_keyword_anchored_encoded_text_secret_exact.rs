//! Gap test: the strong-keyword-anchored encoded-text-secret gate.
//!
//! `is_strong_keyword_anchored_encoded_text_secret(keyword, value)` lets a
//! base64-wrapped printable secret under a credential keyword reach the scorer
//! while keeping random binary/base64 blobs suppressed. The contract:
//!   - a value containing `.` or shorter than 24 bytes is rejected up front;
//!   - the keyword must normalize and be a strong anchor: either it carries a
//!     secret suffix, OR it is one of the encoded-text-secret anchors
//!     (`password`/`passwd`/`pwd`/`passphrase`/`token`/`secret`/`credential`) —
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
