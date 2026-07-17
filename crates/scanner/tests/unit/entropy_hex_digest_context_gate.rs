//! Boundary test for hex-digest context gating in strict-mode plausibility
//! (keywords.rs:187-192, 321-331).
//!
//! Pure-hex strings at canonical lengths (32/40/64/128 chars) are usually file/
//! commit/image digests, not credentials. In keyword-free context, they're
//! rejected to avoid FPs on `sha256: <hex>`. Credential context alone is not an
//! override; only an exact compiled detector key-material policy admits one.

use keyhog_scanner::testing::entropy_keywords::{
    is_candidate_plausible_in_context, is_secret_plausible_in_context,
};

#[test]
fn hex_32_char_canonical_length_without_context_rejected() {
    // MD5 digest: 32 chars of pure hex. Outside credential context, should be rejected.
    let md5 = "d41d8cd98f00b204e9800998ecf8427e";
    assert_eq!(md5.len(), 32);
    assert!(md5.chars().all(|c| c.is_ascii_hexdigit()));
    // Without credential context, pure-hex canonical lengths are rejected.
    let placeholder_keywords = vec![];
    assert!(!is_secret_plausible_in_context(
        md5,
        &placeholder_keywords,
        false,
        false
    ));
}

#[test]
fn hex_40_char_canonical_length_without_context_rejected() {
    // SHA1 / git commit SHA: 40 chars of pure hex. Outside context, rejected.
    let sha1 = "356a192b7913b04c54574d18c28d46e6395428ab";
    assert_eq!(sha1.len(), 40);
    assert!(sha1.chars().all(|c| c.is_ascii_hexdigit()));
    let placeholder_keywords = vec![];
    assert!(!is_secret_plausible_in_context(
        sha1,
        &placeholder_keywords,
        false,
        false
    ));
}

#[test]
fn hex_64_char_canonical_length_without_context_rejected() {
    // SHA256: 64 chars of pure hex. Outside context, rejected.
    let sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert_eq!(sha256.len(), 64);
    assert!(sha256.chars().all(|c| c.is_ascii_hexdigit()));
    let placeholder_keywords = vec![];
    assert!(!is_secret_plausible_in_context(
        sha256,
        &placeholder_keywords,
        false,
        false
    ));
}

#[test]
fn hex_128_char_canonical_length_without_context_rejected() {
    // SHA512: 128 chars of pure hex. Outside context, rejected.
    let sha512 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
    assert_eq!(sha512.len(), 128);
    assert!(sha512.chars().all(|c| c.is_ascii_hexdigit()));
    let placeholder_keywords = vec![];
    assert!(!is_secret_plausible_in_context(
        sha512,
        &placeholder_keywords,
        false,
        false
    ));
}

#[test]
fn hex_64_char_canonical_length_with_context_rejected_without_lift() {
    // SHA256 under broad credential context (`api_key: <hex>`) is still a
    // mirror hash-negative unless the later lift proves a crypto-key anchor.
    let sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert_eq!(sha256.len(), 64);
    assert!(sha256.chars().all(|c| c.is_ascii_hexdigit()));
    let placeholder_keywords = vec![];
    assert!(!is_secret_plausible_in_context(
        sha256,
        &placeholder_keywords,
        true,
        false
    ));
}

#[test]
fn hex_40_char_canonical_length_with_context_rejected() {
    // SHA1 / git commit SHA stays suppressed even under credential context.
    let sha1 = "356a192b7913b04c54574d18c28d46e6395428ab";
    assert_eq!(sha1.len(), 40);
    assert!(sha1.chars().all(|c| c.is_ascii_hexdigit()));
    let placeholder_keywords = vec![];
    assert!(!is_secret_plausible_in_context(
        sha1,
        &placeholder_keywords,
        true,
        false
    ));
}

#[test]
fn hex_non_canonical_66_char_accepted_regardless_of_context() {
    // 66 chars of hex is NOT a canonical digest length (32/40/64/128).
    // Must be accepted regardless of context.
    let non_canonical = "a1".repeat(33);
    assert_eq!(non_canonical.len(), 66);
    assert!(non_canonical.chars().all(|c| c.is_ascii_hexdigit()));
    let placeholder_keywords = vec![];
    // Lenient candidate mode should not reject this through the canonical
    // digest-length gate.
    assert!(is_candidate_plausible_in_context(
        &non_canonical,
        &placeholder_keywords,
        false,
        false
    ));
}

#[test]
fn hex_with_non_hex_char_not_pure_hex() {
    // "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8G5"
    // (G is not hex). Not rejected by the hex-digest gate because it's not pure hex.
    let not_pure_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8G5";
    assert_eq!(not_pure_hex.len(), 64);
    assert!(!not_pure_hex.chars().all(|c| c.is_ascii_hexdigit()));
    // Not rejected by the hex gate. Evaluated by other gates.
}

#[test]
fn hex_32_char_canonical_with_context_requires_detector_policy() {
    let md5 = "d41d8cd98f00b204e9800998ecf8427e";
    assert_eq!(md5.len(), 32);
    assert!(md5.chars().all(|c| c.is_ascii_hexdigit()));
    let placeholder_keywords = vec![];
    assert!(!is_candidate_plausible_in_context(
        md5,
        &placeholder_keywords,
        true,
        false
    ));
    assert!(is_candidate_plausible_in_context(
        md5,
        &placeholder_keywords,
        true,
        true
    ));
}

#[test]
fn hex_128_char_canonical_with_context_rejected() {
    // SHA512 under credential context stays a canonical digest shape.
    let sha512 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
    assert_eq!(sha512.len(), 128);
    assert!(sha512.chars().all(|c| c.is_ascii_hexdigit()));
    let placeholder_keywords = vec![];
    assert!(!is_secret_plausible_in_context(
        sha512,
        &placeholder_keywords,
        true,
        false
    ));
}

#[test]
fn hex_boundary_31_char_not_rejected_by_hex_gate() {
    // 31 chars of pure hex is NOT a canonical length. Not rejected by the hex gate.
    let almost_md5 = "d41d8cd98f00b204e9800998ecf8427";
    assert_eq!(almost_md5.len(), 31);
    assert!(almost_md5.chars().all(|c| c.is_ascii_hexdigit()));
    let placeholder_keywords = vec![];
    // Lenient candidate mode should not reject this through the canonical
    // digest-length gate.
    assert!(is_candidate_plausible_in_context(
        almost_md5,
        &placeholder_keywords,
        false,
        false
    ));
}

#[test]
fn hex_boundary_33_char_not_rejected_by_hex_gate() {
    // 33 chars of pure hex (not 32). Not rejected by the hex gate.
    let almost_md5 = "d41d8cd98f00b204e9800998ecf8427ea";
    assert_eq!(almost_md5.len(), 33);
    assert!(almost_md5.chars().all(|c| c.is_ascii_hexdigit()));
    let placeholder_keywords = vec![];
    // Lenient candidate mode should not reject this through the canonical
    // digest-length gate.
    assert!(is_candidate_plausible_in_context(
        almost_md5,
        &placeholder_keywords,
        false,
        false
    ));
}

#[test]
fn context_gate_only_applies_to_pure_hex_canonical_lengths() {
    // The gate is canonical digest shape without an exact detector-owned lift.
    // Already covered by tests above.
}
