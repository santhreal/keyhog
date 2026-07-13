//! Migrated from src/entropy/scanner.rs, canonical-shape gating under a
//! credential anchor (KH-GAP-004).
//!
//! Perfect digest/UUID/license-serial shapes must be dropped even under a
//! credential keyword anchor (they are not secrets), while genuine symbolic
//! credentials and non-canonical-length values must still surface.

use keyhog_scanner::entropy::shannon_entropy;
use keyhog_scanner::testing::entropy_scanner::{
    candidate_is_plausible, credential_keyword_context, is_canonical_non_secret_shape,
    isolated_keyword_free_match_count_with_min_len,
};

#[test]
fn isolated_keyword_free_min_len_comes_from_active_generic_keyword_secret_spec() {
    let secret = "A1b2C3d4E5f6g7H8i9J";
    assert_eq!(
        isolated_keyword_free_match_count_with_min_len(secret, 30),
        0,
        "a strict detector-owned minimum must suppress the shorter isolated token"
    );
    assert!(
        isolated_keyword_free_match_count_with_min_len(secret, 10) > 0,
        "a looser detector-owned minimum must admit the same isolated token"
    );
}

#[test]
fn sha256_hex_dropped_under_token_anchor() {
    // `token = "<64-hex>"` must NOT fire: a perfect sha256 shape is a digest,
    // the generic `token` anchor is too weak to override it.
    let sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert_eq!(sha256.len(), 64);
    let entropy = shannon_entropy(sha256.as_bytes());
    assert!(is_canonical_non_secret_shape(sha256));
    assert!(!candidate_is_plausible(
        sha256,
        entropy,
        &credential_keyword_context("api_key"),
        &[]
    ));
}

#[test]
fn sha1_and_git_commit_sha_dropped_under_anchor() {
    let sha1 = "356a192b7913b04c54574d18c28d46e6395428ab"; // 40-hex
    assert_eq!(sha1.len(), 40);
    assert!(is_canonical_non_secret_shape(sha1));
    let e = shannon_entropy(sha1.as_bytes());
    assert!(!candidate_is_plausible(
        sha1,
        e,
        &credential_keyword_context("api_key"),
        &[]
    ));
}

#[test]
fn md5_and_sha512_lengths_dropped() {
    let md5 = "d41d8cd98f00b204e9800998ecf8427e"; // 32-hex
    let sha512 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"; // 128-hex
    assert_eq!(md5.len(), 32);
    assert_eq!(sha512.len(), 128);
    assert!(is_canonical_non_secret_shape(md5));
    assert!(is_canonical_non_secret_shape(sha512));
}

#[test]
fn uuid_dropped_under_secret_anchor() {
    // 8-4-4-4-12 UUID / k8s-resource-uid wrapped in `secret=<uuid>`.
    let uuid = "550e8400-e29b-41d4-a716-446655440000";
    assert_eq!(uuid.len(), 36);
    assert!(is_canonical_non_secret_shape(uuid));
    let e = shannon_entropy(uuid.as_bytes());
    assert!(!candidate_is_plausible(
        uuid,
        e,
        &credential_keyword_context("api_key"),
        &[]
    ));
}

#[test]
fn npm_sha512_integrity_dropped_under_anchor() {
    // npm-lock-integrity `integrity: "sha512-<base64>"`.
    // A valid sha512 integrity string: `sha512-` prefix + 88-char base64 body
    // (64 SHA-512 bytes → 88 base64 chars with `==` padding, 88 % 4 == 0).
    // The prior fixture used a 75-char body (75 % 4 == 3) which classify_base64
    // correctly rejected as invalid padded base64, so standard_base64_shape
    // returned None and is_canonical_non_secret_shape returned false.
    // This fixture is the sha512 digest of b"test_input_0" encoded in standard base64.
    let integrity =
        "sha512-Nn+Gk5B3l3p8osBOmDvJiO2mzOZGsDo3jKKykfYRX3wd5Ig5/NRCuXisx2EXI7eQrQNLgxFO2eh1x0r+aK9U+w==";
    let body = &integrity["sha512-".len()..];
    assert_eq!(
        body.len(),
        88,
        "test invariant: sha512 base64 body must be 88 chars"
    );
    assert_eq!(
        body.len() % 4,
        0,
        "test invariant: valid padded base64 requires len%4==0"
    );
    assert!(is_canonical_non_secret_shape(integrity));
    let e = shannon_entropy(integrity.as_bytes());
    assert!(!candidate_is_plausible(
        integrity,
        e,
        &credential_keyword_context("api_key"),
        &[]
    ));
}

#[test]
fn license_serial_5x5_dropped_under_secret_anchor() {
    // 5x5 dashed uppercase license serial `SECRET="JQQJN-..."`.
    for serial in [
        "JQQJN-VBWHG-XYZ12-AB3CD-EF4GH",
        "ABCDE-FGHIJ-KLMNO-PQRST-UVWXY",
    ] {
        assert_eq!(serial.len(), 29);
        assert!(is_canonical_non_secret_shape(serial), "{serial}");
        let e = shannon_entropy(serial.as_bytes());
        assert!(
            !candidate_is_plausible(serial, e, &credential_keyword_context("api_key"), &[]),
            "{serial}"
        );
    }
}

#[test]
fn real_symbolic_credential_under_anchor_still_admitted() {
    // Negative twin / recall guard: a genuine symbolic password is NOT a
    // canonical shape and must still fire under the credential anchor.
    let secret = "Y6NPMwS*rWGUv!JQnSG6a#D14";
    assert!(!is_canonical_non_secret_shape(secret));
    let e = shannon_entropy(secret.as_bytes());
    assert!(candidate_is_plausible(
        secret,
        e,
        &credential_keyword_context("api_key"),
        &[]
    ));
}

#[test]
fn non_canonical_hex_length_under_anchor_not_force_dropped() {
    // Recall guard: a 34-char hex value is not a canonical digest length, so
    // the shape gate must not drop it; a real key of odd length under an
    // anchor still surfaces.
    let oddhex = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7"; // 34 chars
    assert!(!is_canonical_non_secret_shape(oddhex));
}
