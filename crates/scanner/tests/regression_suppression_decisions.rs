//! Regression coverage for the suppression / allowlist decision surface
//! (`crates/scanner/src/suppression/*`). Each test pins the EXACT boolean
//! decision the production pipeline returns for a concrete credential, plus the
//! concrete sub-shape classifiers that drive those decisions. The interesting
//! cases come in positive / negative twins: the SAME value is suppressed under a
//! generic (unanchored) detector but KEPT under a service-anchored detector,
//! which is the Tier-A vs Tier-B split the suppression tree is built around.
//!
//! Facades used (all public, non-`cfg(test)`, available to an integration test):
//!   * `known_example_suppressed(cred, path, ctx)` — the known-example stage
//!   * `named_detector_suppressed(cred, path, ctx, source, detector_id)`
//!   * `is_canonical_service_hex_key`, `looks_like_standard_base64_blob`
//!   * `shape::looks_like_syntactic_punctuation_marker`

use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::shape::looks_like_syntactic_punctuation_marker;
use keyhog_scanner::testing::{
    is_canonical_service_hex_key, known_example_suppressed, looks_like_standard_base64_blob,
    named_detector_suppressed,
};

// ─────────────────────────────────────────────────────────────────────────────
// Known-example stage: placeholder / doc-marker / template / RFC-specimen paths.
// ─────────────────────────────────────────────────────────────────────────────

/// A value carrying the `placeholder` Tier-B word (word-bounded) is a documented
/// sample, never a production secret — the known-example stage suppresses it.
#[test]
fn placeholder_word_value_is_suppressed() {
    assert!(
        known_example_suppressed("config_placeholder_here", None, CodeContext::Documentation),
        "a bounded `placeholder` word marks a sample and must suppress"
    );
}

/// Negative twin: a realistic random Stripe live-secret with a genuine service
/// prefix and a high-entropy body is positive evidence and must NOT be dropped.
#[test]
fn real_stripe_live_secret_is_not_suppressed() {
    assert!(
        !known_example_suppressed(
            "sk_live_51HbY2klWn9RtsZ4uVx7mQ3p",
            None,
            CodeContext::Assignment,
        ),
        "a real prefixed random secret must survive the suppression tree"
    );
}

/// A `{{var}}` template placeholder (brace-wrapped, <= 80 bytes) is never the
/// delivery form of a real credential — the `template_placeholder` gate fires.
#[test]
fn double_brace_template_variable_is_suppressed() {
    assert!(
        known_example_suppressed("{{server_region}}", None, CodeContext::Unknown),
        "a `{{var}}` template wrapper must suppress"
    );
}

/// Negative twin for the template gate: an ordinary alphanumeric identifier with
/// no brace wrapper is not a template placeholder and stays a live candidate.
#[test]
fn unwrapped_identifier_is_not_template_suppressed() {
    assert!(
        !known_example_suppressed("serverRegionToken9xQ", None, CodeContext::Assignment),
        "an unwrapped identifier must not hit the template gate"
    );
}

/// A doc-marker substring (`redacted`) buried inside a service-prefixed token is
/// caught by the plain-substring marker scan BEFORE the known-prefix Allow path.
#[test]
fn embedded_doc_marker_substring_is_suppressed() {
    assert!(
        known_example_suppressed("ghp_redacted_value_123", None, CodeContext::Unknown),
        "an embedded `redacted` doc marker must suppress even inside a ghp_ token"
    );
}

/// A developer marker (`TODO`, word-bounded) overrides provider-prefix trust and
/// suppresses via the `dev_marker_todo_fixme` arm.
#[test]
fn dev_marker_todo_is_suppressed() {
    assert!(
        known_example_suppressed("abc_TODO_xyz123", None, CodeContext::Comment),
        "a bounded TODO developer marker must suppress"
    );
}

/// A PEM-framed private key gets a hard bypass: the `-----BEGIN` frame is the
/// high-confidence signal, so the body-entropy / repetition heuristics never run
/// and the key is NOT suppressed.
#[test]
fn pem_framed_private_key_is_not_suppressed() {
    let pem = "-----BEGIN EC PRIVATE KEY-----\n\
               MHcCAQEEIODqBrJvUvf5k2Lm9QzRt4uVx7mNbPdFhSj\n\
               -----END EC PRIVATE KEY-----";
    assert!(
        !known_example_suppressed(pem, None, CodeContext::Unknown),
        "a PEM-framed key must bypass the shape heuristics and survive"
    );
}

/// The RFC 7519 specimen JWT (the copy-pasted `\"sub\":\"1234567890` example) is
/// suppressed by the literal-prefix `rfc7519_example_jwt` gate.
#[test]
fn rfc7519_specimen_jwt_is_suppressed() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
               eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.\
               SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    assert!(
        known_example_suppressed(jwt, None, CodeContext::Unknown),
        "the RFC 7519 example JWT must suppress"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Tier-A vs Tier-B split: same value, generic vs service-anchored detector.
// ─────────────────────────────────────────────────────────────────────────────

const UUID_V4: &str = "550e8400-e29b-41d4-a716-446655440000";

/// Under a GENERIC (unanchored) detector, a bare UUID v4 is noise and the
/// Tier-B `contains_uuid_v4` gate suppresses it.
#[test]
fn generic_detector_suppresses_bare_uuid() {
    assert!(
        named_detector_suppressed(UUID_V4, None, CodeContext::Unknown, None, "generic-secret"),
        "generic-secret has no service anchor, so a bare UUID must suppress"
    );
}

/// Negative twin: under a SERVICE-ANCHORED detector the same UUID is positive
/// evidence (powerbi/heroku/codecov use UUID bodies), so the Tier-B UUID gate is
/// bypassed and the finding is KEPT.
#[test]
fn service_anchored_detector_keeps_bare_uuid() {
    assert!(
        !named_detector_suppressed(UUID_V4, None, CodeContext::Unknown, None, "aws-access-key"),
        "a service-anchored detector must keep the UUID it fingerprinted"
    );
}

// A 40-char standard-base64 blob (has `/`, length multiple of 4). This is the
// base64-protobuf FP shape — the single largest generic-detector FP class.
const SLASH_B64_BLOB: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzT9k2LmQ8p";

/// A generic detector drops the standard-base64 blob via the `base64_blob` gate.
#[test]
fn generic_detector_suppresses_standard_base64_blob() {
    assert!(
        named_detector_suppressed(
            SLASH_B64_BLOB,
            None,
            CodeContext::Unknown,
            None,
            "generic-secret"
        ),
        "an unanchored base64 blob must be suppressed as protobuf-shaped noise"
    );
}

/// Negative twin: a service-anchored detector proved these bytes ARE the
/// credential (`AWS_SECRET_ACCESS_KEY=<blob>`), so the b64-blob gate is bypassed.
#[test]
fn service_anchored_detector_keeps_standard_base64_blob() {
    assert!(
        !named_detector_suppressed(
            SLASH_B64_BLOB,
            None,
            CodeContext::Unknown,
            None,
            "aws-access-key"
        ),
        "a service-anchored base64 secret must survive the b64-blob gate"
    );
}

/// Tier-A universality: a pure syntactic marker (`--flag`) is never a credential
/// body, so it suppresses even under a strong service-anchored detector.
#[test]
fn syntactic_flag_marker_suppresses_even_for_service_anchored_detector() {
    assert!(
        named_detector_suppressed(
            "--api-secret",
            None,
            CodeContext::Unknown,
            None,
            "aws-access-key"
        ),
        "a `--flag` grammar marker is Tier-A and must suppress for any detector"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Source-type driven suppression: native binary-strings extraction.
// ─────────────────────────────────────────────────────────────────────────────

const OPENAI_SHAPED: &str = "sk-proj-Xy9kLm2Qw";

/// A short-prefix detector firing on printable strings extracted from a compiled
/// binary is noise — the `native_binary_strings` source gate suppresses it.
#[test]
fn binary_strings_source_suppresses_named_finding() {
    assert!(
        named_detector_suppressed(
            OPENAI_SHAPED,
            None,
            CodeContext::Unknown,
            Some("filesystem:binary-strings"),
            "openai-api-key",
        ),
        "a prefix match inside extracted binary strings must suppress"
    );
}

/// Negative twin: the identical value/detector on an ordinary filesystem source
/// (no binary-strings marker) is NOT suppressed by the binary gate.
#[test]
fn ordinary_filesystem_source_keeps_named_finding() {
    assert!(
        !named_detector_suppressed(
            OPENAI_SHAPED,
            None,
            CodeContext::Unknown,
            Some("filesystem"),
            "openai-api-key",
        ),
        "the same value from an ordinary filesystem source must survive"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Direct shape-classifier pins (the predicates the decisions above rely on).
// ─────────────────────────────────────────────────────────────────────────────

/// The 40-char `/`-bearing value is classified as a standard-base64 blob.
#[test]
fn standard_base64_blob_shape_is_recognized() {
    assert!(
        looks_like_standard_base64_blob(SLASH_B64_BLOB),
        "40-char standard base64 with `/` must classify as a blob"
    );
}

/// Boundary: a value shorter than the 40-byte floor is NOT a blob.
#[test]
fn short_value_is_not_a_standard_base64_blob() {
    assert!(
        !looks_like_standard_base64_blob("shorttoken"),
        "a 10-char value is below the 40-byte blob floor"
    );
}

/// A canonical-length (32) uniform-lowercase pure-hex value is a service hex key.
#[test]
fn canonical_service_hex_key_32_lowercase_is_recognized() {
    assert!(
        is_canonical_service_hex_key("0123456789abcdef0123456789abcdef"),
        "32-char uniform-lowercase hex is a canonical service key shape"
    );
}

/// Adversarial: MiXeD-case hex is rejected (real digests are single-case), so the
/// bare-hex-digest exemption does not apply to it.
#[test]
fn mixed_case_hex_is_not_a_canonical_service_hex_key() {
    assert!(
        !is_canonical_service_hex_key("0123456789ABCDEF0123456789abcdef"),
        "mixed-case hex must fail the uniform-case requirement"
    );
}

/// Boundary: a 31-char hex string is not a canonical key length (32/40/48/64).
#[test]
fn wrong_length_hex_is_not_a_canonical_service_hex_key() {
    assert!(
        !is_canonical_service_hex_key("0123456789abcdef0123456789abcde"),
        "31 is not one of the canonical service-hex-key lengths"
    );
}

/// A CLI double-dash flag (`--X`) is a syntactic punctuation marker.
#[test]
fn cli_double_dash_flag_is_syntactic_marker() {
    assert!(
        looks_like_syntactic_punctuation_marker("--api-secret"),
        "`--api-secret` is a CLI flag grammar marker"
    );
}

/// Boundary: a PEM `-----BEGIN` dash run is NOT a `--flag` marker (bytes[2] is
/// another dash), so a private-key block header is not mis-flagged.
#[test]
fn pem_dash_run_is_not_syntactic_marker() {
    assert!(
        !looks_like_syntactic_punctuation_marker("-----BEGIN"),
        "a 5-dash PEM marker must not be treated as a `--flag`"
    );
}

/// A trailing-colon label (`Password:`) over an identifier prefix is a syntactic
/// marker, never a credential body.
#[test]
fn trailing_colon_label_is_syntactic_marker() {
    assert!(
        looks_like_syntactic_punctuation_marker("Password:"),
        "`Password:` is a label marker, not a secret body"
    );
}
