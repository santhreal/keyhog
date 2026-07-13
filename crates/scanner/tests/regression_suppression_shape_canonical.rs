//! Regression coverage for the EXAMPLE / doc-marker "canonical carveout" in the
//! suppression cascade (`crates/scanner/src/suppression/doc_markers.rs`, driven
//! through `suppression/decision.rs::suppression_stage_inner`).
//!
//! The carveout has three moving parts that this file pins by their EXACT
//! `&'static str` suppression-stage reason (never `is_suppressed`-only):
//!   1. A documented AWS/GitHub EXAMPLE token (`AKIA…EXAMPLE`, `…_EXAMPLE_…`,
//!      `EXAMPLEKEY…`) suppresses via the `contains_EXAMPLE_token` example arm.
//!   2. A doc-marker substring buried inside a service-prefixed token
//!      (`ghp_exampleToken…`, `…redacted…`, `…notareal…`) suppresses via the
//!      `doc_marker_substring` arm, which runs BEFORE the known-prefix Allow
//!      fast-path.
//!   3. The reserved-domain carve-out is EXACT: a real secret sitting beside an
//!      `example.com` / `example.org` mention is SPARED (both EXAMPLE arms are
//!      skipped, so a `ghp_`/`sk_live_` token survives via Allow), yet a bare
//!      `example`-word boundary with any OTHER trailing punctuation still fires.
//!
//! The reason string is observed over the PUBLIC dogfood telemetry surface
//! (`keyhog_scanner::telemetry`): a scoped `ScanTelemetry` is installed on this
//! thread via `with_scan_telemetry`, so events route into a thread-local buffer
//! (no process-global mutation, no cross-test serialization needed). The example
//! arm is recorded as `ExampleSuppressed`, every other gate as `ShapeSuppressed`;
//! `drain_reasons` flattens both so the FIRST recorded reason is the
//! authoritative gate that fired (the cascade short-circuits).

use std::sync::Arc;

use keyhog_scanner::context::CodeContext;
use keyhog_scanner::telemetry::{with_scan_telemetry, DogfoodEvent, ScanTelemetry};
use keyhog_scanner::testing::{
    is_canonical_service_hex_key, known_example_suppressed, looks_like_standard_base64_blob,
};

/// Run the known-example suppression stage for `credential` under a scoped
/// dogfood telemetry buffer, returning `(suppressed, reasons_in_recorded_order)`.
fn suppressed_with_reasons(credential: &str) -> (bool, Vec<String>) {
    let trace = Arc::new(ScanTelemetry::new());
    trace.enable_dogfood();
    let suppressed = with_scan_telemetry(&trace, || {
        known_example_suppressed(credential, None, CodeContext::Unknown)
    });
    let reasons = trace
        .drain()
        .dogfood_events
        .into_iter()
        .map(|event| match event {
            DogfoodEvent::ShapeSuppressed { reason, .. }
            | DogfoodEvent::ExampleSuppressed { reason, .. } => reason.into_owned(),
        })
        .collect();
    (suppressed, reasons)
}

/// Assert `credential` is suppressed AND the FIRST recorded gate reason is
/// exactly `expected_reason`.
fn assert_suppressed_reason(credential: &str, expected_reason: &str) {
    let (suppressed, reasons) = suppressed_with_reasons(credential);
    assert!(
        suppressed,
        "{credential:?} must be suppressed (expected gate {expected_reason:?})"
    );
    assert_eq!(
        reasons.first().map(String::as_str),
        Some(expected_reason),
        "{credential:?}: first suppression gate must be {expected_reason:?}, trace was {reasons:?}"
    );
}

/// Assert `credential` is NOT suppressed and emits NO suppression event (a real
/// secret must survive the carveout without a spurious gate firing).
fn assert_kept(credential: &str) {
    let (suppressed, reasons) = suppressed_with_reasons(credential);
    assert!(
        !suppressed,
        "real secret {credential:?} was WRONGLY suppressed by gate(s) {reasons:?}"
    );
    assert!(
        reasons.is_empty(),
        "real secret {credential:?} survived but a gate recorded {reasons:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. EXAMPLE-token example arm → `contains_EXAMPLE_token`.
// ─────────────────────────────────────────────────────────────────────────────

/// The canonical AWS documentation access key ends with `EXAMPLE`, caught by the
/// `upper.ends_with(EXAMPLE)` branch of the example arm.
#[test]
fn aws_example_access_key_suppresses_as_contains_example_token() {
    assert_suppressed_reason("AKIAIOSFODNN7EXAMPLE", "contains_EXAMPLE_token");
}

/// A `_EXAMPLE_`-word-bounded marker inside a `ghp_` token fires the
/// word-boundary `upper_contains_token(EXAMPLE)` branch (before the `ghp_` Allow
/// fast-path can rescue it).
#[test]
fn word_bounded_example_inside_ghp_token_suppresses_as_contains_example_token() {
    assert_suppressed_reason(
        "ghp_THIS_IS_AN_EXAMPLE_TOKEN_VALUE",
        "contains_EXAMPLE_token",
    );
}

/// A leading `EXAMPLEKEY` (its own dedicated literal branch, distinct from the
/// bare `EXAMPLE` word) suppresses as the example arm.
#[test]
fn examplekey_prefix_suppresses_as_contains_example_token() {
    assert_suppressed_reason("EXAMPLEKEY_abc123def456ghij", "contains_EXAMPLE_token");
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Doc-marker substring arm → `doc_marker_substring` (runs before Allow).
// ─────────────────────────────────────────────────────────────────────────────

/// `example` embedded WITHOUT a trailing word boundary (`exampleToken…`) escapes
/// the word-bounded example arm but is caught by the plain-substring doc-marker
/// scan, which runs before the `ghp_` known-prefix Allow.
#[test]
fn embedded_example_substring_suppresses_as_doc_marker_substring() {
    assert_suppressed_reason("ghp_exampleTokenValue1234ABCD", "doc_marker_substring");
}

/// The `redacted` Tier-B marker buried inside a service-prefixed token is a
/// doc-marker substring, not an example token.
#[test]
fn redacted_marker_inside_ghp_token_suppresses_as_doc_marker_substring() {
    assert_suppressed_reason("ghp_redacted_token_value1234", "doc_marker_substring");
}

/// The `notareal` marker (no separators) is a doc-marker substring; `secret` in
/// the same value is deliberately NOT a placeholder word, so the substring arm
/// not the placeholder-word arm (is the one that fires).
#[test]
fn notareal_marker_suppresses_as_doc_marker_substring() {
    assert_suppressed_reason("token_notareal_secret_abcdef", "doc_marker_substring");
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Negative twins: a real token of the SAME shape must NOT be suppressed.
// ─────────────────────────────────────────────────────────────────────────────

/// Same 20-char `AKIA…` shape as the documentation key but WITHOUT the `EXAMPLE`
/// suffix (a real access key body, kept via the known-prefix Allow).
#[test]
fn real_aws_access_key_without_example_is_kept() {
    assert_kept("AKIAJ7QK2MZ4XR8WNP6D");
}

/// A real `ghp_` PAT with a high-entropy body and no marker substring is positive
/// evidence and survives (the doc-marker scan finds nothing, then Allow fires).
#[test]
fn real_ghp_token_without_marker_is_kept() {
    assert_kept("ghp_J8kZq2WxX9nP4rT6yV1bC3dF5gH7jKaLmNo");
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Reserved-domain carve-out is EXACT.
// ─────────────────────────────────────────────────────────────────────────────

/// `example.com` is an RFC 2606 reserved domain: a real `ghp_` secret sitting
/// beside such a mention must NOT be over-suppressed. The `.com` guard skips BOTH
/// the word-bounded example arm and the doc-marker substring arm, so the token
/// reaches the known-prefix Allow and survives, even though a bare `example`
/// word boundary is present.
#[test]
fn reserved_example_com_domain_spares_real_ghp_secret() {
    assert_kept("ghp_example.com_9f3K2pQ7mZ1tR8vN");
}

/// The `.org` sibling of the reserved-domain guard is likewise exact: a real
/// `sk_live_` secret beside an `example.org` mention survives.
#[test]
fn reserved_example_org_domain_spares_real_stripe_secret() {
    assert_kept("sk_live_project_example.org_9f3K2pQ7mZ1tR8");
}

/// Adversarial boundary proving the carve-out is NOT a blanket "contains
/// example" pass: the SAME `ghp_example…` shape with a NON-domain trailing
/// separator (`-` instead of `.com`) has no reserved-domain mention, so the
/// word-bounded example arm still fires and suppresses.
#[test]
fn bare_example_word_without_reserved_domain_still_suppresses() {
    assert_suppressed_reason("ghp_example-9f3K2pQ7mZ1tR8vN", "contains_EXAMPLE_token");
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Direct shape-classifier pins the carveout decisions rely on.
// ─────────────────────────────────────────────────────────────────────────────

/// A canonical-length (32) uniform-lowercase pure-hex value is a service hex key;
/// a 31-char value is off the canonical length set (32/40/48/64) and is not.
#[test]
fn canonical_service_hex_key_length_boundary() {
    assert!(
        is_canonical_service_hex_key("0123456789abcdef0123456789abcdef"),
        "32-char uniform-lowercase hex is a canonical service hex key"
    );
    assert!(
        !is_canonical_service_hex_key("0123456789abcdef0123456789abcde"),
        "31 chars is not a canonical service-hex-key length"
    );
}

/// Mixed-case hex is rejected as a canonical service hex key (real digests are
/// single-case), so the bare-hex-digest exemption never applies to it.
#[test]
fn mixed_case_hex_is_not_a_canonical_service_hex_key() {
    assert!(
        !is_canonical_service_hex_key("0123456789ABCDEF0123456789abcdef"),
        "mixed-case hex must fail the uniform-case requirement"
    );
}

/// A 40-char standard-base64 value carrying a `/` classifies as a base64 blob
/// (the largest generic FP shape), while a 10-char value is below the blob floor.
#[test]
fn standard_base64_blob_shape_length_boundary() {
    assert!(
        looks_like_standard_base64_blob("wJalrXUtnFEMI/K7MDENG/bPxRfiCYzT9k2LmQ8p"),
        "40-char standard base64 with `/` is a blob shape"
    );
    assert!(
        !looks_like_standard_base64_blob("shorttoken"),
        "a 10-char value is below the base64-blob floor"
    );
}
