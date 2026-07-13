//! Regression coverage for the doc/placeholder/marker pre-checks in
//! `crates/scanner/src/suppression/doc_markers.rs` (`check_markers`).
//!
//! `check_markers` is the FIRST arm of `suppression_stage_inner`, so the FIRST
//! dogfood suppression event emitted by the public
//! `keyhog_scanner::testing::known_example_suppressed` entry point is exactly
//! the `MarkerVerdict::Suppress(reason)` this module chose (or, for a
//! `MarkerVerdict::Allow` / `KeepChecking`, no marker event at all). Each test
//! pins the LITERAL `&'static str` reason (Law 6, an exact value, never
//! `is_ok`/`!is_empty`) so a renamed / reordered / removed marker arm flips a
//! specific named row red instead of passing silently.
//!
//! Telemetry routing is thread-local: `enable_dogfood()` on a per-test
//! `ScanTelemetry` handle installed with `with_scan_telemetry` keeps every
//! `#[test]` isolated, so no process-global reset or serial lock is needed and
//! the file is safe under cargo's default parallel test runner.
//!
//! The reason literals asserted here are the ones emitted by
//! `suppression/doc_markers.rs` (`contains_EXAMPLE_token`, `instructional_fragment`,
//! `dev_marker_todo_fixme`, `rfc7519_example_jwt`, `doc_marker_substring`,
//! `placeholder_word`) plus the `mask_run_xxxxx` shape gate that lives in
//! `suppression/decision.rs` (asserted as a NEGATIVE ownership boundary: the
//! `xxxxx` mask is NOT a doc-marker).

use keyhog_scanner::context::CodeContext;
use keyhog_scanner::telemetry::{self, DogfoodEvent, ScanTelemetry};
use keyhog_scanner::testing::known_example_suppressed;
use std::sync::Arc;

/// The literal RFC 7519 example JWT from the spec. `check_markers` suppresses
/// any credential that CONTAINS the 61-char prefix
/// (`eyJhbGci….eyJzdWIiOiIxMjM0NTY3ODkw`). Inlined because the crate-internal
/// `RFC7519_EXAMPLE_JWT_PREFIX` const is `pub(crate)` and not visible here.
const RFC7519_EXAMPLE_JWT: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.\
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

/// Run one credential through the suppression cascade with a scoped dogfood
/// trace and return `(suppressed, first_reason_or_none)`. The cascade
/// short-circuits, so the first recorded reason is the authoritative gate.
fn suppress_and_first_reason(credential: &str) -> (bool, Option<String>) {
    let trace = Arc::new(ScanTelemetry::new());
    trace.enable_dogfood();
    let suppressed = telemetry::with_scan_telemetry(&trace, || {
        known_example_suppressed(credential, None, CodeContext::Unknown)
    });
    let first = trace
        .drain()
        .dogfood_events
        .into_iter()
        .filter_map(|event| match event {
            DogfoodEvent::ShapeSuppressed { reason, .. }
            | DogfoodEvent::ExampleSuppressed { reason, .. } => Some(reason.into_owned()),
            DogfoodEvent::StaticRecoveryRejected { .. } => None,
        })
        .next();
    (suppressed, first)
}

/// Assert `credential` is suppressed AND the first gate reason is exactly
/// `expected_reason`.
fn assert_reason(credential: &str, expected_reason: &str) {
    let (suppressed, first) = suppress_and_first_reason(credential);
    assert!(
        suppressed,
        "{credential:?} must be suppressed (expected gate {expected_reason:?})"
    );
    let first = first.unwrap_or_else(|| {
        panic!(
            "{credential:?} suppressed but emitted NO dogfood reason, a silent gate (Law 10); \
             expected {expected_reason:?}"
        )
    });
    assert_eq!(
        first, expected_reason,
        "{credential:?}: first suppression gate must be {expected_reason:?}"
    );
}

/// Assert `credential` is NOT suppressed and records NO suppression event.
fn assert_not_suppressed(credential: &str) {
    let (suppressed, first) = suppress_and_first_reason(credential);
    assert!(
        !suppressed,
        "{credential:?} was WRONGLY suppressed by gate {first:?}, recall regression"
    );
    assert_eq!(
        first, None,
        "{credential:?} not suppressed yet a gate recorded {first:?}, spurious event"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// EXAMPLE arm: word-boundary token OR ends_with, vs the plain-`contains`
// doc-marker arm. The distinction is load-bearing and produces DIFFERENT reasons.
// ─────────────────────────────────────────────────────────────────────────────

/// An `EXAMPLE` glued INTERIOR to a token (no word boundary, not at the end)
/// misses the boundary/`ends_with` EXAMPLE arm and is instead caught by the
/// plain-substring `doc_marker_substring` arm. This is the exact
/// `contains`-vs-boundary split the module documents.
#[test]
fn interior_glued_example_takes_doc_marker_substring_not_example_token() {
    assert_reason("ghp_MYEXAMPLEKEYvalue", "doc_marker_substring");
}

/// A word-boundary `EXAMPLE` (surrounded by `_`) fires the EXAMPLE special-case
/// arm with the `contains_EXAMPLE_token` reason (recorded as an example
/// suppression, not a generic shape event).
#[test]
fn word_boundary_example_token_reason() {
    assert_reason("ghp_EXAMPLE_TOKEN_VALUE", "contains_EXAMPLE_token");
}

/// The classic AWS docs key ends in `EXAMPLE` glued to a digit, so the
/// boundary-`contains` test fails but the `ends_with("EXAMPLE")` arm catches it:
/// still `contains_EXAMPLE_token`.
#[test]
fn ends_with_example_reason_aws_docs_key() {
    assert_reason("AKIAIOSFODNN7EXAMPLE", "contains_EXAMPLE_token");
    // Bare (no known prefix) ends_with form is caught the same way.
    assert_reason("randomvendortokenvalueEXAMPLE", "contains_EXAMPLE_token");
}

/// The dedicated `EXAMPLEKEY` boundary/`ends_with` arm: a token ending in a
/// word-boundary `EXAMPLEKEY` fires `contains_EXAMPLE_token` even though a bare
/// `EXAMPLE` boundary-token match fails (the trailing `KEY` breaks the right
/// boundary).
#[test]
fn examplekey_boundary_suffix_reason() {
    assert_reason("sk_test_EXAMPLEKEY", "contains_EXAMPLE_token");
}

// ─────────────────────────────────────────────────────────────────────────────
// Instructional fragments: leading-word-boundary required.
// ─────────────────────────────────────────────────────────────────────────────

/// `YOUR_` and `CHANGE` fragments at a leading word boundary suppress with the
/// `instructional_fragment` reason.
#[test]
fn instructional_fragments_with_leading_boundary() {
    assert_reason("YOUR_API_KEY_HERE_put_here", "instructional_fragment");
    assert_reason("CHANGE_THIS_SECRET_value_here", "instructional_fragment");
}

/// NEGATIVE twin: the SAME `your_` fragment glued after an alphanumeric char
/// (`beyour_`) has NO leading word boundary, so the instructional arm does not
/// fire; the clean `ghp_` body then takes the known-prefix `Allow` and the
/// value is NOT suppressed.
#[test]
fn instructional_fragment_requires_leading_boundary() {
    assert_not_suppressed("ghp_beyour_apitoken99abcd");
}

// ─────────────────────────────────────────────────────────────────────────────
// Developer markers override provider-prefix trust.
// ─────────────────────────────────────────────────────────────────────────────

/// `TODO` and `FIXME` at a word boundary suppress with `dev_marker_todo_fixme`.
/// The credentials deliberately avoid instructional fragments so this arm (which
/// runs after them) is the one that fires.
#[test]
fn dev_marker_todo_and_fixme() {
    assert_reason("TODO_fill_in_the_secret_here_42", "dev_marker_todo_fixme");
    assert_reason("api_key_FIXME_before_deploy_77", "dev_marker_todo_fixme");
}

// ─────────────────────────────────────────────────────────────────────────────
// RFC 7519 example JWT: prefix-OR-substring (`contains`), not just `starts_with`.
// ─────────────────────────────────────────────────────────────────────────────

/// The full spec JWT (which STARTS with the prefix) and a `contains`-only form
/// (`auth_token=<jwt>`, where the prefix is buried after `=`) both suppress with
/// `rfc7519_example_jwt`. The `contains` form is the one a plain `starts_with`
/// would miss.
#[test]
fn rfc7519_example_jwt_prefix_and_contains() {
    assert_reason(RFC7519_EXAMPLE_JWT, "rfc7519_example_jwt");
    let embedded = format!("auth_token={RFC7519_EXAMPLE_JWT}");
    assert_reason(&embedded, "rfc7519_example_jwt");
}

// ─────────────────────────────────────────────────────────────────────────────
// Plain-substring doc markers (`marker_substrings` Tier-B list).
// ─────────────────────────────────────────────────────────────────────────────

/// Distinct `marker_substrings` entries (`not_a_real`, `redacted`) buried inside
/// service-prefixed / keyworded tokens fire `doc_marker_substring` via plain
/// `contains` (no word boundary needed).
#[test]
fn doc_marker_substring_specific_markers() {
    assert_reason("ghp_not_a_real_token_abc123", "doc_marker_substring");
    assert_reason("api_REDACTED_secret_value", "doc_marker_substring");
}

// ─────────────────────────────────────────────────────────────────────────────
// Precedence: the placeholder-WORD arm runs before the doc-marker substring arm,
// even though `placeholder` appears in BOTH vocabularies.
// ─────────────────────────────────────────────────────────────────────────────

/// A word-boundary `PLACEHOLDER` (or `DUMMY`) hits the step-1 placeholder-word
/// arm first, so the reason is `placeholder_word`, NOT `doc_marker_substring`
/// (which also lists `placeholder`). This pins the arm ordering.
#[test]
fn placeholder_word_arm_precedes_doc_marker_substring() {
    assert_reason("config_PLACEHOLDER_value_x", "placeholder_word");
    assert_reason("DUMMY_TOKEN_VALUE_abc123def456", "placeholder_word");
}

// ─────────────────────────────────────────────────────────────────────────────
// TESTKEY_ adversarial carve-out: the `TESTKEY`/`TEST_KEY` markers are skipped
// ONLY when the credential itself starts with `TESTKEY_`.
// ─────────────────────────────────────────────────────────────────────────────

/// A credential that STARTS with `TESTKEY_` is exempt from the `TESTKEY` doc
/// marker (it falls through to the repetitive-mask gates), so a high-entropy
/// body is NOT suppressed. Its twin `aTESTKEY_…` (does NOT start with the exact
/// `TESTKEY_` prefix) is NOT exempt and suppresses with `doc_marker_substring`.
#[test]
fn testkey_prefix_carveout_exact_prefix_only() {
    assert_not_suppressed("TESTKEY_9f3K2pQ7mZ1tR8vN4wL6yH0cB5dG2j");
    assert_reason(
        "aTESTKEY_9f3K2pQ7mZ1tR8vN4wL6yH0cB5dG2j",
        "doc_marker_substring",
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Reserved-domain carve-out: an EXAMPLE.COM / EXAMPLE.ORG mention disables BOTH
// the EXAMPLE arm and the doc-marker substring arm (RFC 2606 reserved domain).
// ─────────────────────────────────────────────────────────────────────────────

/// `ghp_EXAMPLE_TOKEN` is suppressed (`contains_EXAMPLE_token`), but the SAME
/// prefix with `EXAMPLE` as a reserved documentation domain
/// (`EXAMPLE.COM` / `EXAMPLE.ORG`) is NOT suppressed, the carve-out prevents
/// over-suppressing a real secret sitting beside a reserved-domain mention.
#[test]
fn reserved_example_domain_carveout() {
    assert_reason("ghp_EXAMPLE_TOKEN", "contains_EXAMPLE_token");
    assert_not_suppressed("ghp_EXAMPLE.COM_KEY");
    assert_not_suppressed("ghp_EXAMPLE.ORG_KEY");
}

/// NEGATIVE twin for the substring markers: a near-miss substring (`EXAM`
/// inside `EXAMination`) is NOT the `example` marker and does NOT suppress; the
/// clean `ghp_` body takes the known-prefix `Allow`.
#[test]
fn near_miss_substring_is_not_a_marker() {
    assert_not_suppressed("ghp_EXAMinationToken1234abcd");
}

/// Real service-prefixed secrets carrying no marker are NOT suppressed by the
/// doc-marker pre-checks (they exit via the known-prefix `Allow`). Recall twin
/// for every positive above.
#[test]
fn real_prefixed_secrets_not_marker_suppressed() {
    assert_not_suppressed("ghp_J8kZq2WxX9nP4rT6yV1bC3dF5gH7jKaLmNo");
    assert_not_suppressed("xoxb-9f3K2pQ7mZ1tR8vN4wL6yH0cB5dG2jE");
    assert_not_suppressed("Tr0ub4dor&3xK9!mZqWvP");
}

/// Ownership boundary: the `xxxxx` mask run is NOT a doc marker, it belongs to
/// `suppression/decision.rs` §3. A token with no doc marker passes through
/// `check_markers` (KeepChecking) and is suppressed downstream with the distinct
/// `mask_run_xxxxx` reason, proving the doc-marker module does not own it.
#[test]
fn xxxxx_mask_run_is_a_shape_gate_not_a_doc_marker() {
    assert_reason("api_keyXXXXXXXXXXXXXXXXXmasked", "mask_run_xxxxx");
}
