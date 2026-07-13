//! LANE-4 detection-truth: pin the EXACT dogfood `reason` string the
//! suppression cascade emits for each placeholder / example / shape class, over
//! the public `keyhog_scanner::testing::known_example_suppressed` entry
//! point.
//!
//! Dogfood's hot-path flag is process-global, so this file takes the shared
//! unit telemetry lock and records events into scoped telemetry rather than the
//! process-global event buffer. This is the COMPANION to the parallel bool-only
//! matrices in `suppression_truth_table.rs`: those pin "suppressed / not", this
//! pins WHICH gate did it by its literal `&'static str` reason, so a renamed /
//! reordered / removed cascade arm flips a specific named row red rather than
//! passing silently (Law 6 (exact value, never `is_ok`/`!is_empty`)).
//!
//! The reason strings are the literals emitted by
//! `crates/scanner/src/suppression/decision.rs` and `suppression/doc_markers.rs`.

use keyhog_scanner::context::CodeContext;
use keyhog_scanner::telemetry::{self, DogfoodEvent, ScanTelemetry};
use keyhog_scanner::testing::known_example_suppressed;
use std::sync::Arc;

/// Drain the dogfood trace and return every suppression reason (example OR
/// shape), in recorded order. The cascade short-circuits, so the FIRST reason
/// is the authoritative gate that fired.
fn drain_reasons(trace: &ScanTelemetry) -> Vec<String> {
    trace
        .drain()
        .dogfood_events
        .into_iter()
        .filter_map(|e| match e {
            DogfoodEvent::ShapeSuppressed { reason, .. }
            | DogfoodEvent::ExampleSuppressed { reason, .. } => Some(reason.into_owned()),
            DogfoodEvent::StaticRecoveryRejected { .. } => None,
        })
        .collect()
}

/// Assert `credential` is suppressed AND the first recorded reason is exactly
/// `expected_reason`. Drains so each case starts clean.
fn assert_reason(credential: &str, expected_reason: &str) {
    let trace = Arc::new(ScanTelemetry::new());
    telemetry::testing::reset();
    trace.enable_dogfood();
    let suppressed = telemetry::with_scan_telemetry(&trace, || {
        known_example_suppressed(credential, None, CodeContext::Unknown)
    });
    assert!(
        suppressed,
        "{credential:?} must be suppressed (expected gate: {expected_reason})"
    );
    let reasons = drain_reasons(&trace);
    assert!(
        !reasons.is_empty(),
        "{credential:?} suppressed but emitted NO dogfood reason, a silent gate \
         (Law 10). Expected {expected_reason:?}."
    );
    assert_eq!(
        reasons[0], expected_reason,
        "{credential:?}: first suppression gate must be {expected_reason:?}, trace was {reasons:?}"
    );
}

/// Assert `credential` is NOT suppressed and emits NO suppression event.
fn assert_not_suppressed(credential: &str) {
    let trace = Arc::new(ScanTelemetry::new());
    telemetry::testing::reset();
    trace.enable_dogfood();
    let suppressed = telemetry::with_scan_telemetry(&trace, || {
        known_example_suppressed(credential, None, CodeContext::Unknown)
    });
    let reasons = drain_reasons(&trace);
    assert!(
        !suppressed,
        "REAL secret {credential:?} was WRONGLY suppressed by gate(s) {reasons:?}, recall regression"
    );
    assert!(
        reasons.is_empty(),
        "REAL secret {credential:?} not suppressed but a gate recorded {reasons:?}, spurious event"
    );
}

/// `(credential, exact gate reason)`: each row pins the precise cascade arm.
const REASON_TABLE: &[(&str, &str)] = &[
    // placeholder words (shared Tier-B vocabulary, recorded as a shape gate)
    ("DUMMY_TOKEN_VALUE_abc123def456", "placeholder_word"),
    ("xPLACEHOLDER_value_notrealkey99", "placeholder_word"),
    ("this_is_a_FAKE_secret_value_009", "placeholder_word"),
    ("MOCK_API_TOKEN_for_unit_tests_4", "placeholder_word"),
    ("SAMPLE_KEY_do_not_use_in_prod_7", "placeholder_word"),
    ("PLEASE_CHANGEME_secret_value_009", "placeholder_word"),
    // EXAMPLE token (doc_markers EXAMPLE special-case, recorded as example suppression)
    ("AKIAIOSFODNN7EXAMPLE", "contains_EXAMPLE_token"),
    (
        "ghp_THIS_IS_AN_EXAMPLE_TOKEN_VALUE",
        "contains_EXAMPLE_token",
    ),
    // mask run (decision.rs §3)
    ("api_keyXXXXXXXXXXXXXXXXXXXXmasked", "mask_run_xxxxx"),
    // bare hex digests (decision.rs §5b): 32/40/64-hex
    ("a1c3e5f7091b2d4f60718293a4b5c6d7", "bare_hex_digest"),
    (
        "a1b2c3d4e5f60718293a4b5c6d7e8f9012345abc",
        "bare_hex_digest",
    ),
    (
        "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0",
        "bare_hex_digest",
    ),
    // labelled hash digest (decision.rs §5b, prefixed form)
    (
        "sha256:0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0",
        "labelled_hash_digest",
    ),
    // UUID v4 (decision.rs §5b)
    ("1f48cec7-bbee-4eb7-8e35-3bc1e7a0f2c2", "uuid_v4_shape"),
    ("a987fbc9-4bed-4078-8f07-9141ba07c9f3", "uuid_v4_shape"),
    // dashed serial / product key (decision.rs §5c)
    ("ABCDE-FGHIJ-KLMNO-PQRST-UVWXY", "dashed_serial_key"),
    ("Q7R9T-2K4M6-N8P0X-W3Y5Z-A1B2C", "dashed_serial_key"),
    // HTML colour (decision.rs §5e2)
    ("#a1b2c3", "html_color"),
    ("#ABCDEF", "html_color"),
    ("#0f0", "html_color"),
    // AWS IAM ARN (decision.rs §5e1)
    (
        "arn:aws:iam::123456789012:role/MyServiceRole",
        "aws_iam_arn",
    ),
    ("arn:aws:iam::123456789012:user/some.person", "aws_iam_arn"),
];

/// REAL secrets that must NOT be suppressed and must emit NO event.
const REAL_SECRETS: &[&str] = &[
    "xoxb-9f3K2pQ7mZ1tR8vN4wL6yH0cB5dG2jE",
    "ghp_J8kZq2WxX9nP4rT6yV1bC3dF5gH7jKaLmNo",
    "Tr0ub4dor&3xK9!mZqWvP",
];

#[test]
fn each_suppression_gate_emits_its_exact_reason_and_real_secrets_emit_none() {
    let _telemetry_guard = super::super::telemetry_serial::lock();
    for (credential, gate) in REASON_TABLE {
        assert_reason(credential, gate);
    }
    for credential in REAL_SECRETS {
        assert_not_suppressed(credential);
    }

    telemetry::testing::reset();
}
