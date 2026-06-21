//! Regression: every SHAPE / heuristic / marker suppression gate in the
//! cascade emits a `--dogfood` `ShapeSuppressed` event naming the gate, so a
//! recall-affecting silent drop can never masquerade as "never reached the
//! engine" (the `--dogfood --help` contract). Before this was wired, the
//! UUID / bare-hex / base64-blob / placeholder arms `return true` silently and
//! the dogfood trace showed `events: []` for a matched-and-silenced credential.
//!
//! Dogfood's hot-path flag is process-global, so this test takes the shared
//! unit telemetry lock and records events into scoped telemetry rather than the
//! process-global event buffer.

use keyhog_scanner::context::CodeContext;
use keyhog_scanner::telemetry::{self, DogfoodEvent, ScanTelemetry};
use std::sync::Arc;

/// Drain the trace and return the `reason` of each `ShapeSuppressed` event.
fn drain_shape_reasons(trace: &ScanTelemetry) -> Vec<String> {
    trace
        .drain()
        .dogfood_events
        .into_iter()
        .filter_map(|e| match e {
            DogfoodEvent::ShapeSuppressed { reason, .. } => Some(reason.into_owned()),
            _ => None,
        })
        .collect()
}

/// Assert `credential` is suppressed AND the dogfood trace names exactly
/// `expected_reason` (drains the buffer so each case starts clean).
fn assert_suppressed_with_reason(credential: &str, expected_reason: &str) {
    let trace = Arc::new(ScanTelemetry::new());
    telemetry::testing::reset();
    telemetry::enable_dogfood();
    let suppressed = telemetry::with_scan_telemetry(&trace, || {
        keyhog_scanner::testing::known_example_suppressed(credential, None, CodeContext::Unknown)
    });
    assert!(
        suppressed,
        "{credential:?} should be suppressed by the {expected_reason} gate"
    );
    assert_eq!(
        drain_shape_reasons(&trace),
        vec![expected_reason.to_string()],
        "dogfood trace for {credential:?} must name exactly the {expected_reason} gate"
    );
}

#[test]
fn dogfood_trace_names_each_cascade_suppression_gate() {
    let _telemetry_guard = super::super::telemetry_serial::lock();
    // ── shape gates (decision.rs) ──
    // UUID-v4 (version nibble 4, variant 8/9/a/b) — the dominant CredData/mirror
    // recall-conflict shape (KH-L-0405/0406); was silently dropped before wiring.
    assert_suppressed_with_reason("1f48cec7-bbee-4eb7-8e35-3bc1e7a0f2c2", "uuid_v4_shape");
    // Bare hex digest (64-hex, not a known example, no algo label).
    assert_suppressed_with_reason(
        "3b8a9c2d1e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
        "bare_hex_digest",
    );
    // Standard base64 blob: `+/` punctuation, `=` padding, length >= 40.
    assert_suppressed_with_reason(
        "QUJDREVG+2hpamtsbW5vcHFy/3N0dXZ3eHl6MDEyMzQ1Njc=",
        "base64_blob",
    );
    // Dashed serial / product-key shape: 5 blocks of 5 alnum.
    assert_suppressed_with_reason("ABCDE-FGHIJ-KLMNO-PQRST-UVWXY", "dashed_serial_key");

    // ── marker gates (doc_markers.rs) ──
    // Placeholder word from the shared Tier-B vocabulary.
    assert_suppressed_with_reason("DUMMY_TOKEN_VALUE_abc123def456", "placeholder_word");
    // Doc-marker substring buried in a longer token WITHOUT word boundaries
    // (camel/run-on), so the word-boundary placeholder check at the top of
    // the marker scan misses it and only the substring scan catches it — the
    // exact case that arm exists for (e.g. `ghp_EXAMPLE_TOKEN`-style buried markers).
    assert_suppressed_with_reason("svckeyPLACEHOLDERnotreal42xy", "doc_marker_substring");

    // ── negative twin: dogfood OFF ⇒ NO events recorded (zero-cost path),
    //     suppression decision itself UNCHANGED (still true). ──
    telemetry::testing::reset(); // clears the enable flag
    let trace = Arc::new(ScanTelemetry::new());
    let still_suppressed = telemetry::with_scan_telemetry(&trace, || {
        keyhog_scanner::testing::known_example_suppressed(
            "1f48cec7-bbee-4eb7-8e35-3bc1e7a0f2c2",
            None,
            CodeContext::Unknown,
        )
    });
    assert!(
        still_suppressed,
        "suppression behavior must be identical whether or not dogfood is on"
    );
    assert!(
        trace.drain().dogfood_events.is_empty(),
        "with dogfood OFF the shape-suppression recorder must emit nothing"
    );
}
