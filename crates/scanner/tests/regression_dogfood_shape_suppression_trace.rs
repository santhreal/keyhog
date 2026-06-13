//! Regression: every SHAPE / heuristic / marker suppression gate in the
//! cascade emits a `--dogfood` `ShapeSuppressed` event naming the gate, so a
//! recall-affecting silent drop can never masquerade as "never reached the
//! engine" (the `--dogfood --help` contract). Before this was wired, the
//! UUID / bare-hex / base64-blob / placeholder arms `return true` silently and
//! the dogfood trace showed `events: []` for a matched-and-silenced credential.
//!
//! Telemetry is process-global, so all assertions live in ONE `#[test]` fn
//! (sequential) — this file is its own test binary, so no cross-file race.

use keyhog_scanner::context::CodeContext;
use keyhog_scanner::telemetry::{self, DogfoodEvent};

/// Drain the trace and return the `reason` of each `ShapeSuppressed` event.
fn drain_shape_reasons() -> Vec<String> {
    telemetry::drain_events()
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
    let suppressed =
        keyhog_scanner::should_suppress_known_example_credential(credential, None, CodeContext::Unknown);
    assert!(
        suppressed,
        "{credential:?} should be suppressed by the {expected_reason} gate"
    );
    assert_eq!(
        drain_shape_reasons(),
        vec![expected_reason.to_string()],
        "dogfood trace for {credential:?} must name exactly the {expected_reason} gate"
    );
}

#[test]
fn dogfood_trace_names_each_cascade_suppression_gate() {
    telemetry::reset();
    telemetry::enable_dogfood();

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
        "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5+/AB==",
        "base64_blob",
    );
    // Dashed serial / product-key shape: 5 blocks of 5 alnum.
    assert_suppressed_with_reason("ABCDE-FGHIJ-KLMNO-PQRST-UVWXY", "dashed_serial_key");

    // ── marker gates (doc_markers.rs) ──
    // Placeholder word.
    assert_suppressed_with_reason("DUMMY_TOKEN_VALUE_abc123def456", "placeholder_word");
    // Doc-marker substring buried in a longer token WITHOUT word boundaries
    // (camel/run-on), so the word-boundary PLACEHOLDER_WORDS check at the top of
    // the marker scan misses it and only the substring scan catches it — the
    // exact case that arm exists for (e.g. `ghp_EXAMPLE_TOKEN`-style buried markers).
    assert_suppressed_with_reason("svckeyPLACEHOLDERnotreal42xy", "doc_marker_substring");

    // ── negative twin: dogfood OFF ⇒ NO events recorded (zero-cost path),
    //     suppression decision itself UNCHANGED (still true). ──
    telemetry::reset(); // clears the enable flag
    let still_suppressed = keyhog_scanner::should_suppress_known_example_credential(
        "1f48cec7-bbee-4eb7-8e35-3bc1e7a0f2c2",
        None,
        CodeContext::Unknown,
    );
    assert!(
        still_suppressed,
        "suppression behavior must be identical whether or not dogfood is on"
    );
    assert!(
        telemetry::drain_events().is_empty(),
        "with dogfood OFF the shape-suppression recorder must emit nothing"
    );
}
