//! Regression (KH-L-0412): the generic-bridge VALUE-SHAPE gauntlet
//! (`generic_value_shape_rejected`, the dominant CredData generic path) was the
//! LAST silent suppression path: `scan_generic_assignments` did
//! `if generic_value_shape_rejected(..) { continue }` with NO telemetry, so a
//! generic-secret candidate dropped by any shape gate (identifier / base64-blob /
//! encoded-binary / placeholder family) was invisible to `--dogfood`, conflated
//! with "never reached the engine" (a Law-10 silent drop). The predicate now
//! returns `Some(gate_name)` and the caller records a `ShapeSuppressed` event.
//!
//! Dogfood's hot-path flag is carried by the scan telemetry scope here, so the
//! positive and negative twins do not depend on process-global test scheduling.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::telemetry::{self, DogfoodEvent, ScanTelemetry};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::sync::Arc;

fn scanner() -> CompiledScanner {
    let detector = keyhog_core::load_embedded_detectors_or_fail()
        .expect("embedded detector corpus")
        .into_iter()
        .find(|detector| detector.id == "generic-secret")
        .expect("generic-secret detector");
    CompiledScanner::compile(vec![detector]).expect("compile scanner")
}

/// Scan `line` through the CPU fallback path (where the generic keyword bridge +
/// its shape gauntlet run) and return the `ShapeSuppressed` reasons recorded for
/// our planted value (matched by redaction prefix so a concurrent gate can't
/// satisfy the assertion).
fn shape_reasons_for(
    scanner: &CompiledScanner,
    line: &str,
    redact_prefix: &str,
    trace: &Arc<ScanTelemetry>,
) -> Vec<String> {
    let chunk = Chunk {
        data: line.into(),
        metadata: ChunkMetadata::default(),
    };
    scanner.clear_fragment_cache();
    let _ = telemetry::with_scan_telemetry(trace, || {
        scanner.scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
    });
    trace
        .drain()
        .dogfood_events
        .into_iter()
        .filter_map(|e| match e {
            DogfoodEvent::ShapeSuppressed {
                reason,
                credential_redacted,
                ..
            } if credential_redacted.starts_with(redact_prefix) => Some(reason.into_owned()),
            _ => None,
        })
        .collect()
}

#[test]
fn generic_gauntlet_base64_blob_drop_is_traced() {
    let _g = super::super::telemetry_serial::lock();
    let s = scanner();
    telemetry::testing::reset();
    // A standard-base64 blob under a `secret` keyword: 48 chars, `+`/`/`, padding,
    // entropy < 4.8, the generic-path `base64_blob` gate (a protobuf/marshalled-
    // binary decoy class) drops it. No vendor prefix => no named detector fires,
    // so the generic bridge is the only path and the gauntlet is what suppresses.
    let blob = "Yml0Y29pbgABAgMEBQYHCAkKCwwND/7+/f38+/r5+Pf=";
    let trace = Arc::new(ScanTelemetry::new());
    trace.enable_dogfood();
    let reasons = shape_reasons_for(&s, &format!("secret = \"{blob}\""), "Yml0", &trace);
    assert!(
        reasons.iter().any(|r| r == "base64_blob"),
        "the generic-bridge base64-blob shape drop must emit a ShapeSuppressed \
         event naming the gate (KH-L-0412); got reasons {reasons:?}"
    );

    // ── negative twin: dogfood OFF ⇒ zero events, decision unchanged ──
    telemetry::testing::reset();
    let trace = Arc::new(ScanTelemetry::new());
    let off = shape_reasons_for(&s, &format!("secret = \"{blob}\""), "Yml0", &trace);
    assert!(
        off.is_empty(),
        "with dogfood OFF the generic-gauntlet recorder must emit nothing, got {off:?}"
    );
}
