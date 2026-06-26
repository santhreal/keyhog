//! Migrated from src/telemetry.rs

use keyhog_scanner::telemetry::{
    drain_events, enable_dogfood, example_suppression_count, record_example_suppression,
    reset_example_suppression_count, testing::reset, with_scan_telemetry, DogfoodEvent,
    ScanTelemetry,
};
use std::sync::{Arc, Barrier};

fn scoped_dogfood_events(f: impl FnOnce()) -> Vec<DogfoodEvent> {
    reset();
    let trace = Arc::new(ScanTelemetry::new());
    trace.enable_dogfood();
    with_scan_telemetry(&trace, f);
    let events = trace.drain().dogfood_events;
    reset();
    events
}

#[test]
fn counter_increments_without_dogfood() {
    let _g = super::super::telemetry_serial::lock();
    reset();
    record_example_suppression("aws", None, "AKIAEXAMPLE", "ends_with_EXAMPLE");
    record_example_suppression("aws", None, "AKIAEXAMPLE2", "ends_with_EXAMPLE");
    assert_eq!(example_suppression_count(), 2);
    assert!(
        drain_events().is_empty(),
        "events only collected with --dogfood"
    );
}

#[test]
fn repeated_default_suppression_counts_without_event_dedup_work() {
    let _g = super::super::telemetry_serial::lock();
    reset();
    record_example_suppression("aws", Some("same.env"), "AKIAEXAMPLE", "ends_with_EXAMPLE");
    record_example_suppression("aws", Some("same.env"), "AKIAEXAMPLE", "ends_with_EXAMPLE");

    assert_eq!(
        example_suppression_count(),
        2,
        "default scans must count per-scan suppressions without a process-global String dedup set"
    );
    assert!(
        drain_events().is_empty(),
        "default scans must not allocate dogfood events"
    );
}

#[test]
fn reset_example_suppression_count_makes_repeated_daemon_scans_stable() {
    let _g = super::super::telemetry_serial::lock();
    reset();
    record_example_suppression("aws", Some("same.env"), "AKIAEXAMPLE", "ends_with_EXAMPLE");
    assert_eq!(example_suppression_count(), 1);

    reset_example_suppression_count();
    record_example_suppression("aws", Some("same.env"), "AKIAEXAMPLE", "ends_with_EXAMPLE");
    assert_eq!(
        example_suppression_count(),
        1,
        "daemon-style per-scan reset must not be defeated by process-global example dedup"
    );
}

#[test]
fn drain_events_allows_same_dogfood_suppression_in_next_scan() {
    let _g = super::super::telemetry_serial::lock();
    reset();
    enable_dogfood();
    record_example_suppression("aws", Some("same.env"), "AKIAEXAMPLE", "ends_with_EXAMPLE");
    assert_eq!(drain_events().len(), 1);

    reset_example_suppression_count();
    record_example_suppression("aws", Some("same.env"), "AKIAEXAMPLE", "ends_with_EXAMPLE");
    assert_eq!(
        drain_events().len(),
        1,
        "draining one daemon scan must clear event dedup for the next scan"
    );
}

#[test]
fn scoped_scan_telemetry_isolates_concurrent_daemon_counts() {
    let _g = super::super::telemetry_serial::lock();
    reset();

    let first = Arc::new(ScanTelemetry::new());
    let second = Arc::new(ScanTelemetry::new());
    first.enable_dogfood();
    second.enable_dogfood();
    let barrier = Arc::new(Barrier::new(3));

    let first_worker = {
        let telemetry = Arc::clone(&first);
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            with_scan_telemetry(&telemetry, || {
                barrier.wait();
                record_example_suppression("aws", Some("first.env"), "AKIAFIRSTEXAMPLE", "first");
                barrier.wait();
            });
        })
    };
    let second_worker = {
        let telemetry = Arc::clone(&second);
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            with_scan_telemetry(&telemetry, || {
                barrier.wait();
                record_example_suppression(
                    "aws",
                    Some("second.env"),
                    "AKIASECONDEXAMPLE",
                    "second",
                );
                barrier.wait();
            });
        })
    };

    barrier.wait();
    barrier.wait();
    first_worker.join().expect("first telemetry worker");
    second_worker.join().expect("second telemetry worker");

    let first_snapshot = first.drain();
    let second_snapshot = second.drain();
    assert_eq!(first_snapshot.example_suppressions, 1);
    assert_eq!(second_snapshot.example_suppressions, 1);
    assert_eq!(first_snapshot.dogfood_events.len(), 1);
    assert_eq!(second_snapshot.dogfood_events.len(), 1);
    assert_eq!(
        example_suppression_count(),
        0,
        "scoped daemon telemetry must not leak into the process-global CLI counter"
    );
    assert!(
        drain_events().is_empty(),
        "scoped daemon telemetry must not leak dogfood events into the global buffer"
    );
}

#[test]
fn dogfood_captures_events() {
    let _g = super::super::telemetry_serial::lock();
    let events = scoped_dogfood_events(|| {
        record_example_suppression(
            "aws-access-key",
            Some("demo-secret.env"),
            concat!("AK", "IAIOSFODNN7EXAMPLE"),
            "ends_with_EXAMPLE",
        )
    });
    assert_eq!(events.len(), 1);
    match &events[0] {
        DogfoodEvent::ExampleSuppressed {
            detector,
            credential_redacted,
            reason,
            ..
        } => {
            assert_eq!(detector, "aws-access-key");
            // Canonical keyhog_core::redact: edge = (len/8).clamp(1,4); this
            // 20-byte value redacts to "AK" + "..." + "LE". telemetry.rs migrated
            // dogfood redaction onto the shared finding-output policy, dropping the
            // old fixed-prefix helper that leaked too much of short secrets
            // (02d6150d9 "Cap redaction preview exposure").
            assert_eq!(
                credential_redacted, "AK...LE",
                "dogfood redaction must match canonical keyhog_core::redact"
            );
            assert!(
                !credential_redacted.contains("EXAMPLE"),
                "must not leak the full value"
            );
            assert_eq!(reason.as_ref(), "ends_with_EXAMPLE");
        }
        other => panic!("expected ExampleSuppressed, got {other:?}"),
    }
}

#[test]
fn redaction_keeps_prefix_only() {
    let _g = super::super::telemetry_serial::lock();
    let events = scoped_dogfood_events(|| {
        record_example_suppression(
            "aws-access-key",
            None,
            concat!("AK", "IAIOSFODNN7EXAMPLE"),
            "ends_with_EXAMPLE",
        )
    });
    let red: &str = match &events[0] {
        DogfoodEvent::ExampleSuppressed {
            credential_redacted,
            ..
        } => credential_redacted.as_str(),
        other => panic!("expected ExampleSuppressed, got {other:?}"),
    };
    // Canonical redact keeps (len/8).clamp(1,4)=2-byte edges for this 20-byte
    // value: "AK...LE". The middle and the distinctive tail stay hidden.
    assert_eq!(red, "AK...LE");
    assert!(!red.contains("EXAMPLE"));
}

#[test]
fn redaction_handles_short_credentials() {
    let _g = super::super::telemetry_serial::lock();
    let events =
        scoped_dogfood_events(|| record_example_suppression("pipeline", None, "", "empty"));
    match &events[0] {
        DogfoodEvent::ExampleSuppressed {
            credential_redacted,
            ..
        } => assert_eq!(
            credential_redacted.as_str(),
            "****",
            "short/empty credentials must be masked by the canonical \
             keyhog_core::redact policy (<=8 chars -> ****), never leaked verbatim"
        ),
        other => panic!("expected ExampleSuppressed, got {other:?}"),
    }
}
