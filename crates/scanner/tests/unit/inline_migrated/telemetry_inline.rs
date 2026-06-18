//! Migrated from src/telemetry.rs

use keyhog_scanner::telemetry::{
    DogfoodEvent, ScanTelemetry, drain_events, enable_dogfood, example_suppression_count,
    record_example_suppression, reset, reset_example_suppression_count, with_scan_telemetry,
};
use std::sync::{Arc, Barrier, Mutex};

static T_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn counter_increments_without_dogfood() {
    let _g = T_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
    let _g = T_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
    let _g = T_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
    let _g = T_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
    let _g = T_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    enable_dogfood();

    let first = Arc::new(ScanTelemetry::new());
    let second = Arc::new(ScanTelemetry::new());
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
    let _g = T_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    enable_dogfood();
    record_example_suppression(
        "aws-access-key",
        Some("demo-secret.env"),
        concat!("AK", "IAIOSFODNN7EXAMPLE"),
        "ends_with_EXAMPLE",
    );
    let events = drain_events();
    assert_eq!(events.len(), 1);
    match &events[0] {
        DogfoodEvent::ExampleSuppressed {
            detector,
            credential_redacted,
            reason,
            ..
        } => {
            assert_eq!(detector, "aws-access-key");
            assert!(
                credential_redacted.starts_with("AKIA"),
                "should keep service prefix: {credential_redacted}"
            );
            assert!(
                !credential_redacted.contains("EXAMPLE"),
                "must not leak the full value"
            );
            assert!(
                credential_redacted.ends_with("MPLE"),
                "short redaction truncation should keep provider tail bytes: {credential_redacted}"
            );
            assert!(
                credential_redacted.contains("..."),
                "must contain an ellipsis separator when redacting a long credential"
            );
            assert_eq!(reason.as_ref(), "ends_with_EXAMPLE");
        }
        other => panic!("expected ExampleSuppressed, got {other:?}"),
    }
}

#[test]
fn redaction_keeps_prefix_only() {
    let _g = T_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    enable_dogfood();
    record_example_suppression(
        "aws-access-key",
        None,
        concat!("AK", "IAIOSFODNN7EXAMPLE"),
        "ends_with_EXAMPLE",
    );
    let events = drain_events();
    let red: &str = match &events[0] {
        DogfoodEvent::ExampleSuppressed {
            credential_redacted,
            ..
        } => credential_redacted.as_str(),
        other => panic!("expected ExampleSuppressed, got {other:?}"),
    };
    assert!(red.starts_with("AKIA"));
    assert!(red.contains("..."));
    assert!(red.ends_with("MPLE"));
    assert!(!red.contains("EXAMPLE"));
}

#[test]
fn redaction_handles_short_credentials() {
    let _g = T_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    enable_dogfood();
    record_example_suppression("pipeline", None, "", "empty");
    let events = drain_events();
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
