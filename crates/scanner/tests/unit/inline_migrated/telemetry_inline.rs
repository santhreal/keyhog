//! Migrated from src/telemetry.rs

use keyhog_scanner::telemetry::{
    append_daemon_events, append_events, dogfood_detail_events_dropped, drain_events,
    enable_dogfood, example_suppression_count, merge_daemon_aggregates, record_example_suppression,
    reset_example_suppression_count, static_recovery_rejection_counts, testing::reset,
    with_scan_telemetry, DogfoodEvent, ScanTelemetry,
};
use std::borrow::Cow;
use std::collections::BTreeMap;
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
fn replay_and_local_details_share_one_exact_capacity() {
    let _g = super::super::telemetry_serial::lock();
    reset();
    append_events(
        (0..keyhog_scanner::telemetry::DOGFOOD_DETAIL_EVENT_LIMIT).map(|index| {
            DogfoodEvent::ShapeSuppressed {
                path: Some(format!("replay-{index}.env")),
                credential_redacted: "****".to_owned(),
                reason: Cow::Borrowed("replayed"),
            }
        }),
    );
    enable_dogfood();
    record_example_suppression("aws", Some("local.env"), "AKIAEXAMPLE", "local");

    assert_eq!(
        drain_events().len(),
        keyhog_scanner::telemetry::DOGFOOD_DETAIL_EVENT_LIMIT
    );
    assert_eq!(dogfood_detail_events_dropped(), 1);
    reset();
}

#[test]
fn poisoned_scoped_event_buffer_counts_the_omitted_detail() {
    let _g = super::super::telemetry_serial::lock();
    let trace = Arc::new(ScanTelemetry::new());
    trace.enable_dogfood();
    crate::telemetry::testing::poison_events(&trace);

    with_scan_telemetry(&trace, || {
        record_example_suppression("aws", Some("poisoned.env"), "AKIAEXAMPLE", "poisoned");
    });
    let snapshot = trace.drain();
    assert!(snapshot.dogfood_events.is_empty());
    assert_eq!(snapshot.dogfood_detail_events_dropped, 1);
}

#[test]
fn poisoned_scoped_event_buffer_drain_recovers_retained_details() {
    let _g = super::super::telemetry_serial::lock();
    let trace = Arc::new(ScanTelemetry::new());
    trace.enable_dogfood();
    with_scan_telemetry(&trace, || {
        record_example_suppression("aws", Some("retained.env"), "AKIAEXAMPLE", "retained");
    });
    crate::telemetry::testing::poison_events(&trace);

    let snapshot = trace.drain();
    assert_eq!(snapshot.dogfood_events.len(), 1);
    assert_eq!(snapshot.dogfood_detail_events_dropped, 0);
}

#[test]
fn daemon_details_and_exact_aggregates_merge_without_double_counting() {
    let _g = super::super::telemetry_serial::lock();
    reset();
    append_daemon_events([DogfoodEvent::StaticRecoveryRejected {
        path: Some("history.js".to_owned()),
        expression_offset: 9,
        decoder: Cow::Borrowed("javascript-static"),
        reason: Cow::Borrowed("json_utf8"),
    }]);
    merge_daemon_aggregates(&BTreeMap::from([("json_utf8".to_owned(), 7)]), 3)
        .expect("merge compatible aggregate reasons");

    assert_eq!(
        static_recovery_rejection_counts().get("json_utf8"),
        Some(&7)
    );
    assert_eq!(dogfood_detail_events_dropped(), 3);
    assert_eq!(drain_events().len(), 1);
    reset();
}

#[test]
fn daemon_aggregate_merge_rejects_unknown_reason_before_mutation() {
    let _g = super::super::telemetry_serial::lock();
    reset();
    let error = merge_daemon_aggregates(
        &BTreeMap::from([
            ("json_utf8".to_owned(), 4),
            ("newer-daemon-reason".to_owned(), 2),
        ]),
        5,
    )
    .expect_err("unknown reason must fail closed");
    assert!(error.contains("restart it with this KeyHog build"));
    assert!(static_recovery_rejection_counts().is_empty());
    assert_eq!(dogfood_detail_events_dropped(), 0);
}

#[test]
fn legacy_static_recovery_event_wire_shape_remains_compatible() {
    let event: DogfoodEvent = serde_json::from_str(
        r#"{"kind":"static_recovery_rejected","path":"old.js","expression_offset":7,"decoder":"javascript-static","reason":"json_utf8"}"#,
    )
    .expect("deserialize pre-source-identity event");
    match event {
        DogfoodEvent::StaticRecoveryRejected {
            path,
            expression_offset,
            ..
        } => {
            assert_eq!(path.as_deref(), Some("old.js"));
            assert_eq!(expression_offset, 7);
        }
        other => panic!("expected static recovery rejection, got {other:?}"),
    }
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
