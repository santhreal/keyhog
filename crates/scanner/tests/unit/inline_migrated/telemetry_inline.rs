//! Migrated from src/telemetry.rs

use keyhog_scanner::telemetry::{
    drain_events, enable_dogfood, example_suppression_count, record_example_suppression, reset,
    DogfoodEvent,
};
use std::sync::Mutex;

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
