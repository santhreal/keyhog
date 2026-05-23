//! Lightweight per-scan telemetry.
//!
//! Two purposes:
//!
//! 1. **Always-on counters** for things the reporter wants to surface
//!    even on a default run (e.g. "no secrets, but 3 example/test keys
//!    were suppressed — pass `--dogfood` to see them"). These are
//!    cheap atomic increments.
//! 2. **Opt-in event capture** (`enable_dogfood()`) — the engine logs
//!    per-decision detail so a user can answer "why didn't keyhog fire
//!    on my fixture?" without rebuilding with debug instrumentation.
//!
//! Single-process scope: keyhog runs one scan per process, so a
//! process-global `OnceLock<Telemetry>` is the lightest container that
//! doesn't drag every engine boundary into accepting a `&Telemetry`
//! argument. Tests reset state via `reset()`.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

/// A single dogfood event. Variants are intentionally narrow — anything
/// scanner-internal that would help a user understand a missed or
/// suppressed credential should go here.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DogfoodEvent {
    /// A credential was matched but suppressed as a known example /
    /// placeholder (e.g. ends with `EXAMPLE`, is a sequential
    /// placeholder, contains a `DUMMY`/`FAKE`/`MOCK` token).
    ExampleSuppressed {
        detector: String,
        path: Option<String>,
        credential_redacted: String,
        reason: &'static str,
    },
}

#[derive(Default)]
struct Telemetry {
    dogfood_enabled: AtomicBool,
    example_suppressions: AtomicUsize,
    events: Mutex<Vec<DogfoodEvent>>,
}

fn cell() -> &'static Telemetry {
    static CELL: OnceLock<Telemetry> = OnceLock::new();
    CELL.get_or_init(Telemetry::default)
}

/// Enable dogfood event capture for the current process. Idempotent.
pub fn enable_dogfood() {
    cell().dogfood_enabled.store(true, Ordering::Relaxed);
}

pub fn is_dogfood_enabled() -> bool {
    cell().dogfood_enabled.load(Ordering::Relaxed)
}

/// Record one example/placeholder suppression. Always increments the
/// counter; only appends a full event record when `--dogfood` is on.
pub fn record_example_suppression(
    detector: &str,
    path: Option<&str>,
    credential: &str,
    reason: &'static str,
) {
    let t = cell();
    t.example_suppressions.fetch_add(1, Ordering::Relaxed);
    if t.dogfood_enabled.load(Ordering::Relaxed) {
        let redacted = redact_credential(credential);
        if let Ok(mut events) = t.events.lock() {
            events.push(DogfoodEvent::ExampleSuppressed {
                detector: detector.to_string(),
                path: path.map(str::to_string),
                credential_redacted: redacted,
                reason,
            });
        }
    }
}

/// Count of example/placeholder credentials suppressed during this scan.
pub fn example_suppression_count() -> usize {
    cell().example_suppressions.load(Ordering::Relaxed)
}

/// Drain and return all captured dogfood events. Returns empty when
/// `enable_dogfood()` was never called.
pub fn drain_events() -> Vec<DogfoodEvent> {
    let t = cell();
    if let Ok(mut events) = t.events.lock() {
        std::mem::take(&mut *events)
    } else {
        Vec::new()
    }
}

/// Reset all state. For tests only.
#[doc(hidden)]
pub fn reset() {
    let t = cell();
    t.dogfood_enabled.store(false, Ordering::Relaxed);
    t.example_suppressions.store(0, Ordering::Relaxed);
    if let Ok(mut events) = t.events.lock() {
        events.clear();
    }
}

/// Redact a credential for safe inclusion in dogfood output: keep a
/// short prefix (so the user can recognise which detector fired) and
/// mask the rest. Never emits the full credential — the whole point of
/// `--dogfood` is "show me decisions", not "leak the secrets I'm
/// scanning for to my terminal scrollback or log file".
fn redact_credential(credential: &str) -> String {
    const PREFIX_KEEP: usize = 6;
    let take = credential.char_indices().nth(PREFIX_KEEP);
    match take {
        Some((end_byte, _)) => format!(
            "{}…[redacted {} chars]",
            &credential[..end_byte],
            credential.chars().count().saturating_sub(PREFIX_KEEP)
        ),
        None => "[redacted]".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Tests in this module touch the process-global `Telemetry` cell.
    /// `cargo test`'s parallel runner would let them step on each other
    /// (one's `reset()` blowing away another's events), so serialise
    /// every test that touches global state behind this lock.
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
            "AKIAIOSFODNN7EXAMPLE",
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
                assert!(credential_redacted.starts_with("AKIAIO"));
                assert!(
                    !credential_redacted.contains("EXAMPLE"),
                    "must not leak the full value"
                );
                assert_eq!(*reason, "ends_with_EXAMPLE");
            }
        }
    }

    #[test]
    fn redaction_keeps_prefix_only() {
        let red = redact_credential("AKIAIOSFODNN7EXAMPLE");
        assert!(red.starts_with("AKIAIO"));
        assert!(!red.contains("EXAMPLE"));
    }

    #[test]
    fn redaction_handles_short_credentials() {
        assert_eq!(redact_credential(""), "[redacted]");
    }
}
