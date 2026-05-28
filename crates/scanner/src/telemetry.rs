//! Lightweight per-scan telemetry.
//!
//! Two purposes:
//!
//! 1. **Always-on counters** for things the reporter wants to surface
//!    even on a default run (e.g. "no secrets, but 3 example/test keys
//!    were suppressed - pass `--dogfood` to see them"). These are
//!    cheap atomic increments.
//! 2. **Opt-in event capture** (`enable_dogfood()`) - the engine logs
//!    per-decision detail so a user can answer "why didn't keyhog fire
//!    on my fixture?" without rebuilding with debug instrumentation.
//!
//! Single-process scope: keyhog runs one scan per process, so a
//! process-global `OnceLock<Telemetry>` is the lightest container that
//! doesn't drag every engine boundary into accepting a `&Telemetry`
//! argument. Tests reset state via `reset()`.

use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

/// A single dogfood event. Variants are intentionally narrow - anything
/// scanner-internal that would help a user understand a missed or
/// suppressed credential should go here.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DogfoodEvent {
    /// A credential was matched but suppressed as a known example /
    /// placeholder (e.g. ends with `EXAMPLE`, is a sequential
    /// placeholder, contains a `DUMMY`/`FAKE`/`MOCK` token).
    ///
    /// `reason` is `Cow<'static, str>` so callers can pass a literal
    /// without allocating (`Cow::Borrowed("ends_with_EXAMPLE")`),
    /// while the daemon-protocol deserialize path can also produce
    /// owned values from over-the-wire JSON.
    ExampleSuppressed {
        detector: String,
        path: Option<String>,
        credential_redacted: String,
        reason: Cow<'static, str>,
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
                reason: Cow::Borrowed(reason),
            });
        }
    }
}

/// Count of example/placeholder credentials suppressed during this scan.
pub fn example_suppression_count() -> usize {
    cell().example_suppressions.load(Ordering::Relaxed)
}

/// Zero the suppression counter without disturbing the dogfood
/// enable-flag or any in-flight events. Used by the daemon between
/// scan requests so per-request counts don't accumulate across
/// clients - the count we ship over the wire belongs to one scan.
pub fn reset_example_suppression_count() {
    cell().example_suppressions.store(0, Ordering::Relaxed);
}

/// Add `n` to the suppression counter without recording an event.
/// Used by the daemon client to merge a daemon-side count into the
/// CLI's own counter so the reporter's empty-findings summary fires
/// correctly across the IPC boundary.
pub fn add_example_suppressions(n: usize) {
    cell().example_suppressions.fetch_add(n, Ordering::Relaxed);
}

/// Append events into the per-process buffer without going through the
/// `record_example_suppression` path (no counter bump, no dogfood
/// enable-check). Used by the daemon client to replay events captured
/// on the daemon side, so `--dogfood` output works in daemon mode.
pub fn append_events<I: IntoIterator<Item = DogfoodEvent>>(events: I) {
    let t = cell();
    if let Ok(mut buf) = t.events.lock() {
        buf.extend(events);
    }
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
/// mask the rest. Never emits the full credential - the whole point of
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
