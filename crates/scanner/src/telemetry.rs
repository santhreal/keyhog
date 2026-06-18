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
use std::collections::HashSet;
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
    /// A credential was matched but suppressed by a SHAPE / heuristic / marker
    /// gate in the suppression cascade (UUID-v4, bare-hex digest, base64 blob,
    /// repetitive run, dashed serial, template placeholder, DUMMY/PLACEHOLDER
    /// word, doc-marker substring, …) other than the example-token counter
    /// path. These gates are recall-affecting: a real secret that happens to
    /// wear a suppressed shape is dropped here, so `--dogfood` must report it
    /// (the `--help` contract: "whether a match was made and silenced, or never
    /// reached the engine"). `reason` is the gate name (e.g.
    /// `Cow::Borrowed("uuid_v4_shape")`). No detector field: the suppression
    /// cascade adjudicates on shape/markers, not detector identity, so naming a
    /// detector here would be a guess.
    ShapeSuppressed {
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
    /// One key (`path\0credential_hash`) per credential the trace has ALREADY
    /// emitted a suppression EVENT for, across BOTH the example and shape paths.
    /// The same credential is adjudicated by several pipeline stages (the
    /// example-token gate AND a shape/weak-anchor gate can both drop the same
    /// `AKIA…EXAMPLE` key), so without this the `--dogfood` trace emitted one
    /// event per STAGE — duplicate noise for one logical suppression (KH-GAP-091).
    /// Keyed without the reason/stage so the FIRST stage to record a credential
    /// wins and later stages are deduped; the example counter keeps its own
    /// (reason-keyed) dedup so per-stage COUNTS are unaffected.
    emitted_suppression_events: Mutex<HashSet<String>>,
}

// Global lock-free telemetry counters (KH-116)
static FILES_SCANNED: AtomicUsize = AtomicUsize::new(0);
static BYTES_SCANNED: AtomicUsize = AtomicUsize::new(0);
static SKIPPED_FILES: AtomicUsize = AtomicUsize::new(0);
static TOTAL_MATCHES: AtomicUsize = AtomicUsize::new(0);
static GPU_DISPATCHES: AtomicUsize = AtomicUsize::new(0);
/// Files that MATCHED a structured-format heuristic (k8s Secret, Terraform
/// state, Jupyter notebook, docker-compose) but FAILED to parse, so the
/// structured decode-through (e.g. base64-encoded secrets inside a k8s `data:`
/// block) was NOT applied. The raw text is still scanned, so this is not a total
/// miss — but credentials only reachable via the structured decode are silently
/// lost on the offending file. Counted (not just `tracing::debug!`-logged, which
/// is filtered out at default verbosity) so the scan can surface the coverage
/// gap loudly at completion (Law 10).
static STRUCTURED_PARSE_FAILURES: AtomicUsize = AtomicUsize::new(0);

// Global static dogfood capability flag for fast opt-in checking (KH-120)
static DOGFOOD_ENABLED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct TelemetrySnapshot {
    pub files_scanned: usize,
    pub bytes_scanned: usize,
    pub skipped_files: usize,
    pub total_matches: usize,
    pub gpu_dispatches: usize,
    pub example_suppressions: usize,
}

fn cell() -> &'static Telemetry {
    static CELL: OnceLock<Telemetry> = OnceLock::new();
    CELL.get_or_init(Telemetry::default)
}

/// Enable dogfood event capture for the current process. Idempotent.
pub fn enable_dogfood() {
    DOGFOOD_ENABLED.store(true, Ordering::Relaxed);
    cell().dogfood_enabled.store(true, Ordering::Relaxed);
}

pub fn is_dogfood_enabled() -> bool {
    DOGFOOD_ENABLED.load(Ordering::Relaxed)
}

/// Record one example/placeholder suppression. The default path is only the
/// per-scan atomic counter; hash/lock/redaction work is reserved for opt-in
/// `--dogfood` event capture.
pub fn record_example_suppression(
    detector: &str,
    path: Option<&str>,
    credential: &str,
    reason: &'static str,
) {
    let t = cell();
    t.example_suppressions.fetch_add(1, Ordering::Relaxed);

    // KH-120: Wrap dogfood logging events behind static capability flags to eliminate overhead during silent scans.
    if !is_dogfood_enabled() {
        return;
    }

    let credential_hash = keyhog_core::hex_encode(&keyhog_core::sha256_hash(credential));
    // One EVENT per credential+path across all stages (KH-GAP-091): if a later
    // shape gate already recorded this same credential, or vice-versa, don't emit
    // a duplicate. First stage to reach it wins.
    if !mark_suppression_event_emitted(t, path, &credential_hash) {
        return;
    }

    // KH-disc: use the single canonical redaction policy (`keyhog_core::redact`)
    // so dogfood output matches finding output - the bespoke 6-char-prefix
    // helper leaked up to 6 of 8 bytes of short credentials.
    let redacted = keyhog_core::redact(credential).into_owned();
    if let Ok(mut events) = t.events.lock() {
        events.push(DogfoodEvent::ExampleSuppressed {
            detector: detector.to_string(),
            path: path.map(str::to_string),
            credential_redacted: redacted,
            reason: Cow::Borrowed(reason),
        });
    }
}

/// Insert `path\0credential_hash` into the shared emitted-event set, returning
/// `true` only the FIRST time a given credential+path is seen. Both suppression
/// recorders gate their `events.push` on this so the `--dogfood` trace carries
/// one event per logical suppression rather than one per pipeline stage. A
/// poisoned lock fails OPEN (returns `true`) — an extra event is a far smaller
/// sin than silently dropping the trace (Law 10).
fn mark_suppression_event_emitted(
    t: &Telemetry,
    path: Option<&str>,
    credential_hash: &str,
) -> bool {
    let key = format!("{}\0{}", path.unwrap_or(""), credential_hash);
    match t.emitted_suppression_events.lock() {
        Ok(mut emitted) => emitted.insert(key),
        Err(_) => true,
    }
}

/// Record one SHAPE / heuristic suppression (UUID, bare-hex, base64 blob,
/// repetitive run, …) for the `--dogfood` trace. Unlike
/// [`record_example_suppression`] this is on the HOT suppression path (every
/// candidate that hits a shape gate), so it is **zero-cost when dogfood is
/// off**: the `is_dogfood_enabled()` atomic load short-circuits before any
/// hashing / locking. It also does NOT bump the example-suppression counter -
/// the reporter's "N example keys suppressed" summary stays example-only; shape
/// drops are a `--dogfood`-only diagnostic. Dedup reuses the shared seen-set
/// (keyed with a `shape\0` prefix so it can't collide with example keys).
pub fn record_shape_suppression(path: Option<&str>, credential: &str, reason: &'static str) {
    // Cheap atomic first - the common (no-dogfood) scan pays nothing beyond this.
    if !is_dogfood_enabled() {
        return;
    }
    let t = cell();
    let credential_hash = keyhog_core::hex_encode(&keyhog_core::sha256_hash(credential));
    // One EVENT per credential+path across ALL stages (KH-GAP-091): a credential
    // the example-token gate already recorded (e.g. `AKIA…EXAMPLE`, which is also
    // a weak-anchor shape) must not emit a second shape event for the same
    // logical drop. The shared emitted-set also collapses the same shape gate
    // firing twice for one credential, so this fully replaces the old
    // reason-keyed dedup.
    if !mark_suppression_event_emitted(t, path, &credential_hash) {
        return;
    }
    let redacted = keyhog_core::redact(credential).into_owned();
    if let Ok(mut events) = t.events.lock() {
        events.push(DogfoodEvent::ShapeSuppressed {
            path: path.map(str::to_string),
            credential_redacted: redacted,
            reason: Cow::Borrowed(reason),
        });
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

/// Record that a file matched a structured-format heuristic but failed to parse,
/// so its structured decode-through was not applied (see
/// [`struct@STRUCTURED_PARSE_FAILURES`]). Always counts (not dogfood-gated): this
/// is a recall-coverage fact the reporter surfaces unconditionally, like the
/// walker skip counters.
pub fn record_structured_parse_failure() {
    STRUCTURED_PARSE_FAILURES.fetch_add(1, Ordering::Relaxed);
}

/// Count of files that matched a structured format but failed to parse this scan.
pub fn structured_parse_failure_count() -> usize {
    STRUCTURED_PARSE_FAILURES.load(Ordering::Relaxed)
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
    // The drained batch is one complete trace; the next scan must be able to emit
    // its own events for the same credentials, so clear the per-credential
    // emitted-event dedup alongside the drain.
    if let Ok(mut emitted) = t.emitted_suppression_events.lock() {
        emitted.clear();
    }
    if let Ok(mut events) = t.events.lock() {
        std::mem::take(&mut *events)
    } else {
        Vec::new()
    }
}

// Telemetry recording helpers (KH-116)
pub fn record_file_scanned(bytes: usize) {
    FILES_SCANNED.fetch_add(1, Ordering::Relaxed);
    BYTES_SCANNED.fetch_add(bytes, Ordering::Relaxed);
}

pub fn record_file_skipped() {
    SKIPPED_FILES.fetch_add(1, Ordering::Relaxed);
}

pub fn record_match_found() {
    TOTAL_MATCHES.fetch_add(1, Ordering::Relaxed);
}

pub fn record_gpu_dispatch() {
    GPU_DISPATCHES.fetch_add(1, Ordering::Relaxed);
}

// KH-122: Expose telemetry counters through static memory structures to avoid allocation during sweeps
pub fn get_telemetry_snapshot() -> TelemetrySnapshot {
    TelemetrySnapshot {
        files_scanned: FILES_SCANNED.load(Ordering::Relaxed),
        bytes_scanned: BYTES_SCANNED.load(Ordering::Relaxed),
        skipped_files: SKIPPED_FILES.load(Ordering::Relaxed),
        total_matches: TOTAL_MATCHES.load(Ordering::Relaxed),
        gpu_dispatches: GPU_DISPATCHES.load(Ordering::Relaxed),
        example_suppressions: example_suppression_count(),
    }
}

/// Reset all state. For tests only.
#[doc(hidden)]
pub fn reset() {
    let t = cell();
    DOGFOOD_ENABLED.store(false, Ordering::Relaxed);
    t.dogfood_enabled.store(false, Ordering::Relaxed);
    t.example_suppressions.store(0, Ordering::Relaxed);
    FILES_SCANNED.store(0, Ordering::Relaxed);
    BYTES_SCANNED.store(0, Ordering::Relaxed);
    SKIPPED_FILES.store(0, Ordering::Relaxed);
    TOTAL_MATCHES.store(0, Ordering::Relaxed);
    GPU_DISPATCHES.store(0, Ordering::Relaxed);
    STRUCTURED_PARSE_FAILURES.store(0, Ordering::Relaxed);
    if let Ok(mut events) = t.events.lock() {
        events.clear();
    }
    if let Ok(mut emitted) = t.emitted_suppression_events.lock() {
        emitted.clear();
    }
}
