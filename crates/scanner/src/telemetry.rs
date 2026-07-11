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
//! Single-process CLI scans use the process-global `OnceLock<Telemetry>` as
//! the lightest container. Long-lived daemon workers use `ScanTelemetry`
//! scopes so concurrent client scans do not share counts/events.

use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

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

/// Per-request scanner telemetry used by daemon scan workers.
///
/// The regular CLI process still uses the process-global telemetry cell because
/// it runs one scan per process. A daemon serves many client requests in one
/// process, so each request owns one `ScanTelemetry` and installs it with
/// [`with_scan_telemetry`] for the duration of the scan. Recorders then route
/// counts/events into that scope instead of the process-global cell.
#[derive(Default)]
pub struct ScanTelemetry {
    dogfood_enabled: AtomicBool,
    example_suppressions: AtomicUsize,
    events: Mutex<Vec<DogfoodEvent>>,
    emitted_suppression_events: Mutex<HashSet<String>>,
}

impl ScanTelemetry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enable_dogfood(&self) {
        self.dogfood_enabled.store(true, Ordering::Relaxed);
    }

    fn is_dogfood_enabled(&self) -> bool {
        self.dogfood_enabled.load(Ordering::Relaxed)
    }

    fn example_suppression_count(&self) -> usize {
        self.example_suppressions.load(Ordering::Relaxed)
    }

    fn drain_events(&self) -> Vec<DogfoodEvent> {
        drain_event_buffers(&self.events, &self.emitted_suppression_events)
    }

    pub fn drain(&self) -> ScanTelemetrySnapshot {
        ScanTelemetrySnapshot {
            example_suppressions: self.example_suppression_count() as u64,
            dogfood_events: self.drain_events(),
        }
    }
}

pub struct ScanTelemetrySnapshot {
    pub example_suppressions: u64,
    pub dogfood_events: Vec<DogfoodEvent>,
}

thread_local! {
    static CURRENT_SCAN_TELEMETRY: RefCell<Option<Arc<ScanTelemetry>>> = RefCell::new(None);
}

struct ScanTelemetryRestore {
    previous: Option<Arc<ScanTelemetry>>,
}

impl Drop for ScanTelemetryRestore {
    fn drop(&mut self) {
        let previous = self.previous.take();
        CURRENT_SCAN_TELEMETRY.with(|slot| {
            *slot.borrow_mut() = previous;
        });
    }
}

/// Run `f` with `telemetry` installed for scanner telemetry recorders on this
/// thread. Nested scopes restore the previous owner on drop, including during
/// unwinding.
pub fn with_scan_telemetry<R>(telemetry: &Arc<ScanTelemetry>, f: impl FnOnce() -> R) -> R {
    let previous = CURRENT_SCAN_TELEMETRY.with(|slot| {
        let mut slot = slot.borrow_mut();
        slot.replace(Arc::clone(telemetry))
    });
    let _restore = ScanTelemetryRestore { previous };
    f()
}

fn current_scan_telemetry() -> Option<Arc<ScanTelemetry>> {
    CURRENT_SCAN_TELEMETRY.with(|slot| slot.borrow().clone())
}

fn current_scan_dogfood_enabled() -> Option<bool> {
    CURRENT_SCAN_TELEMETRY.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|telemetry| telemetry.is_dogfood_enabled())
    })
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
/// A chunk matched a structured decode-through format (k8s Secret /
/// docker-compose / tfstate / Jupyter notebook) but exceeded
/// `MAX_STRUCTURED_PARSE_BYTES`, so its structured decode-through (base64
/// `data:` decoding) was skipped. Distinct from a parse FAILURE: the file is
/// well-formed, just too large for the structured pass. The raw bytes are still
/// scanned, but the regular scan does not recover base64-encoded values, so this
/// is a real recall gap the reporter must surface (Law 10) rather than the bare
/// `return None` that previously dropped it silently.
static STRUCTURED_OVERSIZE_SKIPS: AtomicUsize = AtomicUsize::new(0);
/// Decode-through work was truncated by a safety budget/cap. The raw chunk is
/// still scanned, but secrets only reachable after an omitted recursive decode
/// layer may be missed, so the CLI must surface this as a coverage gap.
static DECODE_TRUNCATIONS: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
thread_local! {
    static THREAD_DECODE_TRUNCATIONS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}
/// A trigger bitmap or compiled pattern-index side table referenced a pattern
/// outside the compiled pattern bitmap. That loses phase-2 admission/expansion
/// coverage for the affected pattern, so the operator must see the partial scan.
static INVALID_PATTERN_INDEX_SKIPS: AtomicUsize = AtomicUsize::new(0);
/// Cross-chunk boundary reassembly could not run because the caller supplied a
/// result vector with different cardinality than the chunk vector.
static BOUNDARY_RESULT_CARDINALITY_MISMATCHES: AtomicUsize = AtomicUsize::new(0);
/// Multiline/structured reassembly produced a synthetic finding mapping whose
/// source line was not present in the caller-provided line-offset table.
static LINE_OFFSET_MAPPING_MISMATCHES: AtomicUsize = AtomicUsize::new(0);

/// Scanner coverage gap recorded when a scanner-owned transform did not run to
/// full coverage. These are not source skips: raw bytes still flow through the
/// scanner, but structured/decode-only secrets may be missed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScannerCoverageGapEvent {
    StructuredParseFailure,
    StructuredOversizeSkip,
    DecodeTruncation,
    InvalidPatternIndexSkip,
    BoundaryResultCardinalityMismatch,
    LineOffsetMappingMismatch,
}

impl ScannerCoverageGapEvent {
    /// Every variant, so the per-scan reset owner (`reset_for_scan`) can zero the
    /// full coverage-gap counter set without a new gap counter ever being forgotten.
    pub(crate) const ALL: [Self; 6] = [
        Self::StructuredParseFailure,
        Self::StructuredOversizeSkip,
        Self::DecodeTruncation,
        Self::InvalidPatternIndexSkip,
        Self::BoundaryResultCardinalityMismatch,
        Self::LineOffsetMappingMismatch,
    ];

    pub(crate) fn counter(self) -> &'static AtomicUsize {
        match self {
            Self::StructuredParseFailure => &STRUCTURED_PARSE_FAILURES,
            Self::StructuredOversizeSkip => &STRUCTURED_OVERSIZE_SKIPS,
            Self::DecodeTruncation => &DECODE_TRUNCATIONS,
            Self::InvalidPatternIndexSkip => &INVALID_PATTERN_INDEX_SKIPS,
            Self::BoundaryResultCardinalityMismatch => &BOUNDARY_RESULT_CARDINALITY_MISMATCHES,
            Self::LineOffsetMappingMismatch => &LINE_OFFSET_MAPPING_MISMATCHES,
        }
    }
}

/// Receipt proving a scanner coverage gap passed through the typed recorder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "scanner coverage gaps must be recorded through the typed recorder so partial coverage remains surfaced"]
pub(crate) struct RecordedScannerCoverageGap {
    event: ScannerCoverageGapEvent,
    previous: usize,
    delta: usize,
}

pub(crate) fn record_scanner_coverage_gap(
    event: ScannerCoverageGapEvent,
) -> RecordedScannerCoverageGap {
    let previous = event.counter().fetch_add(1, Ordering::Relaxed);
    RecordedScannerCoverageGap {
        event,
        previous,
        delta: 1,
    }
}

// Global static dogfood capability flag for fast opt-in checking (KH-120)
static DOGFOOD_ENABLED: AtomicBool = AtomicBool::new(false);

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
    if let Some(enabled) = current_scan_dogfood_enabled() {
        return enabled;
    }
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
    if let Some(t) = current_scan_telemetry() {
        record_example_suppression_in(
            &t.example_suppressions,
            &t.events,
            &t.emitted_suppression_events,
            detector,
            path,
            credential,
            reason,
        );
        return;
    }

    let t = cell();
    record_example_suppression_in(
        &t.example_suppressions,
        &t.events,
        &t.emitted_suppression_events,
        detector,
        path,
        credential,
        reason,
    );
}

fn record_example_suppression_in(
    example_suppressions: &AtomicUsize,
    events: &Mutex<Vec<DogfoodEvent>>,
    emitted_suppression_events: &Mutex<HashSet<String>>,
    detector: &str,
    path: Option<&str>,
    credential: &str,
    reason: &'static str,
) {
    example_suppressions.fetch_add(1, Ordering::Relaxed);

    // KH-120: Wrap dogfood logging events behind static capability flags to eliminate overhead during silent scans.
    if !is_dogfood_enabled() {
        return;
    }

    let credential_hash = keyhog_core::hex_encode(&keyhog_core::sha256_hash(credential));
    // One EVENT per credential across all stages (KH-GAP-091): if a later
    // shape gate already recorded this same credential, or vice-versa, don't emit
    // a duplicate. First stage to reach it wins.
    if !mark_suppression_event_emitted(emitted_suppression_events, &credential_hash) {
        return;
    }

    // KH-disc: use the single canonical redaction policy (`keyhog_core::redact`)
    // so dogfood output matches finding output - the bespoke 6-char-prefix
    // helper leaked up to 6 of 8 bytes of short credentials.
    let redacted = keyhog_core::redact(credential).into_owned();
    if let Ok(mut events) = events.lock() {
        // LAW10: poisoned dogfood telemetry event buffer loses only a diagnostic trace; finding/reporting behavior is unaffected.
        events.push(DogfoodEvent::ExampleSuppressed {
            detector: detector.to_string(),
            path: path.map(str::to_string),
            credential_redacted: redacted,
            reason: Cow::Borrowed(reason),
        });
    }
}

/// Insert `credential_hash` into the shared emitted-event set, returning `true`
/// only the FIRST time a given credential VALUE is seen this scan. Both
/// suppression recorders gate their `events.push` on this so the `--dogfood`
/// trace carries one event per logical suppression rather than one per pipeline
/// stage. The key is the credential hash ALONE — not `path\0hash` — because one
/// logical drop of a credential can be recorded by several stages with
/// INCONSISTENT path context (an early gate knows the file; a later
/// entropy/fallback stage records `path=None`); keying on path would let those
/// re-emit as duplicate events for the same logical suppression (KH-GAP-091). A
/// poisoned lock fails OPEN (returns `true`) — an extra event is a far smaller
/// sin than silently dropping the trace (Law 10).
fn mark_suppression_event_emitted(
    emitted_suppression_events: &Mutex<HashSet<String>>,
    credential_hash: &str,
) -> bool {
    match emitted_suppression_events.lock() {
        Ok(mut emitted) => emitted.insert(credential_hash.to_string()),
        Err(_) => true, // LAW10: poisoned lock => emit the telemetry event anyway (fail-toward-visible); recall-irrelevant suppression-event dedup
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
pub(crate) fn record_shape_suppression(path: Option<&str>, credential: &str, reason: &'static str) {
    // Cheap atomic first - the common (no-dogfood) scan pays nothing beyond this.
    if !is_dogfood_enabled() {
        return;
    }
    if let Some(t) = current_scan_telemetry() {
        record_shape_suppression_in(
            &t.events,
            &t.emitted_suppression_events,
            path,
            credential,
            reason,
        );
        return;
    }
    let t = cell();
    record_shape_suppression_in(
        &t.events,
        &t.emitted_suppression_events,
        path,
        credential,
        reason,
    );
}

fn record_shape_suppression_in(
    events: &Mutex<Vec<DogfoodEvent>>,
    emitted_suppression_events: &Mutex<HashSet<String>>,
    path: Option<&str>,
    credential: &str,
    reason: &'static str,
) {
    let credential_hash = keyhog_core::hex_encode(&keyhog_core::sha256_hash(credential));
    // One EVENT per credential across ALL stages (KH-GAP-091): a credential
    // the example-token gate already recorded (e.g. `AKIA…EXAMPLE`, which is also
    // a weak-anchor shape) must not emit a second shape event for the same
    // logical drop. The shared emitted-set also collapses the same shape gate
    // firing twice for one credential, so this fully replaces the old
    // reason-keyed dedup.
    if !mark_suppression_event_emitted(emitted_suppression_events, &credential_hash) {
        return;
    }
    let redacted = keyhog_core::redact(credential).into_owned();
    if let Ok(mut events) = events.lock() {
        // LAW10: poisoned dogfood telemetry event buffer loses only a diagnostic trace; finding/reporting behavior is unaffected.
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
#[cfg(test)]
pub(crate) fn reset_example_suppression_count() {
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
pub(crate) fn record_structured_parse_failure() {
    let _receipt = record_scanner_coverage_gap(ScannerCoverageGapEvent::StructuredParseFailure);
}

/// Count of files that matched a structured format but failed to parse this scan.
pub fn structured_parse_failure_count() -> usize {
    STRUCTURED_PARSE_FAILURES.load(Ordering::Relaxed)
}

/// Record that a well-formed structured decode-through file (k8s Secret /
/// docker-compose / tfstate / Jupyter notebook) exceeded
/// `MAX_STRUCTURED_PARSE_BYTES`, so its base64 `data:` decode-through was
/// skipped. Always counts: like a parse failure this is a recall-coverage fact
/// the reporter surfaces unconditionally (Law 10), not a silent `return None`.
pub(crate) fn record_structured_oversize_skip() {
    let _receipt = record_scanner_coverage_gap(ScannerCoverageGapEvent::StructuredOversizeSkip);
}

/// Count of decode-through structured files skipped this scan for exceeding the
/// structured-parse size cap.
pub fn structured_oversize_skip_count() -> usize {
    STRUCTURED_OVERSIZE_SKIPS.load(Ordering::Relaxed)
}

/// Record that recursive decode-through stopped before exhausting all available
/// decoder output because a safety budget/cap fired.
pub(crate) fn record_decode_truncation() {
    let _receipt = record_scanner_coverage_gap(ScannerCoverageGapEvent::DecodeTruncation);
    #[cfg(test)]
    THREAD_DECODE_TRUNCATIONS.with(|count| count.set(count.get() + 1));
}

/// Count of decode roots truncated by safety budgets/caps this scan.
#[cfg(not(test))]
pub fn decode_truncation_count() -> usize {
    DECODE_TRUNCATIONS.load(Ordering::Relaxed)
}

/// Count of decode roots truncated by safety budgets/caps on the current test
/// thread. Production still records the global counter; tests read this local
/// view so parallel decode-budget probes cannot pollute exact assertions.
#[cfg(test)]
pub fn decode_truncation_count() -> usize {
    THREAD_DECODE_TRUNCATIONS.with(|count| count.get())
}

/// Record that compiled pattern-index side data referenced an out-of-range
/// pattern and the affected expansion/admission edge had to be skipped.
pub(crate) fn record_invalid_pattern_index_skip() {
    let _receipt = record_scanner_coverage_gap(ScannerCoverageGapEvent::InvalidPatternIndexSkip);
}

/// Count of compiled-pattern expansion/admission edges skipped by invalid
/// pattern indices this scan.
pub fn invalid_pattern_index_skip_count() -> usize {
    INVALID_PATTERN_INDEX_SKIPS.load(Ordering::Relaxed)
}

/// Record that boundary reassembly was skipped because caller-provided chunk
/// and result slices no longer had the same cardinality.
pub(crate) fn record_boundary_result_cardinality_mismatch() {
    let _receipt =
        record_scanner_coverage_gap(ScannerCoverageGapEvent::BoundaryResultCardinalityMismatch);
}

/// Count of boundary-reassembly passes skipped by chunk/result cardinality
/// mismatch this scan.
pub fn boundary_result_cardinality_mismatch_count() -> usize {
    BOUNDARY_RESULT_CARDINALITY_MISMATCHES.load(Ordering::Relaxed)
}

/// Record that source line attribution fell back because a synthetic multiline
/// mapping could not find its line in the original line-offset table.
pub(crate) fn record_line_offset_mapping_mismatch() {
    let _receipt = record_scanner_coverage_gap(ScannerCoverageGapEvent::LineOffsetMappingMismatch);
}

/// Count of synthetic multiline/structured mapping attribution mismatches this
/// scan.
pub fn line_offset_mapping_mismatch_count() -> usize {
    LINE_OFFSET_MAPPING_MISMATCHES.load(Ordering::Relaxed)
}

/// Append events into the per-process buffer without going through the
/// `record_example_suppression` path (no counter bump, no dogfood
/// enable-check). Used by the daemon client to replay events captured
/// on the daemon side, so `--dogfood` output works in daemon mode.
pub fn append_events<I: IntoIterator<Item = DogfoodEvent>>(events: I) {
    let t = cell();
    if let Ok(mut buf) = t.events.lock() {
        // LAW10: poisoned dogfood telemetry event buffer loses only a diagnostic trace; finding/reporting behavior is unaffected.
        buf.extend(events);
    }
}

/// Drain and return all captured dogfood events. Returns empty when
/// `enable_dogfood()` was never called.
pub fn drain_events() -> Vec<DogfoodEvent> {
    let t = cell();
    drain_event_buffers(&t.events, &t.emitted_suppression_events)
}

fn drain_event_buffers(
    events: &Mutex<Vec<DogfoodEvent>>,
    emitted_suppression_events: &Mutex<HashSet<String>>,
) -> Vec<DogfoodEvent> {
    // The drained batch is one complete trace; the next scan must be able to emit
    // its own events for the same credentials, so clear the per-credential
    // emitted-event dedup alongside the drain.
    if let Ok(mut emitted) = emitted_suppression_events.lock() {
        // LAW10: poisoned dogfood dedup set can only duplicate a diagnostic telemetry event; findings/reporting are unaffected.
        emitted.clear();
    }
    if let Ok(mut events) = events.lock() {
        // LAW10: poisoned dogfood event buffer returns empty diagnostics only; this telemetry event drain leaves findings/reporting behavior unaffected.
        std::mem::take(&mut *events)
    } else {
        Vec::new()
    }
}

// Telemetry recording helpers (KH-116)
pub(crate) fn record_file_scanned(bytes: usize) {
    FILES_SCANNED.fetch_add(1, Ordering::Relaxed);
    BYTES_SCANNED.fetch_add(bytes, Ordering::Relaxed);
}

pub(crate) fn record_file_skipped() {
    SKIPPED_FILES.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_match_found() {
    TOTAL_MATCHES.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_gpu_dispatch() {
    GPU_DISPATCHES.fetch_add(1, Ordering::Relaxed);
}

/// Reset process-global telemetry that is scoped to one scan.
///
/// Long-lived callers (CLI library use, daemon-style harnesses, and integration
/// tests) must not let a previous scan's suppression count, dogfood flag, or
/// coverage-gap counters change the next scan's report. Scoped daemon telemetry
/// (`with_scan_telemetry`) remains isolated by its caller-owned handle.
pub fn reset_for_scan() {
    let t = cell();
    DOGFOOD_ENABLED.store(false, Ordering::Relaxed);
    t.dogfood_enabled.store(false, Ordering::Relaxed);
    t.example_suppressions.store(0, Ordering::Relaxed);
    FILES_SCANNED.store(0, Ordering::Relaxed);
    BYTES_SCANNED.store(0, Ordering::Relaxed);
    SKIPPED_FILES.store(0, Ordering::Relaxed);
    TOTAL_MATCHES.store(0, Ordering::Relaxed);
    GPU_DISPATCHES.store(0, Ordering::Relaxed);
    for gap in ScannerCoverageGapEvent::ALL {
        gap.counter().store(0, Ordering::Relaxed);
    }
    #[cfg(test)]
    THREAD_DECODE_TRUNCATIONS.with(|count| count.set(0));
    if let Ok(mut events) = t.events.lock() {
        // LAW10: reset of poisoned dogfood diagnostics cannot hide findings; telemetry event reset only, scan counters are reset above.
        events.clear();
    }
    if let Ok(mut emitted) = t.emitted_suppression_events.lock() {
        // LAW10: reset of poisoned diagnostic dedup cannot hide findings; telemetry event dedup only, scan counters are reset above.
        emitted.clear();
    }
    CURRENT_SCAN_TELEMETRY.with(|slot| {
        *slot.borrow_mut() = None;
    });
}

#[cfg(test)]
#[doc(hidden)]
pub mod testing {
    /// Reset all telemetry state. Test-only facade for integration tests.
    pub fn reset() {
        super::reset_for_scan();
    }
}
