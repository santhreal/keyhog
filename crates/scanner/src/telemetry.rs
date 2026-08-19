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
//! the lightest container. Long-lived daemon workers use [`ScanTelemetry`]
//! scopes so concurrent client scans do not share counts/events.

#[cfg(feature = "decode")]
use keyhog_core::ChunkMetadata;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

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
    /// A bounded static-recovery grammar recognized a candidate expression but
    /// rejected malformed data, an unsafe construct, or a resource limit. The
    /// original source is still scanned. No source bytes are retained.
    StaticRecoveryRejected {
        path: Option<String>,
        expression_offset: usize,
        decoder: Cow<'static, str>,
        reason: Cow<'static, str>,
    },
}

/// Typed reasons emitted when bounded static recovery cannot evaluate a
/// recognized JavaScript expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StaticRecoveryRejection {
    LiteralByteArrayElement,
    JsonBase64,
    JsonUtf8,
    JsonByteArray,
    XorPlaintextUtf8,
    StringJoinJson,
    BufferBase64,
    BufferHex,
    AesKeyLength,
    AesIvLength,
    AesCiphertextBlockLength,
    AesPadding,
    AesPlaintextUtf8,
    UnsupportedCall,
    DynamicPropertyAccess,
    MalformedExpression,
    ResourceLimit,
}

impl StaticRecoveryRejection {
    const ALL: [Self; 17] = [
        Self::LiteralByteArrayElement,
        Self::JsonBase64,
        Self::JsonUtf8,
        Self::JsonByteArray,
        Self::XorPlaintextUtf8,
        Self::StringJoinJson,
        Self::BufferBase64,
        Self::BufferHex,
        Self::AesKeyLength,
        Self::AesIvLength,
        Self::AesCiphertextBlockLength,
        Self::AesPadding,
        Self::AesPlaintextUtf8,
        Self::UnsupportedCall,
        Self::DynamicPropertyAccess,
        Self::MalformedExpression,
        Self::ResourceLimit,
    ];

    const fn index(self) -> usize {
        match self {
            Self::LiteralByteArrayElement => 0,
            Self::JsonBase64 => 1,
            Self::JsonUtf8 => 2,
            Self::JsonByteArray => 3,
            Self::XorPlaintextUtf8 => 4,
            Self::StringJoinJson => 5,
            Self::BufferBase64 => 6,
            Self::BufferHex => 7,
            Self::AesKeyLength => 8,
            Self::AesIvLength => 9,
            Self::AesCiphertextBlockLength => 10,
            Self::AesPadding => 11,
            Self::AesPlaintextUtf8 => 12,
            Self::UnsupportedCall => 13,
            Self::DynamicPropertyAccess => 14,
            Self::MalformedExpression => 15,
            Self::ResourceLimit => 16,
        }
    }

    const fn is_unsupported(self) -> bool {
        matches!(self, Self::UnsupportedCall | Self::DynamicPropertyAccess)
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::LiteralByteArrayElement => "literal_byte_array_element",
            Self::JsonBase64 => "json_base64",
            Self::JsonUtf8 => "json_utf8",
            Self::JsonByteArray => "json_byte_array",
            Self::XorPlaintextUtf8 => "xor_plaintext_utf8",
            Self::StringJoinJson => "string_join_json",
            Self::BufferBase64 => "buffer_base64",
            Self::BufferHex => "buffer_hex",
            Self::AesKeyLength => "aes_key_length",
            Self::AesIvLength => "aes_iv_length",
            Self::AesCiphertextBlockLength => "aes_ciphertext_block_length",
            Self::AesPadding => "aes_padding",
            Self::AesPlaintextUtf8 => "aes_plaintext_utf8",
            Self::UnsupportedCall => "unsupported_call",
            Self::DynamicPropertyAccess => "dynamic_property_access",
            Self::MalformedExpression => "malformed_expression",
            Self::ResourceLimit => "resource_limit",
        }
    }
}

/// Aggregate disposition of bounded JavaScript constant-recovery constructs.
///
/// Counts saturate rather than wrap. Retained dogfood details are independently
/// bounded, so this status remains exact when the detail budget is exhausted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticRecoveryStatus {
    pub supported: u64,
    pub unsupported: u64,
    pub erroneous: u64,
}

/// Maximum retained detail events per scan. Aggregate counters continue past
/// this limit and the omitted count is surfaced in the trace.
pub const DOGFOOD_DETAIL_EVENT_LIMIT: usize = 1024;

fn record_dropped_detail(counter: &AtomicUsize) {
    let mut current = counter.load(Ordering::Relaxed);
    while current != usize::MAX {
        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

fn push_dogfood_detail(
    events: &Mutex<Vec<DogfoodEvent>>,
    detail_events_dropped: &AtomicUsize,
    event: DogfoodEvent,
) -> bool {
    match events.lock() {
        Ok(mut events) if events.len() < DOGFOOD_DETAIL_EVENT_LIMIT => {
            events.push(event);
            true
        }
        Ok(_) | Err(_) => {
            // LAW10: a full or poisoned detail buffer increments the operator-visible dropped-detail counter below.
            record_dropped_detail(detail_events_dropped);
            false
        }
    }
}

fn recover_telemetry_lock<'a, T>(mutex: &'a Mutex<T>) -> std::sync::MutexGuard<'a, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            let guard = poisoned.into_inner();
            mutex.clear_poison();
            guard
        }
    }
}

#[derive(Default)]
pub(crate) struct StaticRecoveryTelemetry {
    counts: [AtomicU64; StaticRecoveryRejection::ALL.len()],
    supported: AtomicU64,
    unsupported: AtomicU64,
    erroneous: AtomicU64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum EmittedDogfoodKey {
    Suppression(String),
    #[cfg(feature = "decode")]
    StaticRecovery {
        source_type: Arc<str>,
        path: Option<Arc<str>>,
        commit: Option<Arc<str>>,
        expression_offset: usize,
        reason: &'static str,
    },
}

impl StaticRecoveryTelemetry {
    fn record(&self, reason: StaticRecoveryRejection) {
        self.add(reason, 1);
    }

    fn add(&self, reason: StaticRecoveryRejection, amount: u64) {
        saturating_add_atomic(&self.counts[reason.index()], amount);
        let disposition = if reason.is_unsupported() {
            &self.unsupported
        } else {
            &self.erroneous
        };
        saturating_add_atomic(disposition, amount);
    }

    fn record_supported(&self, amount: u64) {
        saturating_add_atomic(&self.supported, amount);
    }

    fn snapshot(&self) -> BTreeMap<String, u64> {
        StaticRecoveryRejection::ALL
            .iter()
            .filter_map(|reason| {
                let count = self.counts[reason.index()].load(Ordering::Relaxed);
                (count != 0).then(|| (reason.as_str().to_owned(), count))
            })
            .collect()
    }

    fn status(&self) -> StaticRecoveryStatus {
        StaticRecoveryStatus {
            supported: self.supported.load(Ordering::Relaxed),
            unsupported: self.unsupported.load(Ordering::Relaxed),
            erroneous: self.erroneous.load(Ordering::Relaxed),
        }
    }

    fn reset(&self) {
        for count in &self.counts {
            count.store(0, Ordering::Relaxed);
        }
        self.supported.store(0, Ordering::Relaxed);
        self.unsupported.store(0, Ordering::Relaxed);
        self.erroneous.store(0, Ordering::Relaxed);
    }
}

fn saturating_add_atomic(counter: &AtomicU64, amount: u64) {
    let mut current = counter.load(Ordering::Relaxed);
    while current != u64::MAX {
        let next = current.saturating_add(amount);
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

/// Per-request scanner telemetry container.
///
/// Scoped container that replaces process-global mutable counters. CLI scans
/// and long-lived daemon workers both use [`ScanTelemetry`] scopes installed
/// via [`with_scan_telemetry`] so concurrent scans do not share counts/events.
pub struct ScanTelemetry {
    pub(crate) dogfood_enabled: AtomicBool,
    pub(crate) example_suppressions: AtomicUsize,
    pub(crate) events: Mutex<Vec<DogfoodEvent>>,
    pub(crate) emitted_suppression_events: Mutex<HashSet<EmittedDogfoodKey>>,
    pub(crate) detail_events_dropped: AtomicUsize,
    pub(crate) static_recovery: StaticRecoveryTelemetry,
    pub(crate) vendored_path_suppressions: AtomicUsize,
    pub(crate) vendored_path_suppression_enabled: AtomicBool,
    pub(crate) coverage_gaps: [AtomicUsize; ScannerCoverageGapEvent::ALL.len()],
    pub(crate) files_scanned: AtomicUsize,
    pub(crate) bytes_scanned: AtomicUsize,
    pub(crate) skipped_files: AtomicUsize,
    pub(crate) total_matches: AtomicUsize,
    pub(crate) gpu_dispatches: AtomicUsize,
}

impl Default for ScanTelemetry {
    fn default() -> Self {
        Self {
            dogfood_enabled: AtomicBool::new(false),
            example_suppressions: AtomicUsize::new(0),
            events: Mutex::new(Vec::new()),
            emitted_suppression_events: Mutex::new(HashSet::new()),
            detail_events_dropped: AtomicUsize::new(0),
            static_recovery: StaticRecoveryTelemetry::default(),
            vendored_path_suppressions: AtomicUsize::new(0),
            vendored_path_suppression_enabled: AtomicBool::new(true),
            coverage_gaps: std::array::from_fn(|_| AtomicUsize::new(0)),
            files_scanned: AtomicUsize::new(0),
            bytes_scanned: AtomicUsize::new(0),
            skipped_files: AtomicUsize::new(0),
            total_matches: AtomicUsize::new(0),
            gpu_dispatches: AtomicUsize::new(0),
        }
    }
}

impl ScanTelemetry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset(&self) {
        self.dogfood_enabled.store(false, Ordering::Relaxed);
        self.example_suppressions.store(0, Ordering::Relaxed);
        self.detail_events_dropped.store(0, Ordering::Relaxed);
        self.static_recovery.reset();
        self.vendored_path_suppressions.store(0, Ordering::Relaxed);
        self.vendored_path_suppression_enabled
            .store(true, Ordering::Relaxed);
        for gap in &self.coverage_gaps {
            gap.store(0, Ordering::Relaxed);
        }
        self.files_scanned.store(0, Ordering::Relaxed);
        self.bytes_scanned.store(0, Ordering::Relaxed);
        self.skipped_files.store(0, Ordering::Relaxed);
        self.total_matches.store(0, Ordering::Relaxed);
        self.gpu_dispatches.store(0, Ordering::Relaxed);
        recover_telemetry_lock(&self.events).clear();
        recover_telemetry_lock(&self.emitted_suppression_events).clear();
    }

    pub fn enable_dogfood(&self) {
        self.dogfood_enabled.store(true, Ordering::Relaxed);
    }

    pub fn is_dogfood_enabled(&self) -> bool {
        self.dogfood_enabled.load(Ordering::Relaxed)
    }

    pub fn example_suppression_count(&self) -> usize {
        self.example_suppressions.load(Ordering::Relaxed)
    }

    pub fn drain_events(&self) -> Vec<DogfoodEvent> {
        drain_event_buffers(&self.events, &self.emitted_suppression_events)
    }

    pub fn drain(&self) -> ScanTelemetrySnapshot {
        ScanTelemetrySnapshot {
            example_suppressions: self.example_suppression_count() as u64,
            dogfood_events: self.drain_events(),
            dogfood_detail_events_dropped: self.detail_events_dropped.load(Ordering::Relaxed)
                as u64,
            static_recovery_rejections: self.static_recovery.snapshot(),
            static_recovery_status: self.static_recovery.status(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanTelemetrySnapshot {
    pub example_suppressions: u64,
    pub dogfood_events: Vec<DogfoodEvent>,
    pub dogfood_detail_events_dropped: u64,
    pub static_recovery_rejections: BTreeMap<String, u64>,
    pub static_recovery_status: StaticRecoveryStatus,
}

static GLOBAL_SCAN_TELEMETRY: std::sync::LazyLock<Arc<ScanTelemetry>> =
    std::sync::LazyLock::new(|| Arc::new(ScanTelemetry::new()));

thread_local! {
    static CURRENT_SCAN_TELEMETRY: RefCell<Option<Arc<ScanTelemetry>>> = const { RefCell::new(None) };
}

pub struct ScanTelemetryRestore {
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

/// Enter a scan telemetry scope on this thread, restoring previous scope on drop.
pub fn enter_scan_telemetry_scope(telemetry: &Arc<ScanTelemetry>) -> ScanTelemetryRestore {
    let previous = CURRENT_SCAN_TELEMETRY.with(|slot| {
        let mut slot = slot.borrow_mut();
        slot.replace(Arc::clone(telemetry))
    });
    ScanTelemetryRestore { previous }
}

/// Run `f` with `telemetry` installed for scanner telemetry recorders on this
/// thread. Nested scopes restore the previous owner on drop, including during
/// unwinding.
pub fn with_scan_telemetry<R>(telemetry: &Arc<ScanTelemetry>, f: impl FnOnce() -> R) -> R {
    let _restore = enter_scan_telemetry_scope(telemetry);
    f()
}

pub fn current_scan_telemetry() -> Arc<ScanTelemetry> {
    CURRENT_SCAN_TELEMETRY.with(|slot| {
        if let Some(current) = &*slot.borrow() {
            Arc::clone(current)
        } else {
            Arc::clone(&GLOBAL_SCAN_TELEMETRY)
        }
    })
}

/// Capture the request-scoped telemetry owner before dispatching work to a
/// thread pool. Rayon workers do not inherit thread-local state automatically.
pub(crate) fn capture_scan_telemetry() -> Option<Arc<ScanTelemetry>> {
    CURRENT_SCAN_TELEMETRY.with(|slot| slot.borrow().clone())
}

/// Install a captured request scope for one worker closure. When no request
/// scope exists, execute directly.
pub(crate) fn with_captured_scan_telemetry<R>(
    telemetry: Option<&Arc<ScanTelemetry>>,
    f: impl FnOnce() -> R,
) -> R {
    match telemetry {
        Some(telemetry) => with_scan_telemetry(telemetry, f),
        None => f(),
    }
}

/// Scanner coverage gap recorded when a scanner-owned transform did not run to
/// full coverage. These are not source skips: raw bytes still flow through the
/// scanner, but structured/decode-only secrets may be missed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScannerCoverageGapEvent {
    StructuredParseFailure,
    StructuredOversizeSkip,
    DecodeTruncation,
    DecodeOversizeSkip,
    InvalidPatternIndexSkip,
    BoundaryResultCardinalityMismatch,
    BoundarySeamTruncation,
    LineOffsetMappingMismatch,
    ChunkDeadlineAbort,
    BinaryStringsNamedExclusion,
}

impl ScannerCoverageGapEvent {
    /// Every variant, so the per-scan reset owner (`reset_for_scan`) can zero the
    /// full coverage-gap counter set without a new gap counter ever being forgotten.
    pub(crate) const ALL: [Self; 10] = [
        Self::StructuredParseFailure,
        Self::StructuredOversizeSkip,
        Self::DecodeTruncation,
        Self::DecodeOversizeSkip,
        Self::InvalidPatternIndexSkip,
        Self::BoundaryResultCardinalityMismatch,
        Self::BoundarySeamTruncation,
        Self::LineOffsetMappingMismatch,
        Self::ChunkDeadlineAbort,
        Self::BinaryStringsNamedExclusion,
    ];

    pub(crate) const fn index(self) -> usize {
        match self {
            Self::StructuredParseFailure => 0,
            Self::StructuredOversizeSkip => 1,
            Self::DecodeTruncation => 2,
            Self::DecodeOversizeSkip => 3,
            Self::InvalidPatternIndexSkip => 4,
            Self::BoundaryResultCardinalityMismatch => 5,
            Self::BoundarySeamTruncation => 6,
            Self::LineOffsetMappingMismatch => 7,
            Self::ChunkDeadlineAbort => 8,
            Self::BinaryStringsNamedExclusion => 9,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::StructuredParseFailure => "structured_parse_failures",
            Self::StructuredOversizeSkip => "structured_oversize_skips",
            Self::DecodeTruncation => "decode_truncations",
            Self::DecodeOversizeSkip => "decode_oversize_skips",
            Self::InvalidPatternIndexSkip => "invalid_pattern_index_skips",
            Self::BoundaryResultCardinalityMismatch => "boundary_result_cardinality_mismatches",
            Self::BoundarySeamTruncation => "boundary_seam_truncations",
            Self::LineOffsetMappingMismatch => "line_offset_mapping_mismatches",
            Self::ChunkDeadlineAbort => "chunk_deadline_aborts",
            Self::BinaryStringsNamedExclusion => "binary_strings_named_exclusions",
        }
    }

    pub(crate) const fn counter_id(self) -> keyhog_profile::CounterId {
        match self {
            Self::StructuredParseFailure => keyhog_profile::CounterId::StructuredParseFailures,
            Self::StructuredOversizeSkip => keyhog_profile::CounterId::StructuredOversizeSkips,
            Self::DecodeTruncation => keyhog_profile::CounterId::DecodeTruncations,
            Self::DecodeOversizeSkip => keyhog_profile::CounterId::DecodeOversizeSkips,
            Self::InvalidPatternIndexSkip => keyhog_profile::CounterId::InvalidPatternIndexSkips,
            Self::BoundaryResultCardinalityMismatch => {
                keyhog_profile::CounterId::BoundaryResultCardinalityMismatches
            }
            Self::BoundarySeamTruncation => keyhog_profile::CounterId::BoundarySeamTruncations,
            Self::LineOffsetMappingMismatch => {
                keyhog_profile::CounterId::LineOffsetMappingMismatches
            }
            Self::ChunkDeadlineAbort => keyhog_profile::CounterId::ChunkDeadlineAborts,
            Self::BinaryStringsNamedExclusion => {
                keyhog_profile::CounterId::BinaryStringsNamedExclusions
            }
        }
    }

    pub(crate) fn count(self) -> usize {
        let t = current_scan_telemetry();
        t.coverage_gaps[self.index()].load(Ordering::Relaxed)
    }

    pub(crate) fn store(self, value: usize) {
        let t = current_scan_telemetry();
        t.coverage_gaps[self.index()].store(value, Ordering::Relaxed);
    }
}

/// Exact scanner-owned coverage-gap counters at one point in time.
///
/// Taking a saturating delta around a scan gives autoroute and other embedding
/// surfaces a typed completeness receipt without resetting process-wide state.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct ScannerCoverageSnapshot {
    counts: [usize; ScannerCoverageGapEvent::ALL.len()],
}

impl ScannerCoverageSnapshot {
    #[must_use]
    pub fn capture() -> Self {
        let t = current_scan_telemetry();
        Self {
            counts: std::array::from_fn(|index| t.coverage_gaps[index].load(Ordering::Relaxed)),
        }
    }

    #[must_use]
    pub fn saturating_delta(self, earlier: Self) -> Self {
        Self {
            counts: std::array::from_fn(|index| {
                self.counts[index].saturating_sub(earlier.counts[index])
            }),
        }
    }

    #[must_use]
    pub fn is_empty(self) -> bool {
        self.counts.iter().all(|count| *count == 0)
    }
}

impl std::fmt::Debug for ScannerCoverageSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut gaps = formatter.debug_map();
        for (event, count) in ScannerCoverageGapEvent::ALL.into_iter().zip(self.counts) {
            if count > 0 {
                gaps.entry(&event.label(), &count);
            }
        }
        gaps.finish()
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
    let t = current_scan_telemetry();
    let previous = t.coverage_gaps[event.index()].fetch_add(1, Ordering::Relaxed);
    keyhog_profile::add_counter(event.counter_id(), 1);
    RecordedScannerCoverageGap {
        event,
        previous,
        delta: 1,
    }
}

pub fn enable_dogfood() {
    current_scan_telemetry().enable_dogfood();
}

pub fn is_dogfood_enabled() -> bool {
    current_scan_telemetry().is_dogfood_enabled()
}
/// Enable or disable the vendored/minified path suppression for this process.
///
/// Call AFTER [`reset_for_scan`], which restores the default. The suppression is
/// consulted on every surviving finding, so the read below is a relaxed atomic
/// load and nothing more.
pub fn set_vendored_path_suppression(enabled: bool) {
    current_scan_telemetry()
        .vendored_path_suppression_enabled
        .store(enabled, Ordering::Relaxed);
}

pub fn vendored_path_suppression_enabled() -> bool {
    current_scan_telemetry()
        .vendored_path_suppression_enabled
        .load(Ordering::Relaxed)
}

pub(crate) fn record_vendored_path_suppression() {
    current_scan_telemetry()
        .vendored_path_suppressions
        .fetch_add(1, Ordering::Relaxed);
    keyhog_profile::add_counter(keyhog_profile::CounterId::VendoredPathSuppressions, 1);
}

pub fn vendored_path_suppression_count() -> usize {
    current_scan_telemetry()
        .vendored_path_suppressions
        .load(Ordering::Relaxed)
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
    let t = current_scan_telemetry();
    record_example_suppression_in(
        &t.example_suppressions,
        &t.events,
        &t.emitted_suppression_events,
        &t.detail_events_dropped,
        detector,
        path,
        credential,
        reason,
    );
}

fn record_example_suppression_in(
    example_suppressions: &AtomicUsize,
    events: &Mutex<Vec<DogfoodEvent>>,
    emitted_suppression_events: &Mutex<HashSet<EmittedDogfoodKey>>,
    detail_events_dropped: &AtomicUsize,
    detector: &str,
    path: Option<&str>,
    credential: &str,
    reason: &'static str,
) {
    example_suppressions.fetch_add(1, Ordering::Relaxed);
    keyhog_profile::add_counter(keyhog_profile::CounterId::ExampleSuppressions, 1);
    // KH-120: Wrap dogfood logging events behind static capability flags to eliminate overhead during silent scans.
    if !is_dogfood_enabled() {
        return;
    }

    let credential_hash = keyhog_core::hex_encode(&keyhog_core::sha256_hash(credential));
    // One EVENT per credential across all stages (KH-GAP-091): if a later
    // shape gate already recorded this same credential, or vice-versa, don't emit
    // a duplicate. First stage to reach it wins.
    if !mark_suppression_event_emitted(
        emitted_suppression_events,
        detail_events_dropped,
        &credential_hash,
    ) {
        return;
    }

    // KH-disc: use the single canonical redaction policy (`keyhog_core::redact`)
    // so dogfood output matches finding output - the bespoke 6-char-prefix
    // helper leaked up to 6 of 8 bytes of short credentials.
    let redacted = keyhog_core::redact(credential).into_owned();
    push_dogfood_detail(
        events,
        detail_events_dropped,
        DogfoodEvent::ExampleSuppressed {
            detector: detector.to_string(),
            path: path.map(str::to_string),
            credential_redacted: redacted,
            reason: Cow::Borrowed(reason),
        },
    );
}

/// Insert `credential_hash` into the shared emitted-event set, returning `true`
/// only the FIRST time a given credential VALUE is seen this scan. Both
/// suppression recorders gate their `events.push` on this so the `--dogfood`
/// trace carries one event per logical suppression rather than one per pipeline
/// stage. The key is the credential hash ALONE, not `path\0hash`: because one
/// logical drop of a credential can be recorded by several stages with
/// INCONSISTENT path context (an early gate knows the file; a later
/// entropy/fallback stage records `path=None`); keying on path would let those
/// re-emit as duplicate events for the same logical suppression (KH-GAP-091).
/// The shared detail budget bounds both this set and the event vector. Once it
/// is exhausted, the exact dropped-detail counter remains operator-visible.
fn mark_suppression_event_emitted(
    emitted_suppression_events: &Mutex<HashSet<EmittedDogfoodKey>>,
    detail_events_dropped: &AtomicUsize,
    credential_hash: &str,
) -> bool {
    match emitted_suppression_events.lock() {
        Ok(mut emitted) => {
            let key = EmittedDogfoodKey::Suppression(credential_hash.to_owned());
            if emitted.contains(&key) {
                return false;
            }
            if emitted.len() >= DOGFOOD_DETAIL_EVENT_LIMIT {
                record_dropped_detail(detail_events_dropped);
                return false;
            }
            emitted.insert(key)
        }
        Err(_) => {
            // LAW10: poisoned diagnostic dedup increments the surfaced omitted-detail counter; findings and exact aggregates remain intact.
            record_dropped_detail(detail_events_dropped);
            false // LAW10: poisoned diagnostic dedup is surfaced as one omitted detail; finding and exact aggregate counters are unchanged.
        }
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
    if !is_dogfood_enabled() {
        return;
    }
    let t = current_scan_telemetry();
    record_shape_suppression_in(
        &t.events,
        &t.emitted_suppression_events,
        &t.detail_events_dropped,
        path,
        credential,
        reason,
    );
}

/// Record a static-recovery rejection in the dogfood trace. Deduplication keeps
/// repeated references to the same rejected expression from producing noise.
#[cfg(feature = "decode")]
pub(crate) fn record_static_recovery_rejection(
    metadata: &ChunkMetadata,
    expression_offset: usize,
    reason: StaticRecoveryRejection,
) {
    let t = current_scan_telemetry();
    t.static_recovery.record(reason);
    if !t.is_dogfood_enabled() {
        return;
    }
    if !mark_static_recovery_event_emitted(
        &t.emitted_suppression_events,
        &t.detail_events_dropped,
        metadata,
        expression_offset,
        reason,
    ) {
        return;
    }
    push_dogfood_detail(
        &t.events,
        &t.detail_events_dropped,
        static_recovery_event(metadata, expression_offset, reason),
    );
}

#[cfg(feature = "decode")]
pub(crate) fn record_static_recovery_supported(count: usize) {
    if count == 0 {
        return;
    }
    let amount = u64::try_from(count).unwrap_or(u64::MAX); // LAW10: usize is at most 64 bits on every supported target, so this fallback is unreachable; saturation stays conservative if that target contract ever expands.
    current_scan_telemetry()
        .static_recovery
        .record_supported(amount);
}

#[cfg(feature = "decode")]
fn static_recovery_event(
    metadata: &ChunkMetadata,
    expression_offset: usize,
    reason: StaticRecoveryRejection,
) -> DogfoodEvent {
    DogfoodEvent::StaticRecoveryRejected {
        path: metadata.path.as_deref().map(str::to_owned),
        expression_offset,
        decoder: Cow::Borrowed("javascript-static"),
        reason: Cow::Borrowed(reason.as_str()),
    }
}

#[cfg(feature = "decode")]
fn mark_static_recovery_event_emitted(
    emitted_events: &Mutex<HashSet<EmittedDogfoodKey>>,
    detail_events_dropped: &AtomicUsize,
    metadata: &ChunkMetadata,
    expression_offset: usize,
    reason: StaticRecoveryRejection,
) -> bool {
    let key = EmittedDogfoodKey::StaticRecovery {
        source_type: Arc::clone(&metadata.source_type),
        path: metadata.path.clone(),
        commit: metadata.commit.clone(),
        expression_offset,
        reason: reason.as_str(),
    };
    match emitted_events.lock() {
        Ok(mut emitted) => {
            if emitted.contains(&key) {
                return false;
            }
            if emitted.len() >= DOGFOOD_DETAIL_EVENT_LIMIT {
                record_dropped_detail(detail_events_dropped);
                return false;
            }
            emitted.insert(key)
        }
        Err(_) => {
            // LAW10: poisoned diagnostic dedup increments the surfaced omitted-detail counter; findings and exact aggregates remain intact.
            record_dropped_detail(detail_events_dropped);
            false // LAW10: poisoned diagnostic dedup is surfaced as one omitted detail; scan findings and exact rejection counters are unchanged.
        }
    }
}

fn record_shape_suppression_in(
    events: &Mutex<Vec<DogfoodEvent>>,
    emitted_suppression_events: &Mutex<HashSet<EmittedDogfoodKey>>,
    detail_events_dropped: &AtomicUsize,
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
    if !mark_suppression_event_emitted(
        emitted_suppression_events,
        detail_events_dropped,
        &credential_hash,
    ) {
        return;
    }
    let redacted = keyhog_core::redact(credential).into_owned();
    push_dogfood_detail(
        events,
        detail_events_dropped,
        DogfoodEvent::ShapeSuppressed {
            path: path.map(str::to_string),
            credential_redacted: redacted,
            reason: Cow::Borrowed(reason),
        },
    );
}

/// Count of example/placeholder credentials suppressed during this scan.
pub fn example_suppression_count() -> usize {
    current_scan_telemetry().example_suppression_count()
}

#[cfg(test)]
pub(crate) fn reset_example_suppression_count() {
    current_scan_telemetry()
        .example_suppressions
        .store(0, Ordering::Relaxed);
}

pub fn add_example_suppressions(n: usize) {
    current_scan_telemetry()
        .example_suppressions
        .fetch_add(n, Ordering::Relaxed);
    keyhog_profile::add_counter(keyhog_profile::CounterId::ExampleSuppressions, n as u64);
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
    current_scan_telemetry().coverage_gaps[ScannerCoverageGapEvent::StructuredParseFailure.index()]
        .load(Ordering::Relaxed)
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
    current_scan_telemetry().coverage_gaps[ScannerCoverageGapEvent::StructuredOversizeSkip.index()]
        .load(Ordering::Relaxed)
}

/// Record that recursive decode-through stopped before exhausting all available
/// decoder output because a safety budget/cap fired.
pub(crate) fn record_decode_truncation() {
    let _receipt = record_scanner_coverage_gap(ScannerCoverageGapEvent::DecodeTruncation);
}

pub fn decode_truncation_count() -> usize {
    current_scan_telemetry().coverage_gaps[ScannerCoverageGapEvent::DecodeTruncation.index()]
        .load(Ordering::Relaxed)
}

/// Record that a chunk carrying decode candidates was denied decode-through
/// entirely because it exceeded `max_decode_bytes`.
///
/// Callers MUST establish that the chunk would otherwise have been admitted
/// (`decoder_admission != Impossible` and `max_decode_depth > 0`); counting
/// every oversize chunk would be false-loud on the overwhelming majority that
/// contain no encoded content at all.
pub(crate) fn record_decode_oversize_skip() {
    let _receipt = record_scanner_coverage_gap(ScannerCoverageGapEvent::DecodeOversizeSkip);
}

/// Count of decode-candidate-bearing chunks denied decode-through this scan for
/// exceeding `max_decode_bytes` (`--decode-size-limit`).
pub fn decode_oversize_skip_count() -> usize {
    current_scan_telemetry().coverage_gaps[ScannerCoverageGapEvent::DecodeOversizeSkip.index()]
        .load(Ordering::Relaxed)
}

/// Record that compiled pattern-index side data referenced an out-of-range
/// pattern and the affected expansion/admission edge had to be skipped.
pub(crate) fn record_invalid_pattern_index_skip() {
    let _receipt = record_scanner_coverage_gap(ScannerCoverageGapEvent::InvalidPatternIndexSkip);
}

/// Count of compiled-pattern expansion/admission edges skipped by invalid
/// pattern indices this scan.
pub fn invalid_pattern_index_skip_count() -> usize {
    current_scan_telemetry().coverage_gaps[ScannerCoverageGapEvent::InvalidPatternIndexSkip.index()]
        .load(Ordering::Relaxed)
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
    current_scan_telemetry().coverage_gaps
        [ScannerCoverageGapEvent::BoundaryResultCardinalityMismatch.index()]
    .load(Ordering::Relaxed)
}

/// Record that cross-chunk boundary reassembly was truncated by MAX_BOUNDARY_SEAM_BYTES
/// for an unbounded detector regex or entropy.
pub(crate) fn record_boundary_seam_truncation() {
    let _receipt = record_scanner_coverage_gap(ScannerCoverageGapEvent::BoundarySeamTruncation);
}

/// Count of cross-chunk boundary reassembly passes truncated by MAX_BOUNDARY_SEAM_BYTES
/// this scan.
pub fn boundary_seam_truncation_count() -> usize {
    current_scan_telemetry().coverage_gaps[ScannerCoverageGapEvent::BoundarySeamTruncation.index()]
        .load(Ordering::Relaxed)
}

/// Record that source line attribution fell back because a synthetic multiline
/// mapping could not find its line in the original line-offset table.
#[cfg(feature = "multiline")]
pub(crate) fn record_line_offset_mapping_mismatch() {
    let _receipt = record_scanner_coverage_gap(ScannerCoverageGapEvent::LineOffsetMappingMismatch);
}

/// Record that a configured deadline stopped a chunk before full coverage.
pub(crate) fn record_chunk_deadline_abort() {
    let _receipt = record_scanner_coverage_gap(ScannerCoverageGapEvent::ChunkDeadlineAbort);
}

/// Count of chunks that stopped before full coverage because their deadline elapsed.
pub fn chunk_deadline_abort_count() -> usize {
    current_scan_telemetry().coverage_gaps[ScannerCoverageGapEvent::ChunkDeadlineAbort.index()]
        .load(Ordering::Relaxed)
}

/// Record a named-detector match withheld by the binary-strings noise gate.
pub(crate) fn record_binary_strings_named_exclusion() {
    let _receipt =
        record_scanner_coverage_gap(ScannerCoverageGapEvent::BinaryStringsNamedExclusion);
}

/// Count of named-detector matches withheld from binary-derived chunks this
/// scan for lack of structural proof.
pub fn binary_strings_named_exclusion_count() -> usize {
    current_scan_telemetry().coverage_gaps
        [ScannerCoverageGapEvent::BinaryStringsNamedExclusion.index()]
    .load(Ordering::Relaxed)
}

pub fn line_offset_mapping_mismatch_count() -> usize {
    current_scan_telemetry().coverage_gaps
        [ScannerCoverageGapEvent::LineOffsetMappingMismatch.index()]
    .load(Ordering::Relaxed)
}

/// Append events into the per-process buffer without going through the
/// `record_example_suppression` path (no counter bump, no dogfood
/// enable-check). Used by the daemon client to replay events captured
/// on the daemon side, so `--dogfood` output works in daemon mode.
pub fn append_events<I: IntoIterator<Item = DogfoodEvent>>(events: I) {
    append_event_details(events, true);
}

/// Append detail events transported with exact daemon aggregates.
///
/// Unlike [`append_events`], this does not infer static-recovery counts from
/// the bounded detail list. Call [`merge_daemon_aggregates`] once for the same
/// response so retained details and exact totals cannot be double-counted.
pub fn append_daemon_events<I: IntoIterator<Item = DogfoodEvent>>(events: I) {
    append_event_details(events, false);
}

fn append_event_details<I: IntoIterator<Item = DogfoodEvent>>(
    events: I,
    infer_static_recovery_counts: bool,
) {
    let t = current_scan_telemetry();
    for event in events {
        if infer_static_recovery_counts {
            let DogfoodEvent::StaticRecoveryRejected { reason, .. } = &event else {
                push_dogfood_detail(&t.events, &t.detail_events_dropped, event);
                continue;
            };
            if let Some(reason) = StaticRecoveryRejection::ALL
                .iter()
                .find(|candidate| candidate.as_str() == reason.as_ref())
            {
                t.static_recovery.record(*reason);
            }
        }
        push_dogfood_detail(&t.events, &t.detail_events_dropped, event);
    }
}

/// Merge exact dogfood aggregates returned by a compatible daemon scan.
///
/// Detail events are transported separately through [`append_daemon_events`]. This
/// method validates every typed rejection reason and the disposition conservation
/// invariant before mutating process state, so a response from an incompatible
/// daemon fails instead of producing a plausible but incomplete trace.
pub fn merge_daemon_aggregates(
    static_recovery_rejections: &BTreeMap<String, u64>,
    static_recovery_status: StaticRecoveryStatus,
    detail_events_dropped: u64,
) -> Result<(), String> {
    let mut resolved = Vec::with_capacity(static_recovery_rejections.len());
    let mut unsupported = 0_u64;
    let mut erroneous = 0_u64;
    for (name, count) in static_recovery_rejections {
        let Some(reason) = StaticRecoveryRejection::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.as_str() == name)
        else {
            return Err(format!(
                "daemon returned unknown static-recovery rejection reason {name:?}; restart it with this KeyHog build"
            ));
        };
        let disposition = if reason.is_unsupported() {
            &mut unsupported
        } else {
            &mut erroneous
        };
        *disposition = disposition.checked_add(*count).ok_or_else(|| {
            format!(
                "daemon static-recovery {kind} reason counts overflowed u64",
                kind = if reason.is_unsupported() {
                    "unsupported"
                } else {
                    "erroneous"
                }
            )
        })?;
        resolved.push((reason, *count));
    }
    if unsupported != static_recovery_status.unsupported
        || erroneous != static_recovery_status.erroneous
    {
        return Err(format!(
            "daemon static-recovery aggregate conservation failed: \
             reasons unsupported={unsupported}, erroneous={erroneous}; \
             status unsupported={}, erroneous={}",
            static_recovery_status.unsupported, static_recovery_status.erroneous
        ));
    }

    let telemetry = current_scan_telemetry();
    telemetry
        .static_recovery
        .record_supported(static_recovery_status.supported);
    for (reason, count) in resolved {
        telemetry.static_recovery.add(reason, count);
    }
    let dropped = usize::try_from(detail_events_dropped).unwrap_or(usize::MAX); // LAW10: wire counts wider than this host can represent remain surfaced at the largest representable count; scan findings are unchanged.
    let counter = &telemetry.detail_events_dropped;
    let mut current = counter.load(Ordering::Relaxed);
    while current != usize::MAX {
        match counter.compare_exchange_weak(
            current,
            current.saturating_add(dropped),
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
    Ok(())
}

/// Exact per-reason static-recovery rejection counts for the current process
/// scan. Detail-event deduplication and retention limits never change these
/// aggregates.
pub fn static_recovery_rejection_counts() -> BTreeMap<String, u64> {
    current_scan_telemetry().static_recovery.snapshot()
}

pub fn static_recovery_status() -> StaticRecoveryStatus {
    current_scan_telemetry().static_recovery.status()
}

pub fn dogfood_detail_events_dropped() -> usize {
    current_scan_telemetry()
        .detail_events_dropped
        .load(Ordering::Relaxed)
}

pub fn drain_events() -> Vec<DogfoodEvent> {
    current_scan_telemetry().drain_events()
}

fn drain_event_buffers(
    events: &Mutex<Vec<DogfoodEvent>>,
    emitted_suppression_events: &Mutex<HashSet<EmittedDogfoodKey>>,
) -> Vec<DogfoodEvent> {
    // The drained batch is one complete trace; the next scan must be able to emit
    // its own events for the same credentials, so clear the per-credential
    // emitted-event dedup alongside the drain.
    recover_telemetry_lock(emitted_suppression_events).clear();
    std::mem::take(&mut *recover_telemetry_lock(events))
}

// Telemetry recording helpers (KH-116)
pub(crate) fn record_file_scanned(bytes: usize) {
    let t = current_scan_telemetry();
    t.files_scanned.fetch_add(1, Ordering::Relaxed);
    t.bytes_scanned.fetch_add(bytes, Ordering::Relaxed);
    keyhog_profile::add_counter(keyhog_profile::CounterId::FilesScanned, 1);
    keyhog_profile::add_counter(keyhog_profile::CounterId::BytesScanned, bytes as u64);
}

pub(crate) fn global_scan_counts() -> (usize, usize) {
    let t = current_scan_telemetry();
    (
        t.files_scanned.load(Ordering::Relaxed),
        t.bytes_scanned.load(Ordering::Relaxed),
    )
}

pub(crate) fn record_file_skipped() {
    current_scan_telemetry()
        .skipped_files
        .fetch_add(1, Ordering::Relaxed);
    keyhog_profile::add_counter(keyhog_profile::CounterId::SkippedFiles, 1);
}

pub(crate) fn record_match_found() {
    current_scan_telemetry()
        .total_matches
        .fetch_add(1, Ordering::Relaxed);
    keyhog_profile::add_counter(keyhog_profile::CounterId::MatchesFound, 1);
}

pub(crate) fn record_gpu_dispatch() {
    current_scan_telemetry()
        .gpu_dispatches
        .fetch_add(1, Ordering::Relaxed);
    keyhog_profile::add_counter(keyhog_profile::CounterId::GpuDispatchCalls, 1);
}

/// Reset process-global telemetry that is scoped to one scan.
pub fn reset_for_scan() {
    GLOBAL_SCAN_TELEMETRY.reset();
    current_scan_telemetry().reset();
}

#[cfg(test)]
#[doc(hidden)]
pub mod testing {
    use std::sync::Arc;

    /// Reset all telemetry state. Test-only facade for integration tests.
    pub fn reset() {
        super::reset_for_scan();
    }

    pub(crate) fn poison_events(telemetry: &Arc<super::ScanTelemetry>) {
        let telemetry = Arc::clone(telemetry);
        let _ = std::thread::spawn(move || {
            // LAW10: this cfg(test) helper has no production runtime effect; it joins an expected panic to poison a disposable scoped buffer.
            let Ok(_events) = telemetry.events.lock() else {
                panic!("fresh telemetry event buffer was already poisoned");
            };
            panic!("poison scoped telemetry event buffer");
        })
        .join();
    }
}
