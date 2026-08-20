use std::cell::RefCell;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::ThreadId;

/// Scoped source skip telemetry container.
///
/// Replaces process-global atomic counters with a scoped container that can be
/// installed per unit of work (CLI scan, daemon request, or test scope) via
/// [`with_source_telemetry`].
#[derive(Debug)]
pub struct SourceSkipTelemetry {
    counters: [AtomicUsize; 11],
}

impl Default for SourceSkipTelemetry {
    fn default() -> Self {
        Self {
            counters: std::array::from_fn(|_| AtomicUsize::new(0)),
        }
    }
}

impl SourceSkipTelemetry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset(&self) {
        for counter in &self.counters {
            counter.store(0, Relaxed);
        }
    }

    pub fn snapshot(&self) -> SkipCounts {
        SkipCounts {
            over_max_size: self.counters[0].load(Relaxed),
            binary: self.counters[1].load(Relaxed),
            excluded: self.counters[2].load(Relaxed),
            unreadable: self.counters[3].load(Relaxed),
            git_object_unreadable: self.counters[4].load(Relaxed),
            archive_truncated: self.counters[5].load(Relaxed),
            binary_section_name_unresolved: self.counters[6].load(Relaxed),
            source_truncated: self.counters[7].load(Relaxed),
            structured_source_parse_failures: self.counters[8].load(Relaxed),
            archive_duplicate_scan_unavailable: self.counters[9].load(Relaxed),
            git_lfs_pointer: self.counters[10].load(Relaxed),
        }
    }
}

static GLOBAL_SOURCE_TELEMETRY: std::sync::LazyLock<Arc<SourceSkipTelemetry>> =
    std::sync::LazyLock::new(|| Arc::new(SourceSkipTelemetry::new()));

thread_local! {
    static CURRENT_SOURCE_TELEMETRY: RefCell<Option<Arc<SourceSkipTelemetry>>> = const { RefCell::new(None) };
}

struct SourceTelemetryRestore {
    previous: Option<Arc<SourceSkipTelemetry>>,
}

impl Drop for SourceTelemetryRestore {
    fn drop(&mut self) {
        let previous = self.previous.take();
        CURRENT_SOURCE_TELEMETRY.with(|slot| {
            *slot.borrow_mut() = previous;
        });
    }
}

/// Run `f` with `telemetry` installed for source skip counters on this thread.
pub fn with_source_telemetry<R>(telemetry: &Arc<SourceSkipTelemetry>, f: impl FnOnce() -> R) -> R {
    let previous = CURRENT_SOURCE_TELEMETRY.with(|slot| {
        let mut slot = slot.borrow_mut();
        slot.replace(Arc::clone(telemetry))
    });
    let _restore = SourceTelemetryRestore { previous };
    f()
}

/// Capture the active source telemetry scope before dispatching to thread pools.
pub fn capture_source_telemetry() -> Option<Arc<SourceSkipTelemetry>> {
    CURRENT_SOURCE_TELEMETRY.with(|slot| slot.borrow().clone())
}

/// Run `f` with the captured source telemetry installed.
pub fn with_captured_source_telemetry<R>(
    telemetry: Option<&Arc<SourceSkipTelemetry>>,
    f: impl FnOnce() -> R,
) -> R {
    match telemetry {
        Some(telemetry) => with_source_telemetry(telemetry, f),
        None => f(),
    }
}

/// Return the currently active source telemetry handle for this thread.
pub fn current_source_telemetry() -> Arc<SourceSkipTelemetry> {
    CURRENT_SOURCE_TELEMETRY.with(|slot| {
        if let Some(current) = &*slot.borrow() {
            Arc::clone(current)
        } else {
            Arc::clone(&GLOBAL_SOURCE_TELEMETRY)
        }
    })
}

/// Immutable snapshot of the skip counters, read once at end-of-scan so every
/// reporter (human summary + structured JSON/SARIF) surfaces the same numbers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SkipCounts {
    pub over_max_size: usize,
    pub binary: usize,
    pub excluded: usize,
    pub unreadable: usize,
    /// Git commit/tree/blob objects referenced by Git metadata but not scanned
    /// because the object was unreadable or the wrong kind.
    pub git_object_unreadable: usize,
    /// Archives truncated by a decompression-bomb guard (partial coverage).
    pub archive_truncated: usize,
    /// Binary sections dropped because their name could not be resolved from a
    /// corrupt section-name string table (partial binary parse).
    pub binary_section_name_unresolved: usize,
    /// Source scans stopped early by a source-level aggregate cap.
    pub source_truncated: usize,
    /// Structured source files whose format-specific parser failed; raw text was
    /// still scanned, but derived chunks/decoded bodies were not expanded.
    pub structured_source_parse_failures: usize,
    /// Archives where zip duplicate-entry detection could not run (zip64 or a
    /// malformed central directory); the standard parser still scanned them but
    /// may have missed a duplicated/shadow entry.
    pub archive_duplicate_scan_unavailable: usize,
    /// Git-LFS pointer files whose referenced blob was not on disk to scan (the
    /// pointer text was scanned; the real content in LFS storage was not).
    pub git_lfs_pointer: usize,
}

impl SkipCounts {
    /// Total files skipped (not scanned) across all categories.
    ///
    /// Git object unreadability is source-object partial coverage, not a
    /// whole-file skip. `binary_section_name_unresolved`, `source_truncated`,
    /// `structured_source_parse_failures`, and
    /// `archive_duplicate_scan_unavailable` are partial-coverage signals, not
    /// whole-file skips, so they are surfaced separately and are NOT added into
    /// this file-skip total.
    pub fn total(&self) -> usize {
        self.over_max_size + self.binary + self.excluded + self.unreadable + self.archive_truncated
    }
}

/// Typed source coverage gap recorded when input bytes are deliberately not
/// scanned or only partially scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceSkipEvent {
    OverMaxSize,
    Binary,
    Excluded,
    Unreadable,
    GitObjectUnreadable,
    ArchiveTruncated,
    #[allow(dead_code)]
    BinarySectionNameUnresolved,
    SourceTruncated,
    StructuredSourceParseFailure,
    ArchiveDuplicateScanUnavailable,
    GitLfsPointer,
}

impl SourceSkipEvent {
    pub(crate) const fn index(self) -> usize {
        match self {
            Self::OverMaxSize => 0,
            Self::Binary => 1,
            Self::Excluded => 2,
            Self::Unreadable => 3,
            Self::GitObjectUnreadable => 4,
            Self::ArchiveTruncated => 5,
            Self::BinarySectionNameUnresolved => 6,
            Self::SourceTruncated => 7,
            Self::StructuredSourceParseFailure => 8,
            Self::ArchiveDuplicateScanUnavailable => 9,
            Self::GitLfsPointer => 10,
        }
    }

    pub(crate) const fn counter_id(self) -> keyhog_profile::CounterId {
        match self {
            Self::OverMaxSize => keyhog_profile::CounterId::SkippedOverMaxSize,
            Self::Binary => keyhog_profile::CounterId::SkippedBinary,
            Self::Excluded => keyhog_profile::CounterId::SkippedExcluded,
            Self::Unreadable => keyhog_profile::CounterId::SkippedUnreadable,
            Self::GitObjectUnreadable => keyhog_profile::CounterId::GitObjectUnreadable,
            Self::ArchiveTruncated => keyhog_profile::CounterId::SkippedArchiveTruncated,
            Self::BinarySectionNameUnresolved => {
                keyhog_profile::CounterId::BinarySectionNameUnresolved
            }
            Self::SourceTruncated => keyhog_profile::CounterId::SourceTruncated,
            Self::StructuredSourceParseFailure => {
                keyhog_profile::CounterId::StructuredSourceParseFailures
            }
            Self::ArchiveDuplicateScanUnavailable => {
                keyhog_profile::CounterId::ArchiveDuplicateScanUnavailable
            }
            Self::GitLfsPointer => keyhog_profile::CounterId::GitLfsPointer,
        }
    }
}

/// Receipt proving a source skip event passed through the typed recorder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "source skip events must be recorded through the typed recorder so coverage gaps remain surfaced"]
pub(crate) struct RecordedSkipEvent {
    event: SourceSkipEvent,
    previous: usize,
    delta: usize,
}

pub(crate) fn record_skip_event(event: SourceSkipEvent) -> RecordedSkipEvent {
    record_skip_events(event, 1)
}

pub(crate) fn record_skip_events(event: SourceSkipEvent, delta: usize) -> RecordedSkipEvent {
    await_recording_admission();
    let t = current_source_telemetry();
    let previous = t.counters[event.index()].fetch_add(delta, Relaxed);
    keyhog_profile::add_counter(event.counter_id(), delta as u64);
    RecordedSkipEvent {
        event,
        previous,
        delta,
    }
}

/// Read the current skip counters into a snapshot.
pub fn skip_counts() -> SkipCounts {
    current_source_telemetry().snapshot()
}

/// Merge remote (daemon) skip deltas into process-local counters so
/// `CoverageCounts::current()` / SARIF notifications match the wire gaps
/// (KH-1369). `excluded` is not on the daemon wire and is left unchanged.
pub fn merge_skip_count_deltas(deltas: &SkipCounts) {
    let t = current_source_telemetry();
    let add = |index: usize, delta: usize| {
        if delta > 0 {
            t.counters[index].fetch_add(delta, Relaxed);
        }
    };
    add(0, deltas.over_max_size);
    add(1, deltas.binary);
    add(3, deltas.unreadable);
    add(4, deltas.git_object_unreadable);
    add(5, deltas.archive_truncated);
    add(6, deltas.binary_section_name_unresolved);
    add(7, deltas.source_truncated);
    add(8, deltas.structured_source_parse_failures);
    add(9, deltas.archive_duplicate_scan_unavailable);
    add(10, deltas.git_lfs_pointer);
}

/// Git commit/tree/blob objects that were referenced by Git metadata but not
/// scanned because the object was unreadable or had the wrong kind.
pub fn git_object_unreadable() -> usize {
    skip_counts().git_object_unreadable
}

/// Reset every skip counter in the active telemetry scope.
pub(crate) fn reset_skip_counters() {
    current_source_telemetry().reset();
}

/// Reset all sources runtime counters for a new scan.
pub fn reset_for_scan() {
    reset_skip_counters();
    CURRENT_SOURCE_TELEMETRY.with(|slot| {
        *slot.borrow_mut() = None;
    });
    #[cfg(feature = "binary")]
    crate::binary::reset_binary_counters();
}

/// Reset the over-max-size counter. Retained for API compatibility (Law 3);
/// resets every skip counter so a fixture baselining between runs clears them
/// all, not just the size counter.
pub fn reset_skipped_over_max_size() {
    reset_for_scan();
}

// ---------------------------------------------------------------------------
// Scan serialization gate (test isolation for the process-global counters).
//
// The skip counters above are process-global atomics. In production that is
// exactly right: a keyhog process runs one scan and reads the counters once at
// end-of-scan. The integration test binary runs hundreds of scans concurrently
// in one process, so a counter-asserting test (`reset → scan → read`) can
// otherwise observe another test's increments.
//
// The gate is scan-scoped, NOT thread-scoped. A scan's recording work does not
// all happen on the thread that called `chunks()`: the filesystem reader crew
// records binary / over-max-size / unreadable skips from its own threads, and
// those threads outlive the returned iterator whenever a consumer stops early
// (`take`, `next`, `find`, an early `break`, or a panicking test). The previous
// design keyed the bypass off a thread-local and released the lease when the
// iterator dropped, so a reader thread could bump a counter after its own scan
// had ended and land the increment inside the NEXT counter-asserting test's
// window. That reproduced as `snappy_random_bytes_no_panic` observing
// `unreadable=2` where it plants one.
//
// So a lease is a clonable token, not a lock guard: whoever does recording work
// for a scan holds a clone, and the scan counts as in-flight until the last
// clone drops. An exclusive scope waits for every in-flight scan to finish and
// then blocks new ones. The scope owner's OWN scan is admitted immediately
// (otherwise the asserting test would wait on itself) and stays counted, so the
// next exclusive scope still waits for its reader crew to drain.
static SCAN_GATE: ScanGate = ScanGate {
    state: Mutex::new(GateState {
        active_scans: 0,
        exclusive_owner: None,
        exclusive_waiters: 0,
    }),
    changed: Condvar::new(),
};

struct ScanGate {
    state: Mutex<GateState>,
    changed: Condvar,
}

struct GateState {
    /// Scans whose recording work has not finished yet.
    active_scans: usize,
    /// Thread that holds the exclusive scope, if any.
    exclusive_owner: Option<ThreadId>,
    /// Threads blocked in `enter_exclusive_scan_scope`. New scans yield to them
    /// so a busy test binary cannot starve a counter-asserting test, which is
    /// the writer preference the previous `RwLock` provided.
    exclusive_waiters: usize,
}

impl ScanGate {
    /// Lock the gate state, recovering the inner value on poison.
    ///
    /// LAW10: a panicking test must not cascade into every later scan; the
    /// recovered state still serializes correctly because every mutation of it
    /// is a single infallible field update.
    fn lock(&self) -> std::sync::MutexGuard<'_, GateState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) // LAW10: poisoned test gate recovery preserves the single-mutex state machine and cannot alter production scan results.
    }
}

/// Exclusive scan scope held by a counter-asserting test for its whole
/// reset→scan→read window. Serializes against every other gated scan and
/// against other exclusive scopes. Dropping it reopens the scan gate.
pub struct ScanCounterScope {
    _not_send: std::marker::PhantomData<*const ()>,
}

impl Drop for ScanCounterScope {
    fn drop(&mut self) {
        let mut state = SCAN_GATE.lock();
        state.exclusive_owner = None;
        drop(state);
        SCAN_GATE.changed.notify_all();
    }
}

/// Enter an exclusive scan scope. Blocks until every in-flight scan has
/// finished recording and no other exclusive scope is held.
pub(crate) fn enter_exclusive_scan_scope() -> ScanCounterScope {
    let mut state = SCAN_GATE.lock();
    state.exclusive_waiters += 1;
    while state.exclusive_owner.is_some() || state.active_scans > 0 {
        state = SCAN_GATE
            .changed
            .wait(state)
            .unwrap_or_else(|poisoned| poisoned.into_inner()); // LAW10: poisoned test gate recovery resumes the same counter-guarded state and cannot suppress a source row.
    }
    state.exclusive_waiters -= 1;
    state.exclusive_owner = Some(std::thread::current().id());
    ScanCounterScope {
        _not_send: std::marker::PhantomData,
    }
}

/// One scan's registration in the gate. Deregisters when the last clone drops,
/// which is what makes the gate wait for a reader crew rather than for the
/// thread that spawned it.
struct ActiveScan;

impl Drop for ActiveScan {
    fn drop(&mut self) {
        let mut state = SCAN_GATE.lock();
        state.active_scans = state.active_scans.saturating_sub(1);
        let idle = state.active_scans == 0;
        drop(state);
        if idle {
            SCAN_GATE.changed.notify_all();
        }
    }
}

/// Lease proving one scan is registered with the gate.
///
/// Clone it into every thread that records skip events for that scan. `Send`
/// and `Sync`, unlike the `RwLockReadGuard` this replaced, precisely so the
/// reader crew can hold it.
#[derive(Clone)]
pub(crate) struct ScanReadLease {
    _active: Arc<ActiveScan>,
    telemetry: Arc<SourceSkipTelemetry>,
}

/// Acquire a scan lease before any recording work (eager walk errors or
/// reader-pool spawn), then keep it alive for as long as anything records.
pub(crate) fn acquire_scan_read_lease() -> ScanReadLease {
    let mut state = SCAN_GATE.lock();
    let me = std::thread::current().id();
    // The scope owner's own scan is admitted immediately: it is the scan the
    // asserting test is measuring, and blocking it would deadlock the test
    // against its own scope. Everyone else waits out the scope, and also waits
    // behind a pending scope so exclusive entry cannot starve.
    while state.exclusive_owner.is_some_and(|owner| owner != me)
        || (state.exclusive_owner.is_none() && state.exclusive_waiters > 0)
    {
        state = SCAN_GATE
            .changed
            .wait(state)
            .unwrap_or_else(|poisoned| poisoned.into_inner()); // LAW10: poisoned test gate recovery resumes the same counter-guarded state and cannot suppress a source row.
    }
    state.active_scans += 1;
    ScanReadLease {
        _active: Arc::new(ActiveScan),
        telemetry: current_source_telemetry(),
    }
}

// Depth of nested "this thread is doing work for a leased scan" markers.
//
// The gate serializes SCANS, but a counter increment is what a test observes,
// and not every increment comes from a thread the gate knows about: the
// filesystem reader crew records from its own threads, and a thread whose scan
// has ended can still be mid-`process_entry`. This marker is what lets
// `record_skip_events` tell "I belong to an admitted scan" from "I am an
// unattributed leftover", without plumbing a token through forty call sites.
thread_local! {
    static SCAN_THREAD_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub(crate) struct AttributedScanWork {
    _not_send: std::marker::PhantomData<*const ()>,
    prev_telemetry: Option<Arc<SourceSkipTelemetry>>,
}

impl Drop for AttributedScanWork {
    fn drop(&mut self) {
        SCAN_THREAD_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
        let previous = self.prev_telemetry.take();
        CURRENT_SOURCE_TELEMETRY.with(|slot| {
            *slot.borrow_mut() = previous;
        });
    }
}

impl ScanReadLease {
    /// Attribute the current thread's work to this scan for the guard's
    /// lifetime. Every thread that records skip events for a scan must hold
    /// one, including reader-pool threads.
    pub(crate) fn enter(&self) -> AttributedScanWork {
        SCAN_THREAD_DEPTH.with(|depth| depth.set(depth.get() + 1));
        let prev_telemetry = CURRENT_SOURCE_TELEMETRY.with(|slot| {
            let mut slot = slot.borrow_mut();
            let prev = slot.clone();
            *slot = Some(Arc::clone(&self.telemetry));
            prev
        });
        AttributedScanWork {
            _not_send: std::marker::PhantomData,
            prev_telemetry,
        }
    }
}

/// Block an unattributed recorder until no other thread holds the exclusive
/// scope.
///
/// Threads inside an admitted scan pass straight through: the gate already
/// serialized their scan against every exclusive scope, so a lock here would be
/// pure overhead and, for the scope owner's own scan, a deadlock. Everyone else
/// is either a leftover from a finished scan or a direct caller outside any
/// scan, and their increment must not land inside a counter-asserting test's
/// window. The event is delayed, never dropped: a coverage gap that is not
/// recorded is a false clean. A no-op in production, where no scope is ever
/// taken and the fast path is one thread-local read.
fn await_recording_admission() {
    if SCAN_THREAD_DEPTH.with(std::cell::Cell::get) > 0 {
        return;
    }
    let me = std::thread::current().id();
    let mut state = SCAN_GATE.lock();
    while state.exclusive_owner.is_some_and(|owner| owner != me) {
        state = SCAN_GATE
            .changed
            .wait(state)
            .unwrap_or_else(|poisoned| poisoned.into_inner()); // LAW10: poisoned test gate recovery only waits for test-owned scan counters to drain; production findings are untouched.
    }
}

pub(crate) fn scan_gate_exclusive_available_for_test() -> bool {
    let state = SCAN_GATE.lock();
    state.exclusive_owner.is_none() && state.active_scans == 0
}

struct LeasedScanIter<'a, T> {
    lease: ScanReadLease,
    inner: Box<dyn Iterator<Item = T> + 'a>,
}

impl<T> Iterator for LeasedScanIter<'_, T> {
    type Item = T;
    fn next(&mut self) -> Option<T> {
        // Lazy sources record while the consumer pulls, so each pull runs
        // attributed to this scan.
        let _attributed = self.lease.enter();
        self.inner.next()
    }
}

/// Bind an already-acquired lease to a built iterator so the lease lives at
/// least as long as the consumer keeps pulling (covers lazy recording on the
/// consuming thread). Threads that outlive the iterator hold their own clone.
pub(crate) fn attach_scan_lease<'a, T: 'a>(
    lease: ScanReadLease,
    inner: Box<dyn Iterator<Item = T> + 'a>,
) -> Box<dyn Iterator<Item = T> + 'a> {
    Box::new(LeasedScanIter { lease, inner })
}

/// Acquire a lease, run an (often eager) iterator builder under it, then keep
/// the lease bound to the result. The single-call form for sources whose
/// `chunks()` body is one expression and whose recording all happens on the
/// consuming thread.
pub(crate) fn gate_scan<'a, T: 'a>(
    build: impl FnOnce() -> Box<dyn Iterator<Item = T> + 'a>,
) -> Box<dyn Iterator<Item = T> + 'a> {
    let lease = acquire_scan_read_lease();
    let inner = {
        let _attributed = lease.enter();
        build()
    };
    attach_scan_lease(lease, inner)
}

pub(crate) fn subtract_excluded(delta: usize) {
    if delta == 0 {
        return;
    }
    let t = current_source_telemetry();
    // LAW10: closure always returns Some, so the update cannot fail; no fallback path
    let _ = t.counters[2].fetch_update(Relaxed, Relaxed, |current| {
        Some(current.saturating_sub(delta))
    });
}

pub(crate) fn store_skip_counts(counts: SkipCounts) {
    let t = current_source_telemetry();
    t.counters[0].store(counts.over_max_size, Relaxed);
    t.counters[1].store(counts.binary, Relaxed);
    t.counters[2].store(counts.excluded, Relaxed);
    t.counters[3].store(counts.unreadable, Relaxed);
    t.counters[4].store(counts.git_object_unreadable, Relaxed);
    t.counters[5].store(counts.archive_truncated, Relaxed);
    t.counters[6].store(counts.binary_section_name_unresolved, Relaxed);
    t.counters[7].store(counts.source_truncated, Relaxed);
    t.counters[8].store(counts.structured_source_parse_failures, Relaxed);
    t.counters[9].store(counts.archive_duplicate_scan_unavailable, Relaxed);
    t.counters[10].store(counts.git_lfs_pointer, Relaxed);
}
