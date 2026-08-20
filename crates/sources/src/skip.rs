use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::ThreadId;

/// How many files the filesystem walker skipped because they exceeded
/// the active `--max-file-size` cap. Bumped once per skipped entry
/// inside `FilesystemSource::process_entry`; the orchestrator reads
/// it at end-of-scan to emit a single summary line so users see what
/// the previously-silent walker filter dropped (kimi-1 dogfood #130).
/// Counter is process-global; reset between scans by the test harness
/// via `reset_skipped_over_max_size()`.
static SKIPPED_OVER_MAX_SIZE: AtomicUsize = AtomicUsize::new(0);

/// How many files the filesystem walker skipped because their extension,
/// content-sniffed magic header, or repeated-NUL binary prefix marked them
/// binary before any content scan. Previously a silent `return` (Law 10): a
/// `.bin`/`.dat`/no-ext file that is actually a planted-credential blob vanished
/// with no trace. Bumped at each binary skip site in `process_entry`; surfaced
/// at end-of-scan.
static SKIPPED_BINARY: AtomicUsize = AtomicUsize::new(0);

/// How many files were skipped by the default-exclusion filter (lock files,
/// minified/bundled JS, vendored trees). Also previously a silent `return`.
static SKIPPED_EXCLUDED: AtomicUsize = AtomicUsize::new(0);

/// How many files the walker could not read (permission denied / I/O error) and
/// therefore did NOT scan. This is the most important to surface: an unreadable
/// file is an UNKNOWN, not a clean file, silently dropping it is a false-clean
/// (Law 10). Bumped on the walk's error path.
static SKIPPED_UNREADABLE: AtomicUsize = AtomicUsize::new(0);

/// How many Git history/diff objects were referenced by Git metadata but could
/// not be read or decoded as the object kind the scan required. These are
/// source objects, not filesystem files, so report them separately from
/// `SKIPPED_UNREADABLE` while still treating them as incomplete coverage.
static GIT_OBJECT_UNREADABLE: AtomicUsize = AtomicUsize::new(0);

/// How many archives (zip/apk/jar/tar/.gz/.tgz/...) had their extraction
/// TRUNCATED by a decompression-bomb guard, the per-archive 4x-of-`--max-file-size`
/// uncompressed budget was exceeded, so the remaining entries were NOT scanned.
/// A truncated archive is partial coverage, not a clean archive: silently
/// dropping the unscanned tail is a false-clean (Law 10). Bumped once per
/// archive that hit a bomb guard; surfaced at end-of-scan alongside the other
/// skip categories.
static SKIPPED_ARCHIVE_TRUNCATED: AtomicUsize = AtomicUsize::new(0);

/// How many binary (ELF/PE/Mach-O) sections were SKIPPED because their name
/// could not be resolved from the object's section-name string table, a
/// corrupt/truncated strtab in a malformed binary. The previous code substituted
/// an empty name (`unwrap_or("")`) and then silently dropped the section because
/// `""` is never in the high-value target list: a `.rodata`/`.data` section whose
/// name lookup failed vanished from the scan with no trace (Law 10 false-clean
/// embedded secrets in that section were never scanned). Bumped once per section
/// whose name lookup fails; surfaced so the operator knows the binary parse was
/// partial. Reset via `reset_skip_counters`.
static BINARY_SECTION_NAME_UNRESOLVED: AtomicUsize = AtomicUsize::new(0);

/// How many source scans stopped before exhausting their input because a
/// source-level aggregate cap fired. This is distinct from per-file
/// over-max-size skips: e.g. Git history may stop after the aggregate
/// byte/chunk ceiling even though every individual blob was below its own cap.
static SOURCE_TRUNCATED: AtomicUsize = AtomicUsize::new(0);

/// How many structured source files matched a format-specific source expander
/// but failed to parse, so only the raw text fallback was scanned. This is
/// partial coverage, not a whole-file skip: e.g. a malformed HAR still gets
/// scanned as text, but request/response/body expansion is missing.
static STRUCTURED_SOURCE_PARSE_FAILURES: AtomicUsize = AtomicUsize::new(0);

/// How many archives matched the zip duplicate-entry detector but it could not
/// run (e.g. a zip64 central directory it does not model, or a malformed/truncated
/// central directory), so only the standard zip parser was used. That parser
/// surfaces one entry per name, so a duplicated/shadow central-directory entry an
/// attacker hid a secret in could be missed. Partial coverage, not a whole-file
/// skip: the archive's ordinary entries are still scanned. Previously the error
/// was discarded by an `if let Ok(Some(..))` and the degrade was invisible (Law
/// 10 false-clean); now surfaced.
static ARCHIVE_DUPLICATE_SCAN_UNAVAILABLE: AtomicUsize = AtomicUsize::new(0);

/// How many files were recognised as Git-LFS *pointers*, the tiny text
/// stand-ins Git LFS commits in place of a large blob. keyhog scans the pointer
/// text (and suppresses its content-hash `oid`), but the real blob it references
/// lives in LFS storage and is NOT on disk to scan unless `git lfs pull` has
/// materialised it. Silently reporting an unmaterialised-pointer repo as clean
/// is a false-clean (Law 10): the blob, which can hold secrets (a keystore, a
/// `.pem`, an encrypted `.env`), was never scanned. Bumped once per pointer
/// file; surfaced at end-of-scan as partial coverage. Recognition is the shared
/// `keyhog_core::git_lfs::is_git_lfs_pointer`.
static GIT_LFS_POINTER: AtomicUsize = AtomicUsize::new(0);

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
    #[cfg(feature = "binary")]
    BinarySectionNameUnresolved,
    SourceTruncated,
    StructuredSourceParseFailure,
    ArchiveDuplicateScanUnavailable,
    GitLfsPointer,
}

impl SourceSkipEvent {
    fn counter(self) -> &'static AtomicUsize {
        match self {
            Self::OverMaxSize => &SKIPPED_OVER_MAX_SIZE,
            Self::Binary => &SKIPPED_BINARY,
            Self::Excluded => &SKIPPED_EXCLUDED,
            Self::Unreadable => &SKIPPED_UNREADABLE,
            Self::GitObjectUnreadable => &GIT_OBJECT_UNREADABLE,
            Self::ArchiveTruncated => &SKIPPED_ARCHIVE_TRUNCATED,
            #[cfg(feature = "binary")]
            Self::BinarySectionNameUnresolved => &BINARY_SECTION_NAME_UNRESOLVED,
            Self::SourceTruncated => &SOURCE_TRUNCATED,
            Self::StructuredSourceParseFailure => &STRUCTURED_SOURCE_PARSE_FAILURES,
            Self::ArchiveDuplicateScanUnavailable => &ARCHIVE_DUPLICATE_SCAN_UNAVAILABLE,
            Self::GitLfsPointer => &GIT_LFS_POINTER,
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
    let previous = event.counter().fetch_add(delta, Relaxed);
    RecordedSkipEvent {
        event,
        previous,
        delta,
    }
}

/// Read the current skip counters into a snapshot.
pub fn skip_counts() -> SkipCounts {
    SkipCounts {
        over_max_size: SKIPPED_OVER_MAX_SIZE.load(Relaxed),
        binary: SKIPPED_BINARY.load(Relaxed),
        excluded: SKIPPED_EXCLUDED.load(Relaxed),
        unreadable: SKIPPED_UNREADABLE.load(Relaxed),
        git_object_unreadable: GIT_OBJECT_UNREADABLE.load(Relaxed),
        archive_truncated: SKIPPED_ARCHIVE_TRUNCATED.load(Relaxed),
        binary_section_name_unresolved: BINARY_SECTION_NAME_UNRESOLVED.load(Relaxed),
        source_truncated: SOURCE_TRUNCATED.load(Relaxed),
        structured_source_parse_failures: STRUCTURED_SOURCE_PARSE_FAILURES.load(Relaxed),
        archive_duplicate_scan_unavailable: ARCHIVE_DUPLICATE_SCAN_UNAVAILABLE.load(Relaxed),
        git_lfs_pointer: GIT_LFS_POINTER.load(Relaxed),
    }
}

/// Merge remote (daemon) skip deltas into process-local counters so
/// `CoverageCounts::current()` / SARIF notifications match the wire gaps
/// (KH-1369). `excluded` is not on the daemon wire and is left unchanged.
pub fn merge_skip_count_deltas(deltas: &SkipCounts) {
    let add = |counter: &AtomicUsize, delta: usize| {
        if delta > 0 {
            counter.fetch_add(delta, Relaxed);
        }
    };
    add(&SKIPPED_OVER_MAX_SIZE, deltas.over_max_size);
    add(&SKIPPED_BINARY, deltas.binary);
    add(&SKIPPED_UNREADABLE, deltas.unreadable);
    add(&GIT_OBJECT_UNREADABLE, deltas.git_object_unreadable);
    add(&SKIPPED_ARCHIVE_TRUNCATED, deltas.archive_truncated);
    add(
        &BINARY_SECTION_NAME_UNRESOLVED,
        deltas.binary_section_name_unresolved,
    );
    add(&SOURCE_TRUNCATED, deltas.source_truncated);
    add(
        &STRUCTURED_SOURCE_PARSE_FAILURES,
        deltas.structured_source_parse_failures,
    );
    add(
        &ARCHIVE_DUPLICATE_SCAN_UNAVAILABLE,
        deltas.archive_duplicate_scan_unavailable,
    );
    add(&GIT_LFS_POINTER, deltas.git_lfs_pointer);
}

/// Git commit/tree/blob objects that were referenced by Git metadata but not
/// scanned because the object was unreadable or had the wrong kind.
pub fn git_object_unreadable() -> usize {
    skip_counts().git_object_unreadable
}

/// Reset every skip counter. Public so test fixtures and the orchestrator can
/// baseline between scans in one process.
pub(crate) fn reset_skip_counters() {
    current_source_telemetry().reset();
}

/// Reset all sources runtime counters for a new scan.
pub fn reset_for_scan() {
    GLOBAL_SOURCE_TELEMETRY.reset();
    reset_skip_counters();
    #[cfg(feature = "binary")]
    crate::binary::reset_binary_counters();
}

/// Reset the over-max-size counter. Retained for API compatibility (Law 3);
/// resets every skip counter so a fixture baselining between runs clears them
/// all, not just the size counter.
pub fn reset_skipped_over_max_size() {
    reset_skip_counters();
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

/// Marks the current thread as doing work for an admitted scan. Not `Send`:
/// the depth it decrements is the depth its constructor incremented.
pub(crate) struct AttributedScanWork {
    _not_send: std::marker::PhantomData<*const ()>,
}

impl Drop for AttributedScanWork {
    fn drop(&mut self) {
        SCAN_THREAD_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

impl ScanReadLease {
    /// Attribute the current thread's work to this scan for the guard's
    /// lifetime. Every thread that records skip events for a scan must hold
    /// one, including reader-pool threads.
    pub(crate) fn enter(&self) -> AttributedScanWork {
        SCAN_THREAD_DEPTH.with(|depth| depth.set(depth.get() + 1));
        AttributedScanWork {
            _not_send: std::marker::PhantomData,
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
    // LAW10: Infallible atomic subtraction for telemetry counter; fetch_update closure unconditionally returns Some.
    let _ = t.counters[2].fetch_update(Relaxed, Relaxed, |current| {
        // LAW10: closure always returns Some, so fetch_update cannot fail; no fallback path exists.
        Some(current.saturating_sub(delta))
    });
}

pub(crate) fn store_skip_counts(counts: SkipCounts) {
    SKIPPED_OVER_MAX_SIZE.store(counts.over_max_size, Relaxed);
    SKIPPED_BINARY.store(counts.binary, Relaxed);
    SKIPPED_EXCLUDED.store(counts.excluded, Relaxed);
    SKIPPED_UNREADABLE.store(counts.unreadable, Relaxed);
    GIT_OBJECT_UNREADABLE.store(counts.git_object_unreadable, Relaxed);
    SKIPPED_ARCHIVE_TRUNCATED.store(counts.archive_truncated, Relaxed);
    BINARY_SECTION_NAME_UNRESOLVED.store(counts.binary_section_name_unresolved, Relaxed);
    SOURCE_TRUNCATED.store(counts.source_truncated, Relaxed);
    STRUCTURED_SOURCE_PARSE_FAILURES.store(counts.structured_source_parse_failures, Relaxed);
    ARCHIVE_DUPLICATE_SCAN_UNAVAILABLE.store(counts.archive_duplicate_scan_unavailable, Relaxed);
    GIT_LFS_POINTER.store(counts.git_lfs_pointer, Relaxed);
}
