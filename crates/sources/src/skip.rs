use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

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

/// Git commit/tree/blob objects that were referenced by Git metadata but not
/// scanned because the object was unreadable or had the wrong kind.
pub fn git_object_unreadable() -> usize {
    skip_counts().git_object_unreadable
}

/// Reset every skip counter. Public so test fixtures and the orchestrator can
/// baseline between scans in one process.
pub(crate) fn reset_skip_counters() {
    SKIPPED_OVER_MAX_SIZE.store(0, Relaxed);
    SKIPPED_BINARY.store(0, Relaxed);
    SKIPPED_EXCLUDED.store(0, Relaxed);
    SKIPPED_UNREADABLE.store(0, Relaxed);
    GIT_OBJECT_UNREADABLE.store(0, Relaxed);
    SKIPPED_ARCHIVE_TRUNCATED.store(0, Relaxed);
    BINARY_SECTION_NAME_UNRESOLVED.store(0, Relaxed);
    SOURCE_TRUNCATED.store(0, Relaxed);
    STRUCTURED_SOURCE_PARSE_FAILURES.store(0, Relaxed);
    ARCHIVE_DUPLICATE_SCAN_UNAVAILABLE.store(0, Relaxed);
    GIT_LFS_POINTER.store(0, Relaxed);
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
// exactly right: a keyhog process runs ONE scan and reads the counters once at
// end-of-scan. But the integration test binary runs hundreds of scans
// concurrently in a single process, so a counter-asserting test
// (`reset → scan → read skip_counts()`) can observe increments from another
// test's scan running on a different thread, a false failure that has nothing
// to do with the code under test.
//
// The gate makes the asserting window EXCLUSIVE without changing the counters'
// production semantics or weakening any assertion:
//   * A counter-asserting test takes `enter_exclusive_scan_scope()` (a write
//     lease) for the whole reset→scan→read window; while it is held no other
//     scan may record.
//   * Every source's `chunks()` takes a read lease for the scan's lifetime via
//     `gate_scan` / `acquire_scan_read_lease`, so concurrent scans serialize
//     behind an active asserting test instead of polluting its counters.
//
// The gate is ARMED only when the test harness first enters an exclusive scope.
// A production scan never arms it, so `scan_gate_read_lease` returns after a
// single relaxed atomic-bool load and never touches the lock, zero production
// cost (Law 7). The asserting test's OWN scan bypasses the read lease via a
// thread-local flag, so its reader-pool workers (which never touch the gate)
// run freely under the held write lease without self-deadlock.
static SCAN_GATE: RwLock<()> = RwLock::new(());
static SCAN_GATE_ARMED: AtomicBool = AtomicBool::new(false);
thread_local! {
    static IN_EXCLUSIVE_SCAN_SCOPE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Exclusive scan scope held by a counter-asserting test for its whole
/// reset→scan→read window. Serializes against every other gated scan and
/// against other exclusive scopes. Dropping it releases the scan gate.
pub struct ScanCounterScope {
    // Field order matters: `Drop for ScanCounterScope` runs first (clearing the
    // thread-local), then this field drops, releasing the write lock.
    _write: RwLockWriteGuard<'static, ()>,
}

impl Drop for ScanCounterScope {
    fn drop(&mut self) {
        IN_EXCLUSIVE_SCAN_SCOPE.with(|in_scope| in_scope.set(false));
    }
}

/// Enter an exclusive scan scope. Arms the gate (so subsequent scans take read
/// leases), then blocks until every in-flight gated scan has finished and no
/// other exclusive scope is held. Recovers the inner guard on poison so one
/// panicking test does not cascade.
pub(crate) fn enter_exclusive_scan_scope() -> ScanCounterScope {
    SCAN_GATE_ARMED.store(true, Relaxed);
    let write = SCAN_GATE
        .write()
        // LAW10: recover the inner guard, test-only scan gate, never armed in
        // production; a recovered guard still serializes the asserting test.
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    IN_EXCLUSIVE_SCAN_SCOPE.with(|in_scope| in_scope.set(true));
    ScanCounterScope { _write: write }
}

/// Read lease held for the lifetime of one scan. `None` inside when the gate is
/// unarmed (production) or the current thread already holds the exclusive scope
/// (the asserting test's own scan must not block on its own write lease).
pub(crate) struct ScanReadLease {
    _lease: Option<RwLockReadGuard<'static, ()>>,
}

/// Acquire a scan read lease. Must be taken BEFORE any recording work (eager
/// walk errors, reader-pool spawn) so a concurrent scan blocks here, behind an
/// active exclusive scope, instead of recording into the counters an asserting
/// test is about to read. Returns immediately in production (gate unarmed).
pub(crate) fn acquire_scan_read_lease() -> ScanReadLease {
    if !SCAN_GATE_ARMED.load(Relaxed) {
        return ScanReadLease { _lease: None };
    }
    if IN_EXCLUSIVE_SCAN_SCOPE.with(|in_scope| in_scope.get()) {
        return ScanReadLease { _lease: None };
    }
    ScanReadLease {
        _lease: Some(
            SCAN_GATE
                .read()
                // LAW10: recover the inner guard, test-only scan gate, never
                // armed in production; a recovered guard still serializes scans.
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        ),
    }
}

struct LeasedScanIter<'a, T> {
    _lease: ScanReadLease,
    inner: Box<dyn Iterator<Item = T> + 'a>,
}

impl<T> Iterator for LeasedScanIter<'_, T> {
    type Item = T;
    fn next(&mut self) -> Option<T> {
        self.inner.next()
    }
}

/// Bind an already-acquired lease to a built iterator so the lease lives for the
/// whole scan (covers lazy reader-pool recording during iteration).
pub(crate) fn attach_scan_lease<'a, T: 'a>(
    lease: ScanReadLease,
    inner: Box<dyn Iterator<Item = T> + 'a>,
) -> Box<dyn Iterator<Item = T> + 'a> {
    if lease._lease.is_some() {
        Box::new(LeasedScanIter {
            _lease: lease,
            inner,
        })
    } else {
        inner
    }
}

/// Acquire a lease, run an (often eager) iterator builder under it, then keep
/// the lease bound to the result. The single-call form for sources whose
/// `chunks()` body is one expression. A no-op in production.
pub(crate) fn gate_scan<'a, T: 'a>(
    build: impl FnOnce() -> Box<dyn Iterator<Item = T> + 'a>,
) -> Box<dyn Iterator<Item = T> + 'a> {
    let lease = acquire_scan_read_lease();
    let inner = build();
    attach_scan_lease(lease, inner)
}

pub(crate) fn set_skip_counts_for_test(counts: SkipCounts) {
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
