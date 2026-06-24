use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

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
/// file is an UNKNOWN, not a clean file — silently dropping it is a false-clean
/// (Law 10). Bumped on the walk's error path.
static SKIPPED_UNREADABLE: AtomicUsize = AtomicUsize::new(0);

/// How many Git history/diff objects were referenced by Git metadata but could
/// not be read or decoded as the object kind the scan required. These are
/// source objects, not filesystem files, so report them separately from
/// `SKIPPED_UNREADABLE` while still treating them as incomplete coverage.
static GIT_OBJECT_UNREADABLE: AtomicUsize = AtomicUsize::new(0);

/// How many archives (zip/apk/jar/tar/.gz/.tgz/...) had their extraction
/// TRUNCATED by a decompression-bomb guard — the per-archive 4x-of-`--max-file-size`
/// uncompressed budget was exceeded, so the remaining entries were NOT scanned.
/// A truncated archive is partial coverage, not a clean archive: silently
/// dropping the unscanned tail is a false-clean (Law 10). Bumped once per
/// archive that hit a bomb guard; surfaced at end-of-scan alongside the other
/// skip categories.
static SKIPPED_ARCHIVE_TRUNCATED: AtomicUsize = AtomicUsize::new(0);

/// How many binary (ELF/PE/Mach-O) sections were SKIPPED because their name
/// could not be resolved from the object's section-name string table — a
/// corrupt/truncated strtab in a malformed binary. The previous code substituted
/// an empty name (`unwrap_or("")`) and then silently dropped the section because
/// `""` is never in the high-value target list: a `.rodata`/`.data` section whose
/// name lookup failed vanished from the scan with no trace (Law 10 false-clean —
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

/// Immutable snapshot of the skip counters, read once at end-of-scan so every
/// reporter (human summary + structured JSON/SARIF) surfaces the same numbers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SkipCounts {
    pub over_max_size: usize,
    pub binary: usize,
    pub excluded: usize,
    pub unreadable: usize,
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
}

impl SkipCounts {
    /// Total files skipped (not scanned) across all categories.
    ///
    /// Git object unreadability is exposed through `git_object_unreadable()`;
    /// `binary_section_name_unresolved`, `source_truncated`,
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
        archive_truncated: SKIPPED_ARCHIVE_TRUNCATED.load(Relaxed),
        binary_section_name_unresolved: BINARY_SECTION_NAME_UNRESOLVED.load(Relaxed),
        source_truncated: SOURCE_TRUNCATED.load(Relaxed),
        structured_source_parse_failures: STRUCTURED_SOURCE_PARSE_FAILURES.load(Relaxed),
        archive_duplicate_scan_unavailable: ARCHIVE_DUPLICATE_SCAN_UNAVAILABLE.load(Relaxed),
    }
}

/// Git commit/tree/blob objects that were referenced by Git metadata but not
/// scanned because the object was unreadable or had the wrong kind.
pub fn git_object_unreadable() -> usize {
    GIT_OBJECT_UNREADABLE.load(Relaxed)
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
}

/// Reset the over-max-size counter. Retained for API compatibility (Law 3);
/// resets every skip counter so a fixture baselining between runs clears them
/// all, not just the size counter.
pub fn reset_skipped_over_max_size() {
    reset_skip_counters();
}

pub(crate) fn set_skip_counts_for_test(counts: SkipCounts) {
    SKIPPED_OVER_MAX_SIZE.store(counts.over_max_size, Relaxed);
    SKIPPED_BINARY.store(counts.binary, Relaxed);
    SKIPPED_EXCLUDED.store(counts.excluded, Relaxed);
    SKIPPED_UNREADABLE.store(counts.unreadable, Relaxed);
    GIT_OBJECT_UNREADABLE.store(0, Relaxed);
    SKIPPED_ARCHIVE_TRUNCATED.store(counts.archive_truncated, Relaxed);
    BINARY_SECTION_NAME_UNRESOLVED.store(counts.binary_section_name_unresolved, Relaxed);
    SOURCE_TRUNCATED.store(counts.source_truncated, Relaxed);
    STRUCTURED_SOURCE_PARSE_FAILURES.store(counts.structured_source_parse_failures, Relaxed);
    ARCHIVE_DUPLICATE_SCAN_UNAVAILABLE.store(counts.archive_duplicate_scan_unavailable, Relaxed);
}
