//! Filesystem source: recursively walks a directory tree, skips binary files,
//! respects `.gitignore`, and yields chunks for scanning.

use codewalk::CodeWalker;
use keyhog_core::MerkleIndex;
use keyhog_core::{Chunk, Source, SourceError};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

mod extract;
mod filter;
mod path;
mod read;
mod reader;

pub(crate) use extract::extraction_total_budget;
use filter::walker_config;
pub(crate) use path::display_path;
pub(crate) use read::decode_text_file;

#[cfg(feature = "git")]
pub(crate) fn is_default_excluded_path(path: &str) -> bool {
    filter::is_default_excluded(path)
}

#[cfg(any(feature = "azure", feature = "s3", feature = "gcs"))]
pub(crate) fn is_default_skip_extension(ext: &str) -> bool {
    filter::is_skip_extension(ext)
}

pub(crate) fn reader_pool_thread_count_for_test(scanner_threads: usize) -> usize {
    reader::reader_thread_count(scanner_threads, None)
}

pub(crate) fn reader_pool_thread_count_with_config_for_test(
    scanner_threads: usize,
    configured: NonZeroUsize,
) -> usize {
    reader::reader_thread_count(scanner_threads, Some(configured))
}

pub(crate) fn reader_panic_rows_for_test() -> Vec<Result<Chunk, SourceError>> {
    struct PanicEntries;

    impl Iterator for PanicEntries {
        type Item = codewalk::FileEntry;

        fn next(&mut self) -> Option<Self::Item> {
            panic!("reader exploded")
        }
    }

    let rx = reader::spawn_chunk_producer(
        Box::new(PanicEntries),
        None,
        Arc::new(AtomicUsize::new(0)),
        PathBuf::from("."),
        keyhog_core::DEFAULT_MAX_FILE_SIZE_BYTES,
        reader::DEFAULT_WINDOW_SIZE,
        reader::DEFAULT_WINDOW_OVERLAP,
        true,
        NonZeroUsize::new(1),
    );
    rx.into_iter().collect()
}

pub(crate) fn reader_process_entry_panic_rows_for_test() -> Vec<Result<Chunk, SourceError>> {
    reader::process_entry_panic_rows_for_test()
}

pub(crate) fn process_entry_with_recorded_size_for_test(
    path: PathBuf,
    recorded_size: u64,
    max_size: u64,
) -> Vec<Result<Chunk, SourceError>> {
    let mut rows = Vec::new();
    let entry = codewalk::FileEntry {
        path,
        size: recorded_size,
        is_binary: false,
    };
    extract::process_entry(
        entry,
        &None,
        &Arc::new(AtomicUsize::new(0)),
        std::path::Path::new("."),
        max_size,
        reader::DEFAULT_WINDOW_SIZE,
        reader::DEFAULT_WINDOW_OVERLAP,
        true,
        &mut |row| {
            rows.push(row);
            true
        },
    );
    rows
}

pub(crate) fn max_buffered_read_bytes_for_test() -> u64 {
    read::max_buffered_read_bytes_for_test()
}

pub(crate) fn mmap_toctou_sanity_cap_bytes_for_test() -> u64 {
    read::mmap_toctou_sanity_cap_bytes_for_test()
}

pub(crate) fn read_file_safe_capped_for_test(
    path: &std::path::Path,
    cap: u64,
) -> std::io::Result<Vec<u8>> {
    read::read_file_safe_capped_for_test(path, cap)
}

pub(crate) fn read_file_mmap_for_test(path: &std::path::Path) -> Option<String> {
    read::read_file_mmap_for_test(path)
}

pub(crate) fn read_file_for_compressed_input_for_test(
    path: &std::path::Path,
    size_cap: u64,
) -> Option<Vec<u8>> {
    read::read_file_for_compressed_input_for_test(path, size_cap)
}

pub(crate) fn read_file_windowed_mmap_len_for_test(
    path: &std::path::Path,
    window_size: usize,
    overlap: usize,
) -> Option<usize> {
    read::read_file_windowed_mmap_len_for_test(path, window_size, overlap)
}

pub(crate) fn slice_into_windows_for_test(
    bytes: &[u8],
    window_size: usize,
    overlap: usize,
) -> Vec<String> {
    read::slice_into_windows_for_test(bytes, window_size, overlap)
}

pub(crate) fn decode_utf16_for_test(bytes: &[u8]) -> Option<String> {
    read::decode_utf16_for_test(bytes)
}

pub(crate) fn looks_binary_for_test(bytes: &[u8]) -> bool {
    read::looks_binary_for_test(bytes)
}

pub(crate) fn duplicate_zip_central_entries_error_for_test(
    path: &std::path::Path,
) -> Result<String, String> {
    extract::duplicate_zip_central_entries_error_for_test(path)
}

pub(crate) fn duplicate_zip_local_entry_data_error_for_test(
    path: &std::path::Path,
    compressed_size: u64,
) -> Result<String, String> {
    extract::duplicate_zip_local_entry_data_error_for_test(path, compressed_size)
}

pub(crate) fn default_max_file_size_for_test() -> u64 {
    FilesystemSource::new(PathBuf::from(".")).max_file_size
}

/// Scans files in a directory tree.
pub struct FilesystemSource {
    root: PathBuf,
    max_file_size: u64,
    ignore_paths: Vec<String>,
    include_paths: Vec<PathBuf>,
    /// Whether to honor `.gitignore` / `.keyhogignore` files during the walk.
    /// `true` (default) is correct for normal scans. `keyhog scan-system`
    /// flips this to `false` because an attacker stashing a leaked key
    /// inside a project would `.gitignore` it.
    respect_gitignore: bool,
    /// Optional merkle-index handle. When set, the iterator consults the
    /// index per file BEFORE reading: if `(path, mtime_ns, size)` matches
    /// a stored entry the file is skipped without an open() / read() -
    /// the dominant cost on cold-cache disk. Doubles as an output sink:
    /// when `record_metadata` is true, the source records the live
    /// `(mtime, size)` of every chunk it does emit so the orchestrator
    /// only has to attach the BLAKE3 hash post-scan.
    merkle: Option<Arc<MerkleIndex>>,
    /// Counter incremented for every file the metadata fast-path skips.
    /// The orchestrator reads it after the scan to log how much I/O the
    /// cache saved. Atomic so rayon-driven walkers don't have to lock.
    skipped: Arc<AtomicUsize>,
    /// Window size for the big-file scan path. Tests override this via
    /// `with_window_config` to exercise the windowed flow without
    /// writing the 1 MiB fixtures the production threshold requires.
    window_size: usize,
    /// Bytes of overlap between consecutive windows. Same rationale.
    window_overlap: usize,
    /// Whether the walker's built-in exclusion list (lock files, minified /
    /// bundled JS, vendored directories — `filter::is_default_excluded` + the
    /// `.min.`/`.bundle.` filename checks) is applied. `true` (default) is the
    /// normal scan. `--no-default-excludes` flips this to `false` so a secret
    /// committed inside e.g. `package-lock.json` is still scanned — previously
    /// the flag only reached the codewalk glob layer, NOT this in-process
    /// filter, so the lock/vendored files stayed silently excluded.
    respect_default_excludes: bool,
    /// Explicit filesystem reader thread count. `None` keeps the source-derived
    /// default tied to the configured scan worker pool.
    reader_threads: Option<NonZeroUsize>,
}

impl FilesystemSource {
    /// Create a filesystem source rooted at `root`.
    pub fn new(root: PathBuf) -> Self {
        // Canonicalize so that discovered file paths are absolute and match
        // include_paths that are typically absolute (e.g. from git diff).
        let root = root.canonicalize().unwrap_or(root); // LAW10: canonicalize failure => original path (best-effort normalization); recall-safe
        Self {
            root,
            max_file_size: keyhog_core::DEFAULT_MAX_FILE_SIZE_BYTES,
            ignore_paths: Vec::new(),
            include_paths: Vec::new(),
            respect_gitignore: true,
            merkle: None,
            skipped: Arc::new(AtomicUsize::new(0)),
            window_size: reader::DEFAULT_WINDOW_SIZE,
            window_overlap: reader::DEFAULT_WINDOW_OVERLAP,
            respect_default_excludes: true,
            reader_threads: None,
        }
    }

    /// Toggle the walker's built-in exclusion list (lock/minified/vendored).
    /// Pass `false` (from `--no-default-excludes`) to scan files the default
    /// list would otherwise drop. Default `true`.
    #[must_use]
    pub fn with_default_excludes(mut self, respect: bool) -> Self {
        self.respect_default_excludes = respect;
        self
    }

    /// Override the windowed-scan parameters. Production callers stick
    /// with the defaults (1 MiB / 128 KiB); tests use this to exercise
    /// the multi-window path on tiny fixtures. `window_size` must
    /// strictly exceed `overlap` (the underlying slicer asserts this).
    pub(crate) fn with_window_config(mut self, window_size: usize, overlap: usize) -> Self {
        assert!(window_size > overlap, "window must exceed overlap");
        self.window_size = window_size;
        self.window_overlap = overlap;
        self
    }

    /// Wire the source up to a merkle index so `(path, mtime, size)`
    /// matches skip the file *before* it is read. The cache contents
    /// themselves are loaded by the orchestrator (which also handles
    /// detector-spec-hash invalidation) and shared via `Arc` so multiple
    /// sources can consult one index.
    pub fn with_merkle_skip(mut self, merkle: Arc<MerkleIndex>) -> Self {
        self.merkle = Some(merkle);
        self
    }

    /// Returns a counter that the source increments every time the
    /// metadata fast-path skips a file. Cloned `Arc<AtomicUsize>`, safe
    /// to read after the iterator drains.
    pub(crate) fn skipped_counter(&self) -> Arc<AtomicUsize> {
        self.skipped.clone()
    }

    /// Only include files whose paths match one of the given paths.
    /// Paths are compared against the absolute path of each discovered file.
    pub fn with_include_paths(mut self, paths: Vec<PathBuf>) -> Self {
        self.include_paths = paths;
        self
    }

    /// Override the maximum file size scanned from disk.
    pub fn with_max_file_size(mut self, bytes: u64) -> Self {
        self.max_file_size = bytes;
        self
    }

    /// Add patterns to ignore during the walk.
    pub fn with_ignore_paths(mut self, paths: Vec<String>) -> Self {
        self.ignore_paths = paths;
        self
    }

    /// Override whether the walk honors `.gitignore` / `.keyhogignore`.
    /// `keyhog scan-system` flips this to `false` so a leaked key
    /// stashed in `.gitignore` can't hide.
    pub fn with_respect_gitignore(mut self, respect: bool) -> Self {
        self.respect_gitignore = respect;
        self
    }

    /// Override the dedicated filesystem reader thread count.
    pub fn with_reader_threads(mut self, threads: NonZeroUsize) -> Self {
        self.reader_threads = Some(threads);
        self
    }
}

impl Source for FilesystemSource {
    fn name(&self) -> &str {
        "filesystem"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        let max_size = self.max_file_size;
        let mut config = walker_config(self.max_file_size, &self.ignore_paths);
        if !self.respect_gitignore {
            config = config.respect_gitignore(false);
        }
        if self.include_paths.is_empty() {
            match self.root.try_exists() {
                Ok(true) => {}
                Ok(false) => {
                    let error = SourceError::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!(
                            "filesystem root '{}' does not exist; path was not scanned",
                            self.root.display()
                        ),
                    ));
                    return Box::new(std::iter::once(Err(error)));
                }
                Err(error) => {
                    let error = SourceError::Io(std::io::Error::new(
                        error.kind(),
                        format!(
                            "failed to stat filesystem root '{}': {error}; path was not scanned",
                            self.root.display()
                        ),
                    ));
                    return Box::new(std::iter::once(Err(error)));
                }
            }
        }
        // Autoroute calibration and replay bucket the fused pipeline by chunk
        // batch shape. A parallel walker can emit the same tree in different
        // orders across runs, which changes which files land in a 32-chunk
        // batch and makes a freshly calibrated cache miss on replay. Collecting
        // and sorting FileEntry metadata by path keeps batch identity stable;
        // the heavier file reads still flow through the existing reader pool
        // below. Per-entry errors are counted and skipped, never propagated,
        // so one unreadable sibling cannot turn a partial scan into zero
        // findings.
        fn sorted_entries(walker: CodeWalker) -> Vec<codewalk::FileEntry> {
            let mut entries: Vec<_> = walker
                .walk_iter()
                .filter_map(|result| match result {
                    Ok(entry) => Some(entry),
                    Err(error) => {
                        // An unreadable entry is an UNKNOWN, not a clean file: count it
                        // so end-of-scan surfacing can tell the operator the tree was
                        // not fully covered (Law 10 — a permission-denied subtree must
                        // not read as "clean"). The warn! line is debug-level noise at
                        // the default log level; the counter is the durable signal.
                        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                        tracing::warn!(
                            %error,
                            "skipping unreadable filesystem entry; scan continues"
                        );
                        None
                    }
                })
                .collect();
            entries.sort_by(|left, right| left.path.cmp(&right.path));
            entries
        }

        let mut source_errors: Vec<SourceError> = Vec::new();
        let entries: Box<dyn Iterator<Item = codewalk::FileEntry> + Send> = if !self
            .include_paths
            .is_empty()
        {
            // Restrict the walk to the canonicalized allowed set so we
            // never traverse unrequested subdirectories (KH-54). The set is
            // small (user-supplied include list); directory entries are
            // collected deterministically before the reader pool, and
            // explicitly-named single files are stat'd directly without a walk.
            let mut allowed: Vec<PathBuf> = Vec::new();
            for p in &self.include_paths {
                // No-follow guard at include-admission (M17), scoped to the
                // dangerous case. Include paths are admitted below via
                // `canonicalize()` + `is_file()`, BOTH of which follow
                // symlinks, and canonicalize resolves the link before any
                // later `is_symlink(path)` check can see it — so the refusal
                // must happen HERE, on the original pre-canonicalization path.
                //
                // ASYMMETRY (two pinned contracts): a symlink to a PLAIN file
                // is read (documented "canonicalize-then-read" — the user
                // explicitly named it; see
                // `included_symlinked_plain_file_is_canonicalized_then_read`).
                // But a symlink whose own extension marks it an ARCHIVE /
                // expandable container (`creds.har -> ~/.aws/credentials`,
                // `x.zip -> /etc/...`) is REFUSED: following it would read AND
                // structurally EXPAND an out-of-tree target, the link-swap
                // exfiltration class (see `har_symlink_target_is_not_followed_via_include`).
                // The expandable-extension set mirrors the archive/compressed
                // branches in `extract.rs::process_entry`.
                let is_link = std::fs::symlink_metadata(p)
                    .map(|m| m.file_type().is_symlink())
                    .unwrap_or(false); // LAW10: empty/absent => documented numeric default, recall-safe
                if !is_link {
                    allowed.push(p.canonicalize().unwrap_or_else(|_| p.clone())); // LAW10: canonicalize failure => original path (best-effort normalization); recall-safe
                    continue;
                }
                const EXPANDABLE_SYMLINK_EXTS: &[&str] = &[
                    "har", "zip", "apk", "ipa", "crx", "jar", "tar", "gz", "tgz", "zst", "lz4",
                    "sz", "bz2", "xz", "7z", "rar", "pdf",
                ];
                let expandable = p.extension().and_then(|e| e.to_str()).is_some_and(|ext| {
                    EXPANDABLE_SYMLINK_EXTS
                        .iter()
                        .any(|candidate| ext.eq_ignore_ascii_case(candidate))
                });
                if expandable {
                    tracing::warn!(
                        path = %p.display(),
                        "refusing --include of an archive symlink - prevents the link-swap exfiltration class"
                    );
                    let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                    source_errors.push(SourceError::Other(format!(
                        "refusing to scan explicitly included archive symlink '{}': archive symlink expansion is blocked to prevent link-swap exfiltration",
                        p.display()
                    )));
                    continue;
                }
                allowed.push(p.canonicalize().unwrap_or_else(|_| p.clone())); // LAW10: canonicalize failure => original path (best-effort normalization); recall-safe
            }
            allowed.sort();
            allowed.dedup();
            let mut include_entries = Vec::new();
            for path in allowed {
                if path.is_dir() {
                    let sub_walker = CodeWalker::new(&path, config.clone());
                    include_entries.extend(sorted_entries(sub_walker));
                } else if path.is_file() {
                    match std::fs::metadata(&path) {
                        Ok(meta) => include_entries.push(codewalk::FileEntry {
                            path,
                            size: meta.len(),
                            // `is_binary` is a walk-time hint codewalk fills for
                            // directory walks. For an EXPLICITLY-included single
                            // file the user asked us to scan, leave it false:
                            // keyhog never reads this field (it does its own
                            // null-byte binary check at read time in this same
                            // file), so the hint is inert and `false` keeps the
                            // requested file in the scan set. (Required field
                            // since codewalk 0.2.5; omitting it broke every
                            // fresh keyhog-sources compile.)
                            is_binary: false,
                        }),
                        // Law 10: the user EXPLICITLY --include'd this file but
                        // `stat` failed (permission / I/O / race-delete). A
                        // silent `empty()` here drops a requested file while the
                        // scan still prints "0 secrets", reading as a clean bill
                        // of health for a file we never read. Count it as
                        // unreadable so `report_skip_summary` surfaces the gap
                        // (the same counter the archive-symlink refusal above uses).
                        Err(e) => {
                            tracing::warn!(
                                path = %path.display(),
                                error = %e,
                                "explicitly --include'd file could not be stat'd; NOT scanned"
                            );
                            let _event =
                                crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                            source_errors.push(SourceError::Other(format!(
                                "failed to scan explicitly included path '{}': stat failed ({e}); path was not scanned",
                                path.display()
                            )));
                        }
                    }
                } else {
                    // Explicitly --include'd path that is neither a file nor a
                    // directory: a broken symlink, a special file (socket /
                    // device / fifo), or it vanished between include-admission
                    // and this walk. The user named it, so a silent drop would
                    // again read as "clean" — count it unreadable so the gap is
                    // surfaced rather than swallowed (Law 10).
                    tracing::warn!(
                        path = %path.display(),
                        "explicitly --include'd path is neither a file nor a directory; NOT scanned"
                    );
                    let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                    source_errors.push(SourceError::Other(format!(
                        "failed to scan explicitly included path '{}': path is neither a file nor a directory; path was not scanned",
                        path.display()
                    )));
                }
            }
            Box::new(include_entries.into_iter())
        } else {
            let walker = CodeWalker::new(&self.root, config);
            Box::new(sorted_entries(walker).into_iter())
        };

        let merkle = self.merkle.clone();
        let skipped = self.skipped.clone();
        let window_size = self.window_size;
        let window_overlap = self.window_overlap;
        let respect_default_excludes = self.respect_default_excludes;
        let reader_threads = self.reader_threads;

        let rx = reader::spawn_chunk_producer(
            entries,
            merkle,
            skipped,
            self.root.clone(),
            max_size,
            window_size,
            window_overlap,
            respect_default_excludes,
            reader_threads,
        );
        Box::new(source_errors.into_iter().map(Err).chain(rx))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
