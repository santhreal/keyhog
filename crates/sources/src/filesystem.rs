//! Filesystem source: recursively walks a directory tree, skips binary files,
//! respects `.gitignore`, and yields chunks for scanning.

use codewalk::CodeWalker;
use keyhog_core::merkle_index::MerkleIndex;
use keyhog_core::{Chunk, Source, SourceError};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

mod extract;
mod filter;
mod read;

use extract::process_entry;
use filter::walker_config;
/// Default source-level window size for the large-file scanning path.
///
/// Keep this aligned with the scanner's 1 MiB max chunk size so a multi-MiB
/// source file enters the scanner as many independent chunks instead of one
/// worker serially re-windowing the entire file. The overlap below preserves
/// boundary-spanning secrets.
const DEFAULT_WINDOW_SIZE: usize = 1024 * 1024;

/// Convert a `Path` to a user-facing display string, stripping the
/// `\\?\` UNC verbatim prefix on Windows. `std::fs::canonicalize` on
/// Windows always returns extended-length paths (`\\?\C:\Users\...`),
/// which leak into finding output as
/// `"\\\\?\\C:\\Users\\..."` JSON strings. Editors don't jump to those,
/// and the prefix is purely a kernel implementation detail. Strip it
/// when surfacing the path to humans / IDEs while leaving the actual
/// `PathBuf` we use for I/O untouched.
pub(crate) fn display_path(path: &Path) -> String {
    let raw = path.display().to_string();
    if cfg!(windows) {
        strip_unc_prefix(&raw).to_string()
    } else {
        raw
    }
}

pub(crate) fn strip_unc_prefix(s: &str) -> &str {
    // Two shapes Rust may emit on Windows:
    //   `\\?\C:\Users\me\src` (drive-letter form - the common case)
    //   `\\?\UNC\server\share\dir` (network share form)
    // Both prefixes are 4 / 8 bytes of ASCII; safe to slice.
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        // `\\?\UNC\server\share` → `\\server\share`. Rebuilding the
        // double-backslash leading would require an allocation, so we
        // accept losing it: returning the bare `server\share` form is
        // ambiguous, so for UNC we leave it as-is for now (rare in
        // user scans) and just trim the `\\?\` part.
        let _ = rest;
        s.strip_prefix(r"\\?\").unwrap_or(s)
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        rest
    } else {
        s
    }
}

/// Default overlap between consecutive source windows. 128 KiB matches the
/// scanner's own window overlap and covers PEM-sized and multiline secrets
/// that straddle a source cut.
const DEFAULT_WINDOW_OVERLAP: usize = 128 * 1024;

const MAX_READER_POOL_THREADS: usize = 16;

fn reader_pool_thread_count(scanner_threads: usize) -> usize {
    let scanner_threads = scanner_threads.max(1);
    let half_scan_pool = scanner_threads.div_ceil(2);
    half_scan_pool.clamp(2, MAX_READER_POOL_THREADS)
}

#[doc(hidden)]
pub fn reader_pool_thread_count_for_test(scanner_threads: usize) -> usize {
    reader_pool_thread_count(scanner_threads)
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
}

impl FilesystemSource {
    /// Create a filesystem source rooted at `root`.
    pub fn new(root: PathBuf) -> Self {
        // Canonicalize so that discovered file paths are absolute and match
        // include_paths that are typically absolute (e.g. from git diff).
        let root = root.canonicalize().unwrap_or(root);
        Self {
            root,
            max_file_size: 100 * 1024 * 1024, // 100 MB default - large files use windowed scanning
            ignore_paths: Vec::new(),
            include_paths: Vec::new(),
            respect_gitignore: true,
            merkle: None,
            skipped: Arc::new(AtomicUsize::new(0)),
            window_size: DEFAULT_WINDOW_SIZE,
            window_overlap: DEFAULT_WINDOW_OVERLAP,
        }
    }

    /// Override the windowed-scan parameters. Production callers stick
    /// with the defaults (1 MiB / 128 KiB); tests use this to exercise
    /// the multi-window path on tiny fixtures. `window_size` must
    /// strictly exceed `overlap` (the underlying slicer asserts this).
    pub fn with_window_config(mut self, window_size: usize, overlap: usize) -> Self {
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
    pub fn skipped_counter(&self) -> Arc<AtomicUsize> {
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
        // Stream the walk through `walk_parallel` instead of `.collect()`-ing
        // it into a `Vec<FileEntry>` up front. The old flow drained the entire
        // directory walk into a Vec before the reader pool touched a byte: on a
        // multi-million-file tree that paid the whole enumeration latency with
        // the rayon pool idle AND held one PathBuf (+ size + flag) per file
        // resident before a single read - hundreds of MB for a 10M-file
        // monorepo / whole-disk scan-system walk. `walk_parallel` fans the walk
        // across background threads and pushes `FileEntry`s into a bounded
        // (8192-entry) channel AS THEY ARE DISCOVERED; `par_bridge()` below
        // pulls from that channel into the reader pool, so file reads start on
        // the first enumerated entry, directory-traversal syscalls overlap file
        // I/O, and resident entry memory is bounded by the channel depth, not
        // O(file_count).
        //
        // Per-entry errors (EACCES on a chmod-000 sub-tree, a racing unlink)
        // are logged and skipped, never propagated - one unreadable sibling
        // must not short-circuit the walk and hand the user ZERO findings (the
        // failure mode of `walk()`/`.collect()` on a `Result` iterator). The
        // channel `Receiver` is owned and `'static`, so the iterator can move
        // into the producer thread without borrowing a stack-local walker.
        //
        // threads=0 lets `ignore` pick the logical-CPU count, matching its own
        // `build_parallel` default.
        fn forward_entries(
            rx: std::sync::mpsc::Receiver<codewalk::error::Result<codewalk::FileEntry>>,
        ) -> impl Iterator<Item = codewalk::FileEntry> + Send {
            rx.into_iter().filter_map(|result| match result {
                Ok(entry) => Some(entry),
                Err(error) => {
                    tracing::warn!(
                        %error,
                        "skipping unreadable filesystem entry; scan continues"
                    );
                    None
                }
            })
        }

        let entries: Box<dyn Iterator<Item = codewalk::FileEntry> + Send> =
            if !self.include_paths.is_empty() {
                // Restrict the walk to the canonicalized allowed set so we
                // never traverse unrequested subdirectories (KH-54). The set is
                // small (user-supplied include list); the directory walks it
                // spawns stream lazily via `flat_map`, and explicitly-named
                // single files are stat'd directly without a walk.
                let allowed: HashSet<PathBuf> = self
                    .include_paths
                    .iter()
                    .map(|p| p.canonicalize().unwrap_or_else(|_| p.clone()))
                    .collect();
                Box::new(allowed.into_iter().flat_map(move |path| {
                    let inner: Box<dyn Iterator<Item = codewalk::FileEntry> + Send> =
                        if path.is_dir() {
                            let sub_walker = CodeWalker::new(&path, config.clone());
                            Box::new(forward_entries(sub_walker.walk_parallel(0)))
                        } else if path.is_file() {
                            match std::fs::metadata(&path) {
                                Ok(meta) => Box::new(std::iter::once(codewalk::FileEntry {
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
                                })),
                                Err(_) => Box::new(std::iter::empty()),
                            }
                        } else {
                            Box::new(std::iter::empty())
                        };
                    inner
                }))
            } else {
                let walker = CodeWalker::new(&self.root, config);
                Box::new(forward_entries(walker.walk_parallel(0)))
            };

        let merkle = self.merkle.clone();
        let skipped = self.skipped.clone();
        let window_size = self.window_size;
        let window_overlap = self.window_overlap;

        // Parallel file producer: the walk is lazy (dir tree syscalls
        // amortize cheaply), but per-file I/O + decode + chunk assembly
        // was previously serial - at ~16 MiB/s/core that meant a 16-core
        // box scanned at the speed of one core. A spawned producer thread
        // bridges the walk iterator into the rayon pool (which the CLI
        // sizes to `--threads`/physical cores), and each worker pushes
        // finished chunks through a bounded channel. The bound (64) caps
        // peak in-flight memory at ~64 × max-chunk-size independent of
        // corpus size; backpressure is automatic - when the scanner
        // thread (downstream) falls behind, workers block on `send` and
        // stop reading new files. Nosey Parker uses the same pattern
        // (ignore::WalkBuilder::build_parallel); the gap was never
        // throughput, it was concurrency.
        let (tx, rx) = std::sync::mpsc::sync_channel::<Result<Chunk, SourceError>>(64);

        // DEADLOCK FIX (large-tree scan hang). The reader below uses
        // `par_bridge()`, and each task BLOCKS on `tx.send` once the bounded
        // channel (64) fills - that backpressure is intentional. The hazard
        // is the POOL it runs on. Previously this spawned thread had no rayon
        // context, so `par_bridge` ran on the GLOBAL pool - the SAME pool the
        // downstream scanner uses for `scan_coalesced` (`chunks.par_iter()`).
        // On a large tree the pipeline saturates: every global worker parks in
        // `send` (channel full), so the scanner's `par_iter` can never get a
        // worker to do the scanning that would drain the channel and release
        // the readers. Reader-blocks-on-send and scanner-needs-worker form a
        // cycle and the whole scan deadlocks (all threads parked in futex at
        // ~0% CPU). Small trees drain before full saturation, which is why the
        // SecretBench mirror never exposed it but the Linux kernel (94k files)
        // hangs every time, under both the SIMD and GPU backends.
        //
        // Running the reader on a DEDICATED pool breaks the cycle: the reader
        // threads may all park in `send`, but the global pool stays free for
        // the scanner, which drains the channel, which unblocks the readers.
        // Size that pool below the scanner pool: reads and archive/string
        // extraction need overlap, not a second full CPU pool competing with
        // scan workers on large trees.
        let reader_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(reader_pool_thread_count(rayon::current_num_threads()))
            .thread_name(|i| format!("keyhog-reader-{i}"))
            .build()
            .ok();
        std::thread::spawn(move || {
            use rayon::iter::{ParallelBridge, ParallelIterator};
            // `par_bridge()` pulls entries from the lazy walk iterator on
            // demand through a shared Mutex-guarded cursor, so reads start
            // as soon as enumeration yields the first entry (overlapping
            // walk + I/O) and entry memory never materializes as one big
            // Vec. Unlike `into_par_iter()` on a `Vec`, the bridge does NOT
            // build a deep balanced split tree whose depth scales with file
            // count - that recursion was what overflowed the 8 MiB worker
            // stack (~1300+ nested bridge_producer_consumer frames, SIGABRT
            // "has overflowed its stack") on 100k+-file trees and forced the
            // old `.with_min_len(64)` floor. The bridge splits shallowly off
            // a single producer, so the stack stays bounded for any corpus
            // size without a grain knob.
            //
            // PERF NOTE (2026-05-31): a bounded-batch `into_par_iter` variant
            // was tried here on the theory that the bridge's single-mutex
            // cursor serialised the 94k-tiny-file pull. It REGRESSED the
            // kernel scan (84.2 s -> 102.7 s, 213% -> 175% CPU): the readers
            // are not pull-bound, they block on the inner `sync_channel(64)`
            // SEND (downstream-limited, confirmed by PERF-05's off-CPU
            // profile), and the per-batch barrier only cut overlap. The real
            // lever is the DOWNSTREAM single-thread funnel (one main-thread
            // chunk drain + one scanner thread), not the reader pull. Left as
            // par_bridge; do not "optimise" the reader without a measurement
            // that isolates the consumer side first.
            let pump = move || {
                entries.par_bridge().for_each_with(tx, |tx, entry| {
                    // `emit` returns false once the receiver is gone (scan
                    // cancelled / orchestrator shut down); `process_entry`
                    // stops producing the moment that happens instead of
                    // churning chunks no one will read. Emitting through a
                    // callback (rather than returning a Vec) keeps the
                    // windowed-file path streaming - one window's String is
                    // resident at a time, not the whole file.
                    let mut emit = |chunk: Result<Chunk, SourceError>| tx.send(chunk).is_ok();
                    process_entry(
                        entry,
                        &merkle,
                        &skipped,
                        max_size,
                        window_size,
                        window_overlap,
                        &mut emit,
                    );
                });
            };
            // Run the reader on the dedicated pool so it cannot starve the
            // scanner's global-pool `par_iter` (see DEADLOCK FIX above).
            match reader_pool {
                Some(pool) => pool.install(pump),
                None => pump(),
            }
        });

        Box::new(rx.into_iter())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
