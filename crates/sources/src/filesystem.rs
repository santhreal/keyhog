//! Filesystem source: recursively walks a directory tree, skips binary files,
//! respects `.gitignore`, and yields chunks for scanning.

use codewalk::CodeWalker;
use keyhog_core::merkle_index::MerkleIndex;
use keyhog_core::{Chunk, Source, SourceError};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};

mod extract;
mod filter;
mod read;

pub(crate) use read::decode_text_file;
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

/// Hard ceiling on the dedicated file-reader crew. The crew is sized as a
/// SMALL fraction of the host's cores (the I/O-overlap budget), NOT as a
/// fraction of the scan pool. Reader threads spend almost all their time
/// blocked - on the bounded `sync_channel(64)` `send` (downstream backpressure,
/// confirmed by PERF-05's off-CPU profile) or on `read(2)` - so a modest crew
/// overlaps read + decode + chunk-assembly with scanning while leaving the bulk
/// of the cores to the scan workers. Growing it with the scan pool (the old
/// `scan/2` sizing) only oversubscribes cores against the scan workers.
const MAX_READER_THREADS: usize = 4;

/// Number of dedicated file-reader threads to run alongside a scan pool of
/// `scanner_threads`.
///
/// CRITICAL INVARIANT (PERF-parallel_cores): the reader crew must NOT scale
/// with the scan pool. The previous sizing `clamp(scanner_threads/2, 2, 16)`
/// added a SECOND CPU pool on top of the scan pool, so an N-core box running
/// N scan threads also ran ~N/2 reader threads (16 scan + 8 reader = 24 on 16
/// cores; 32 + 16 = 48). Those reader threads do real CPU work (UTF-8 decode,
/// chunk assembly) and the OS time-sliced them against the scan workers,
/// capping end-to-end multicore scaling at ~4.7x@16t (the scan engine alone
/// reaches ~9.7x) and REGRESSING at 32t.
///
/// The crew is instead a small slice of the host (~1/4 of the cores), capped at
/// [`MAX_READER_THREADS`] and floored at 2. That is the I/O-overlap budget: a
/// handful of readers keep many scan workers fed (real scan work - Hyperscan +
/// ML - dwarfs per-file read/decode, so few readers saturate the consumer),
/// while the crew never balloons with the scan pool and so never oversubscribes
/// cores. The readers run on their OWN threads (never the global/scan rayon
/// pool), preserving the deadlock-avoidance invariant from the large-tree hang
/// fix. `scanner_threads/4` ties the crew to the same core count the scan pool
/// is sized from (the CLI sizes the global pool to `--threads`/physical cores),
/// so reader + scan stays within the machine instead of stacking a second pool
/// on top of it.
fn reader_thread_count(scanner_threads: usize) -> usize {
    // Tier-A operational override: `KEYHOG_READER_THREADS` lets an operator pin
    // the reader crew (e.g. on an unusually I/O-bound or unusually CPU-bound
    // corpus) without a recompile. A `0` / unparseable value falls back to the
    // computed default. The override is still bounded by `scanner_threads` so it
    // can never request more readers than the scan pool can usefully feed.
    if let Ok(raw) = std::env::var("KEYHOG_READER_THREADS") {
        if let Ok(n) = raw.trim().parse::<usize>() {
            if n > 0 {
                return n.min(scanner_threads.max(1));
            }
        }
    }
    // ~1/4 of the cores for I/O overlap, floored at 2 (one reader can stall on
    // a slow file) and capped so the crew never balloons. Never more readers
    // than scan threads (a 1-thread scan needs only 1 reader).
    let crew = (scanner_threads / 4).clamp(2, MAX_READER_THREADS);
    crew.min(scanner_threads.max(1))
}

#[doc(hidden)]
pub fn reader_pool_thread_count_for_test(scanner_threads: usize) -> usize {
    reader_thread_count(scanner_threads)
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
            respect_default_excludes: true,
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
                    // An unreadable entry is an UNKNOWN, not a clean file: count it
                    // so end-of-scan surfacing can tell the operator the tree was
                    // not fully covered (Law 10 — a permission-denied subtree must
                    // not read as "clean"). The warn! line is debug-level noise at
                    // the default log level; the counter is the durable signal.
                    crate::SKIPPED_UNREADABLE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
                    .filter(|p| {
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
                            .unwrap_or(false);
                        if !is_link {
                            return true;
                        }
                        let ext = p
                            .extension()
                            .and_then(|e| e.to_str())
                            .unwrap_or("")
                            .to_ascii_lowercase();
                        let expandable = matches!(
                            ext.as_str(),
                            "har" | "zip" | "apk" | "ipa" | "crx" | "jar" | "tar" | "gz"
                                | "tgz" | "zst" | "lz4" | "sz"
                        );
                        if expandable {
                            tracing::warn!(
                                path = %p.display(),
                                "refusing --include of an archive symlink - prevents the link-swap exfiltration class"
                            );
                            crate::SKIPPED_UNREADABLE
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            return false;
                        }
                        true
                    })
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
        let respect_default_excludes = self.respect_default_excludes;

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

        // DEADLOCK FIX (large-tree scan hang) + CORE-BUDGET FIX
        // (PERF-parallel_cores). Two invariants the reader MUST satisfy:
        //
        //   1. Readers must NOT run on the global rayon pool. The downstream
        //      scanner runs `scan_coalesced` via `par_iter` on that pool. If
        //      the readers shared it, on a large tree every pool worker would
        //      park in `tx.send` (channel full) and the scanner could never
        //      get a worker to drain the channel and unblock the readers - a
        //      reader-blocks-on-send / scanner-needs-worker cycle that hung the
        //      94k-file Linux kernel scan every time (all threads in futex at
        //      ~0% CPU). Readers on their OWN threads break the cycle: they may
        //      all park in `send`, but the global pool stays free to scan.
        //
        //   2. Readers must NOT form a SECOND full CPU pool sized as a fraction
        //      of the scan pool. The previous design ran a dedicated rayon pool
        //      of `clamp(scan_threads/2, 2, 16)` readers ON TOP of the scan
        //      pool, so an N-core box ran N scan + ~N/2 reader threads (16+8=24
        //      on 16 cores; 32+16=48). Reader threads do real CPU work (UTF-8
        //      decode, chunk assembly), so the OS time-sliced them against the
        //      scan workers and capped end-to-end scaling at ~4.7x@16t while
        //      the scan engine alone reaches ~9.7x - and 32t REGRESSED below
        //      16t as the reader pool grew to 16. (PERF-parallel_cores tripwire)
        //
        // The fix that satisfies BOTH: a SMALL FIXED crew of dedicated reader
        // threads (`reader_thread_count`, ~1/4 of the cores, capped at
        // MAX_READER_THREADS), sharing the lazy walk iterator through a
        // `Mutex`-guarded cursor and
        // pushing finished chunks into the same bounded `sync_channel(64)`.
        // The crew is mostly parked (on `send` backpressure or `read(2)`), so
        // it overlaps reads with scans WITHOUT claiming scan cores, and its
        // size never grows with the scan pool - ending the oversubscription.
        // The cursor `Mutex` is held only for the O(1) `next()` pull; the heavy
        // per-file work (`process_entry`: read + decode + chunk assembly) runs
        // OUTSIDE the lock, so the readers still parallelise across files. This
        // mirrors `par_bridge`'s shared-cursor pull WITHOUT par_bridge's pool
        // coupling: pulling off a single shared cursor (not an `into_par_iter`
        // split tree) also keeps the worker stack bounded for any corpus size,
        // so the 100k+-file stack-overflow that forced the old `.with_min_len`
        // floor cannot recur.
        let cursor: Arc<Mutex<Box<dyn Iterator<Item = codewalk::FileEntry> + Send>>> =
            Arc::new(Mutex::new(entries));
        let reader_count = reader_thread_count(rayon::current_num_threads());

        // One reader's drain loop: pull entries off the shared cursor and feed
        // each one's chunks into `tx` until the walk is drained or the receiver
        // is gone. Shared by every reader thread (and by the synchronous
        // fallback below) so the production path is identical regardless of how
        // many threads back it.
        let run_reader =
            move |cursor: Arc<Mutex<Box<dyn Iterator<Item = codewalk::FileEntry> + Send>>>,
                  tx: std::sync::mpsc::SyncSender<Result<Chunk, SourceError>>,
                  merkle: Option<Arc<MerkleIndex>>,
                  skipped: Arc<AtomicUsize>| {
                loop {
                    // Hold the cursor lock only for the cheap pull, then release it
                    // so other readers advance while this thread does the heavy
                    // read + decode.
                    let entry = {
                        let mut guard = match cursor.lock() {
                            Ok(g) => g,
                            // A peer reader panicked mid-pull: the walk iterator may
                            // be in any state, so stop this reader rather than risk
                            // emitting torn chunks.
                            Err(_) => return,
                        };
                        guard.next()
                    };
                    let Some(entry) = entry else {
                        return; // walk drained
                    };

                    // `emit` returns false once the receiver is gone (scan
                    // cancelled / orchestrator shut down); `process_entry` stops
                    // producing the moment that happens instead of churning chunks
                    // no one will read. Emitting through a callback (rather than
                    // returning a Vec) keeps the windowed-file path streaming - one
                    // window's String is resident at a time, not the whole file.
                    let mut sender_alive = true;
                    let mut emit = |chunk: Result<Chunk, SourceError>| {
                        let ok = tx.send(chunk).is_ok();
                        sender_alive = ok;
                        ok
                    };
                    process_entry(
                        entry,
                        &merkle,
                        &skipped,
                        max_size,
                        window_size,
                        window_overlap,
                        respect_default_excludes,
                        &mut emit,
                    );
                    if !sender_alive {
                        return; // receiver dropped; nothing more to feed
                    }
                }
            };

        let mut spawned = 0usize;
        for i in 0..reader_count {
            let cursor = Arc::clone(&cursor);
            let tx = tx.clone();
            let merkle = merkle.clone();
            let skipped = skipped.clone();
            let run_reader = run_reader.clone();
            match std::thread::Builder::new()
                .name(format!("keyhog-reader-{i}"))
                .spawn(move || run_reader(cursor, tx, merkle, skipped))
            {
                Ok(_) => spawned += 1,
                // OS thread-table exhaustion (EAGAIN) must not abort the scan:
                // the cursor is shared, so any reader that DID start still
                // drains the whole walk - it just has less I/O overlap. We log
                // and keep going rather than panic.
                Err(error) => {
                    tracing::warn!(%error, reader = i, "failed to spawn file-reader thread; continuing with fewer readers");
                }
            }
        }

        // Guarantee the walk is drained even if EVERY reader spawn failed: hand
        // the cursor to one last dedicated thread. If even that spawn fails
        // (the box is truly out of threads), drain synchronously on this thread
        // before returning - the channel is bounded(64) so this can't OOM, and
        // it is strictly better than returning an iterator no thread will ever
        // feed (which would surface ZERO findings - a silent recall loss). This
        // mirrors the previous design's `None => pump()` inline fallback.
        if spawned == 0 {
            let cursor_fb = Arc::clone(&cursor);
            let tx_fb = tx.clone();
            let merkle_fb = merkle.clone();
            let skipped_fb = skipped.clone();
            let run_reader_fb = run_reader.clone();
            if std::thread::Builder::new()
                .name("keyhog-reader-fallback".to_string())
                .spawn(move || run_reader_fb(cursor_fb, tx_fb, merkle_fb, skipped_fb))
                .is_err()
            {
                run_reader(cursor, tx.clone(), merkle.clone(), skipped.clone());
            }
        }

        // Drop the original `tx`: once every reader thread finishes and drops
        // its clone, the channel closes and `rx.into_iter()` ends. Without this
        // the consumer would block forever waiting on a sender that never
        // existed past this point.
        drop(tx);

        Box::new(rx.into_iter())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
