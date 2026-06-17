//! Filesystem source: recursively walks a directory tree, skips binary files,
//! respects `.gitignore`, and yields chunks for scanning.

use codewalk::CodeWalker;
use keyhog_core::merkle_index::MerkleIndex;
use keyhog_core::{Chunk, Source, SourceError};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

mod extract;
mod filter;
mod path;
mod read;
mod reader;

use filter::walker_config;
pub(crate) use path::display_path;
pub(crate) use read::decode_text_file;

pub(crate) fn is_default_excluded_path(path: &str) -> bool {
    filter::is_default_excluded(path)
}

pub(crate) fn reader_pool_thread_count_for_test(scanner_threads: usize) -> usize {
    reader::reader_thread_count(scanner_threads)
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
        let root = root.canonicalize().unwrap_or(root); // LAW10: canonicalize failure => original path (best-effort normalization); recall-safe
        Self {
            root,
            max_file_size: 100 * 1024 * 1024, // 100 MB default - large files use windowed scanning
            ignore_paths: Vec::new(),
            include_paths: Vec::new(),
            respect_gitignore: true,
            merkle: None,
            skipped: Arc::new(AtomicUsize::new(0)),
            window_size: reader::DEFAULT_WINDOW_SIZE,
            window_overlap: reader::DEFAULT_WINDOW_OVERLAP,
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
                    let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                    tracing::warn!(
                        %error,
                        "skipping unreadable filesystem entry; scan continues"
                    );
                    None
                }
            })
        }

        let entries: Box<dyn Iterator<Item = codewalk::FileEntry> + Send> = if !self
            .include_paths
            .is_empty()
        {
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
                            .unwrap_or(false);  // LAW10: empty/absent => documented numeric default, recall-safe
                        if !is_link {
                            return true;
                        }
                        let ext = p
                            .extension()
                            .and_then(|e| e.to_str())
                            .unwrap_or("")  // LAW10: missing/non-string field => empty/placeholder; recall-safe
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
                            let _event =
                                crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                            return false;
                        }
                        true
                    })
                    .map(|p| p.canonicalize().unwrap_or_else(|_| p.clone()))  // LAW10: canonicalize failure => original path (best-effort normalization); recall-safe
                    .collect();
            Box::new(allowed.into_iter().flat_map(move |path| {
                let inner: Box<dyn Iterator<Item = codewalk::FileEntry> + Send> = if path.is_dir() {
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
                            Box::new(std::iter::empty())
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

        let rx = reader::spawn_chunk_producer(
            entries,
            merkle,
            skipped,
            self.root.clone(),
            max_size,
            window_size,
            window_overlap,
            respect_default_excludes,
        );
        Box::new(rx.into_iter())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
