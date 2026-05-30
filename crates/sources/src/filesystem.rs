//! Filesystem source: recursively walks a directory tree, skips binary files,
//! respects `.gitignore`, and yields chunks for scanning.

use codewalk::{CodeWalker, WalkConfig};
use keyhog_core::merkle_index::MerkleIndex;
use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use std::collections::HashSet;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

mod read;

/// Test whether `path` is a symlink. No cache: the walker visits each
/// path exactly once, so a process-lifetime `DashMap<PathBuf, bool>`
/// only ever sees a single lookup per key and retained one PathBuf per
/// file for the whole scan (1GB+ on a multi-million-file tree) while
/// providing a ~0% hit rate. A bare `symlink_metadata` stat is the
/// single-pass-correct choice. (Was KH-41 SYMLINK_CACHE; removed - the
/// cache was pure retained-forever overhead on single-pass walks.)
fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

static SKIP_EXTENSIONS_SET: OnceLock<std::collections::HashSet<&'static str>> = OnceLock::new();

fn get_skip_extensions() -> &'static std::collections::HashSet<&'static str> {
    SKIP_EXTENSIONS_SET.get_or_init(|| SKIP_EXTENSIONS.iter().copied().collect())
}

/// Minimum file size to use memory mapping. The crossover point is
/// platform-specific:
///
///   * Linux / macOS: mmap setup is sub-microsecond and avoids the
///     `read(2)` copy from kernel page cache to userland buffer. Worth
///     it as soon as the file is at least one page (4 KiB) - pick
///     64 KiB to keep tiny-config-file scans on the buffered path
///     where the syscall floor dominates either way.
///   * Windows: `MapViewOfFile` has more setup cost (security tokens,
///     section-object routing) and the `ReadFile` path is already
///     well-optimised by the OS for buffered I/O. Keep the historical
///     1 MiB threshold here to avoid regressing typical source-tree
///     scans.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const MMAP_THRESHOLD: u64 = 64 * 1024;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const MMAP_THRESHOLD: u64 = 1024 * 1024;
/// Default window size for the >64 MiB scanning path. Overridable on a
/// per-source basis (see `with_window_config`) so tests can exercise
/// the windowed flow without writing 64 MiB+ fixtures.
const DEFAULT_WINDOW_SIZE: usize = 64 * 1024 * 1024;

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

/// Default overlap between consecutive windows. 4 KiB matches the
/// longest plausible secret span we want to catch across the cut.
const DEFAULT_WINDOW_OVERLAP: usize = 4 * 1024;

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
    /// writing the 64 MiB fixtures the production threshold requires.
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
    /// with the defaults (64 MiB / 4 KiB); tests use this to exercise
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

/// File extensions to skip (binary, images, etc.).
const SKIP_EXTENSIONS: &[&str] = &[
    // Images
    "png",
    "jpg",
    "jpeg",
    "gif",
    "bmp",
    "ico",
    "cur",
    "icns",
    "webp",
    "svg",
    // Audio/Video
    "mp3",
    "mp4",
    "avi",
    "mov",
    "mkv",
    "flac",
    "wav",
    "ogg",
    "webm",
    // Archives (binary - secrets inside are caught by archive source, not filesystem)
    "tar",
    // gz / zst / lz4 / sz are handled by `extract_compressed_chunks`
    // below, NOT skipped - earlier versions had them in this list,
    // which silently bypassed the streaming-decompression path. See
    // the dispatch on line ~340 for the actual decoder routing.
    "tgz",
    "bz2",
    "xz",
    "rar",
    "7z",
    // NOTE: the zip extension is deliberately NOT skipped here. The per-file
    // read gate below (`if SKIP_EXTENSIONS.contains(ext) { return }`) runs
    // BEFORE the archive-unpack branch (which matches zip/apk/ipa/crx/jar), so
    // listing the zip extension here made a .zip return empty before
    // extraction ever ran - a recall bug where a secret in a committed .zip
    // was silently missed (.jar, in neither list, worked on identical bytes).
    // Dogfood 2026-05-29. The tar/7z/rar extensions stay skipped: no unpack
    // branch handles them.
    // Native binaries
    "exe",
    "dll",
    "so",
    "dylib",
    "o",
    "a",
    "lib",
    "obj",
    // Compiled/bytecode
    "class",
    "wasm",
    "pyc",
    "pyo",
    "elc",
    "beam",
    // Documents (binary formats)
    "pdf",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    // Fonts
    "ttf",
    "otf",
    "woff",
    "woff2",
    "eot",
    // Database files
    "db",
    "sqlite",
    "sqlite3",
    // Disk images / firmware
    "iso",
    "img",
    "bin",
    "rom",
    // Serialized data (not human-authored)
    "pickle",
    "npy",
    "npz",
    "onnx",
    "pb",
    "tflite",
    "pt",
    "safetensors",
];

/// Directories to skip entirely.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "vendor",
    "swagger-ui",
    "swagger",
];

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
        });

        Box::new(rx.into_iter())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Per-entry chunk extraction. Extracted from the inline `chunks()`
/// closure so it can run on a rayon worker via
/// `par_bridge().for_each_with`. Reads the file (or archive, or
/// compressed stream) and feeds each resulting `Chunk` to `emit` as it
/// is produced; the parallel producer fans calls out across the rayon
/// pool so per-file I/O overlaps freely.
///
/// Emitting through a callback (rather than returning a `Vec`) keeps the
/// large-file windowed path streaming: only one window's decoded
/// `String` is resident at a time before it flows into the bounded
/// orchestrator channel, instead of materializing every window of a
/// (up to `max_file_size`) file at once. `emit` returns `false` once the
/// receiver is gone (scan cancelled); we stop producing immediately so
/// no work is wasted on chunks no one will read.
///
/// Captures nothing beyond the parameters/callback, so the rayon closure
/// stays free of `&'_ self` borrows.
fn process_entry(
    entry: codewalk::FileEntry,
    merkle: &Option<Arc<MerkleIndex>>,
    skipped: &Arc<AtomicUsize>,
    max_size: u64,
    window_size: usize,
    window_overlap: usize,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) {
    let path = entry.path;
    let file_size = entry.size;

    // Screen out `.min.js` and `.bundle.js` files instantly using fast checks before reading/metadata stats (KH-55)
    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if is_default_excluded(filename) {
        return;
    }
    if filename.contains(".min.")
        || filename.contains(".bundle.")
        || filename.ends_with(".chunk.js")
        || filename.ends_with(".min.js")
        || filename.ends_with(".bundle.js")
    {
        return;
    }

    // Over-size audit. codewalk used to silently drop files past
    // `max_file_size` (filter.rs:46) - the user only saw a smaller
    // findings list with no signal about which files were suppressed.
    // We now disable codewalk's own cap (walker_config sets it to 0
    // = unlimited) and gate here so each over-size skip emits a warn
    // and increments the SKIPPED_OVER_MAX_SIZE counter the orchestrator
    // surfaces at end of scan. kimi-1 dogfood #130.
    if max_size > 0 && file_size > max_size {
        tracing::warn!(
            path = %path.display(),
            size_bytes = file_size,
            max_size,
            "skipping file: size exceeds --max-file-size cap"
        );
        crate::SKIPPED_OVER_MAX_SIZE.fetch_add(1, Ordering::Relaxed);
        return;
    }

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    // Compile the SKIP_EXTENSIONS array into a fast HashSet at startup to accelerate file-type screening (KH-45)
    if get_skip_extensions().contains(ext.as_str()) {
        return;
    }

    if ext.is_empty() {
        // Sniff the first 16 bytes of files without extensions to quickly skip binary structures without full content reads (KH-50)
        if let Ok(mut f) = std::fs::File::open(&path) {
            let mut buf = [0u8; 16];
            if let Ok(n) = f.read(&mut buf) {
                if n > 0 {
                    let is_binary = buf[..n].iter().any(|&b| b == 0)
                        || buf.starts_with(b"\x7fELF") // ELF
                        || buf.starts_with(b"MZ") // PE exe
                        || buf.starts_with(b"%PDF") // PDF
                        || buf.starts_with(b"PK\x03\x04"); // Zip / Docx
                    if is_binary {
                        return;
                    }
                }
            }
        }
    }

    // Fast-path skip: stat the file once and ask the merkle index "have I
    // seen this exact (path, mtime, size) tuple?" If yes, never
    // open() or read() - the dominant cost on cold-cache disk.
    // Stored alongside the chunk so the orchestrator can refresh
    // the index entry post-scan without a second stat. (No cross-file
    // mtime cache: the walker visits each path once, so a cache here
    // retained one PathBuf per file for the whole scan with no hits.)
    let live_mtime_ns = file_mtime_ns(&path);
    if let (Some(idx), Some(mtime_ns)) = (merkle.as_ref(), live_mtime_ns) {
        if idx.metadata_unchanged(&path, mtime_ns, file_size) {
            skipped.fetch_add(1, Ordering::Relaxed);
            return;
        }
    }

    if ext == "zip" || ext == "apk" || ext == "ipa" || ext == "crx" || ext == "jar" {
        // SSRF/path-traversal defense: refuse to open archive paths
        // that resolve through a symlink. The walker's
        // `follow_symlinks=false` lists the symlink file itself, and
        // openpack::open_default does NOT honor O_NOFOLLOW - a
        // symlink named secret.zip → /etc/shadow would otherwise let
        // an attacker stage an archive that openpack reads from the
        // (privileged) target. symlink_metadata() does not follow
        // links; if file_type().is_symlink() we skip the archive
        // entirely. Kimi sources-audit HIGH finding.
        if is_symlink(&path) {
            tracing::warn!(
                archive = %path.display(),
                "refusing to open archive at a symlink path - \
                 prevents the link-swap attack class"
            );
            return;
        }
        // Per-entry uncompressed-size cap to defeat zip-bomb DoS.
        // openpack's central directory exposes uncompressed_size; skip
        // any entry that exceeds max_size (per-file cap) and the total
        // uncompressed budget. Each decoded entry is emitted immediately
        // so we never hold the whole archive's worth of chunks at once.
        let archive_display = display_path(&path);
        let mut total_uncompressed: u64 = 0;
        let total_budget: u64 = max_size.saturating_mul(4); // 4x file cap budget for archives
        if let Ok(pack) = openpack::OpenPack::open_default(&path) {
            if let Ok(entries) = pack.entries() {
                for archive_entry in entries {
                    if archive_entry.is_dir || is_default_excluded(&archive_entry.name) {
                        continue;
                    }
                    if archive_entry.uncompressed_size > max_size {
                        tracing::warn!(
                            archive = %path.display(),
                            entry = %archive_entry.name,
                            size = archive_entry.uncompressed_size,
                            "skipping archive entry: uncompressed size exceeds per-file cap"
                        );
                        continue;
                    }
                    total_uncompressed =
                        total_uncompressed.saturating_add(archive_entry.uncompressed_size);
                    if total_uncompressed > total_budget {
                        tracing::warn!(
                            archive = %path.display(),
                            "aborting archive extraction: total uncompressed size exceeds 4x file cap (zip-bomb guard)"
                        );
                        break;
                    }
                    if let Ok(content) = pack.read_entry(&archive_entry.name) {
                        let entry_path = || format!("{}//{}", archive_display, archive_entry.name);
                        let chunk = match String::from_utf8(content) {
                            Ok(s) => Some(Ok(Chunk {
                                data: s.into(),
                                metadata: ChunkMetadata {
                                    source_type: "filesystem/archive".into(),
                                    path: Some(entry_path()),
                                    ..Default::default()
                                },
                            })),
                            Err(error) => {
                                let content = error.into_bytes();
                                let strings =
                                    crate::strings::extract_printable_strings(&content, 8);
                                if strings.is_empty() {
                                    None
                                } else {
                                    Some(Ok(Chunk {
                                        data: keyhog_core::SensitiveString::join(&strings, "\n"),
                                        metadata: ChunkMetadata {
                                            source_type: "filesystem/archive-binary".into(),
                                            path: Some(entry_path()),
                                            ..Default::default()
                                        },
                                    }))
                                }
                            }
                        };
                        if let Some(chunk) = chunk {
                            if !emit(chunk) {
                                return;
                            }
                        }
                    }
                }
            }
        }
        return;
    } else if ext == "gz" || ext == "zst" || ext == "lz4" || ext == "sz" {
        extract_compressed_chunks(&path, max_size, emit);
        return;
    } else if ext == "har" {
        // Browser DevTools "Save all as HAR with content" export.
        // Expand into one chunk per request + one per response so
        // findings carry the `wire:har:request` / `wire:har:response`
        // source-type distinction (outbound credential leak vs
        // inbound credential reflection). Falls through to the
        // regular text scan when the file fails to parse - better to
        // grep a malformed HAR than to silently drop it.
        if let Ok(bytes) = std::fs::read(&path) {
            let path_str = display_path(&path);
            if let Some(har_chunks) = crate::har::try_expand_har(&bytes, &path_str, max_size) {
                for chunk in har_chunks {
                    if !emit(chunk) {
                        return;
                    }
                }
                return;
            }
        }
        // fall through to the regular text scan below
    }

    if file_size > window_size as u64 {
        let display = display_path(&path);
        // Fast path: mmap once and slice zero-copy into overlapping
        // `window_size` views with `window_overlap` shared bytes
        // between neighbours. Replaces a 64 MiB heap buffer +
        // per-window `seek-back+re-read` round-trip with a single
        // mmap + madvise(SEQUENTIAL). We `into_iter()` the window Vec
        // and emit each chunk as we go so a window's decoded `String`
        // is dropped before the next is built - resident memory stays
        // ~one window rather than the whole file.
        if let Some(windows) = read::read_file_windowed_mmap(&path, window_size, window_overlap) {
            for w in windows {
                let chunk = Ok(Chunk {
                    data: w.text.into(),
                    metadata: ChunkMetadata {
                        source_type: "filesystem/windowed".to_string(),
                        path: Some(display.clone()),
                        base_offset: w.offset,
                        mtime_ns: live_mtime_ns,
                        size_bytes: Some(file_size),
                        ..Default::default()
                    },
                });
                if !emit(chunk) {
                    return;
                }
            }
            return;
        }
        // Buffered fallback: mmap refused (locked writer, unsupported
        // filesystem). Working buffer + seek-back overlap, sized to the
        // configured window so test overrides apply here too. Each
        // window is emitted as soon as it is decoded, so only the single
        // reusable read buffer plus one window's `String` is resident -
        // the prior implementation collected every window of the entire
        // file into a Vec before returning, holding the whole (up to
        // `max_file_size`) file decoded at once.
        if let Ok(mut file) = std::fs::File::open(&path) {
            let mut current_offset = 0;
            let mut buffer = vec![0u8; window_size];
            while let Ok(n) = file.read(&mut buffer) {
                if n == 0 {
                    break;
                }
                let data = String::from_utf8_lossy(&buffer[..n]).into_owned();
                let chunk = Ok(Chunk {
                    data: data.into(),
                    metadata: ChunkMetadata {
                        source_type: "filesystem/windowed".to_string(),
                        path: Some(display.clone()),
                        base_offset: current_offset,
                        mtime_ns: live_mtime_ns,
                        size_bytes: Some(file_size),
                        ..Default::default()
                    },
                });
                if !emit(chunk) {
                    return;
                }
                if n < window_size {
                    break;
                }
                let _ = file.seek(SeekFrom::Current(-(window_overlap as i64)));
                current_offset += n - window_overlap;
            }
        }
        return;
    }
    let file_text = if file_size >= MMAP_THRESHOLD {
        read::read_file_mmap(&path)
    } else {
        read::read_file_buffered(&path)
    };

    let (content, source_type) = match file_text {
        Some(text) if !text.is_empty() => (text.into(), "filesystem"),
        _ => {
            if let Ok(bytes) = read::read_file_safe(&path) {
                let strings = crate::strings::extract_printable_strings(&bytes, 8);
                if strings.is_empty() {
                    return;
                }
                (
                    keyhog_core::SensitiveString::join(&strings, "\n"),
                    "filesystem:binary-strings",
                )
            } else {
                return;
            }
        }
    };

    let _ = emit(Ok(Chunk {
        data: content,
        metadata: ChunkMetadata {
            source_type: source_type.to_string(),
            path: Some(display_path(&path)),
            mtime_ns: live_mtime_ns,
            size_bytes: Some(file_size),
            ..Default::default()
        },
    }));
}

fn extract_compressed_chunks(
    path: &Path,
    max_size: u64,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    let format = match ext.as_str() {
        "gz" => ziftsieve::CompressionFormat::Gzip,
        "zst" => ziftsieve::CompressionFormat::Zstd,
        "lz4" => ziftsieve::CompressionFormat::Lz4,
        _ => ziftsieve::CompressionFormat::Snappy,
    };

    // mmap the compressed file when possible - ziftsieve only takes a
    // contiguous `&[u8]`, so a streaming decoder isn't on the menu, but
    // mmap lets us hand it the whole file without a corresponding heap
    // allocation. A 1 GiB `.zst` previously turned into a 1 GiB
    // `Vec<u8>` before decompression even started; now it sits in the
    // page cache backed by the file. Falls back to a buffered read
    // when mmap is refused (locked writer, unsupported filesystem) so
    // behaviour is identical to the prior implementation in that case.
    //
    // The per-source `max_size` doubles as the compressed-input cap:
    // anything bigger is refused before mapping. The decompressed
    // budget gate (4× max_size) still applies inside the loop below.
    let file_bytes = match read::read_file_for_compressed_input(path, max_size) {
        Some(b) => b,
        None => return,
    };
    let bytes = file_bytes.as_slice();

    // Decompression-bomb cap: a 4x compression-ratio multiplier on the
    // per-file size budget bounds total expanded bytes. A 1 MB gzip bomb
    // expanding to 4 GB hits this ceiling and aborts cleanly instead of
    // OOMing. See audit release-2026-04-26 filesystem.rs:308-361.
    let total_budget: usize = max_size.saturating_mul(4) as usize;

    if let Ok(blocks) = ziftsieve::extract_from_bytes(format, bytes) {
        let mut current_chunk_literals = String::new();
        let mut total_decompressed: usize = 0;
        let path_display = display_path(path);
        for block in blocks {
            if let Ok(s) = std::str::from_utf8(block.literals()) {
                total_decompressed = total_decompressed.saturating_add(s.len());
                if total_decompressed > total_budget {
                    tracing::warn!(
                        path = %path.display(),
                        bytes = total_decompressed,
                        cap = total_budget,
                        "aborting compressed extraction: total decompressed size exceeds 4x file cap (gzip-bomb guard)"
                    );
                    break;
                }
                current_chunk_literals.push_str(s);
                current_chunk_literals.push('\n');
            }

            if current_chunk_literals.len() > 8 * 1024 * 1024 {
                if !emit(Ok(Chunk {
                    data: std::mem::take(&mut current_chunk_literals).into(),
                    metadata: ChunkMetadata {
                        source_type: "filesystem/compressed".into(),
                        path: Some(path_display.clone()),
                        ..Default::default()
                    },
                })) {
                    return;
                }
            }
        }
        if !current_chunk_literals.is_empty() {
            let _ = emit(Ok(Chunk {
                data: current_chunk_literals.into(),
                metadata: ChunkMetadata {
                    source_type: "filesystem/compressed".into(),
                    path: Some(path_display),
                    ..Default::default()
                },
            }));
        }
    }
}

/// Check if a path matches the built-in default exclusion patterns.
/// Mirrors the patterns in `crates/cli/src/sources.rs`.
///
/// ASCII case-insensitive byte comparisons; splits on both `/` and
/// `\` so Windows paths get the same treatment as POSIX. The previous
/// flow built a fully-lowercased copy of the entire path and ran
/// POSIX-only `.contains("/x/")` checks, which (a) allocated per
/// file on the walker hot path and (b) silently failed to exclude
/// `\node_modules\`, `\vendor\`, etc. on Windows checkouts.
fn is_default_excluded(path: &str) -> bool {
    let bytes = path.as_bytes();
    let ends_ci = |suffix: &[u8]| -> bool {
        bytes.len() >= suffix.len()
            && bytes[bytes.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
    };

    // File suffixes
    const SUFFIXES: &[&[u8]] = &[
        b".min.js",
        b".min.css",
        b".bak",
        b".swp",
        b".tmp",
        b".map",
        b".cache",
    ];
    if SUFFIXES.iter().any(|s| ends_ci(s)) {
        return true;
    }

    // Directory contents - segment-walk catches both separators.
    const SKIP_SEGMENTS: &[&[u8]] = &[
        b"node_modules",
        b".git",
        b"__pycache__",
        b"vendor",
        b"dist",
        b"build",
        b"out",
    ];
    let mut filename: &[u8] = bytes;
    for segment in path.split(['/', '\\']) {
        let seg_bytes = segment.as_bytes();
        if SKIP_SEGMENTS
            .iter()
            .any(|skip| seg_bytes.eq_ignore_ascii_case(skip))
        {
            return true;
        }
        if !seg_bytes.is_empty() {
            filename = seg_bytes;
        }
    }

    // Specific filename matches (the trailing component only -
    // intermediate-dir matches were already handled above).
    const FILENAMES: &[&[u8]] = &[
        b"package-lock.json",
        b"yarn.lock",
        b"pnpm-lock.yaml",
        b"cache.json",
        b"cargo.lock",
        b"go.sum",
        b"gemfile.lock",
        b"angular.json",
    ];
    if FILENAMES
        .iter()
        .any(|name| filename.eq_ignore_ascii_case(name))
    {
        return true;
    }

    // tsconfig*.json
    let tsc = b"tsconfig";
    let json = b".json";
    if filename.len() >= tsc.len() + json.len()
        && filename[..tsc.len()].eq_ignore_ascii_case(tsc)
        && filename[filename.len() - json.len()..].eq_ignore_ascii_case(json)
    {
        return true;
    }

    false
}

/// Read the mtime as nanoseconds-since-UNIX-epoch via a single `stat`.
/// Returns `None` when the platform/filesystem doesn't expose a usable
/// modified time - in that case the cache fast-path simply doesn't fire,
/// which is strictly better than a false skip.
fn file_mtime_ns(path: &Path) -> Option<u64> {
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    let dur = modified.duration_since(std::time::UNIX_EPOCH).ok()?;
    // Cap nanos at u64::MAX for the (unrealistic) far-future case so the
    // numeric key stays stable. ~584 years from epoch fits in u64 ns
    // comfortably; the real concern is filesystems returning weird values.
    let nanos = dur.as_secs() as u128 * 1_000_000_000 + dur.subsec_nanos() as u128;
    Some(u64::try_from(nanos).unwrap_or(u64::MAX))
}

fn walker_config(max_file_size: u64, ignore_paths: &[String]) -> WalkConfig {
    let mut exclude_extensions = HashSet::new();
    exclude_extensions.extend(SKIP_EXTENSIONS.iter().map(|ext| (*ext).to_string()));

    let mut exclude_dirs = HashSet::new();
    exclude_dirs.extend(SKIP_DIRS.iter().map(|dir| (*dir).to_string()));

    let ignore_overrides = ignore_paths
        .iter()
        .map(|pattern| {
            if pattern.starts_with('!') {
                pattern.clone()
            } else {
                format!("!{pattern}")
            }
        })
        .collect();

    // Pass max_file_size=0 (unlimited) to codewalk so the cap is
    // enforced inside keyhog instead. That moves the silent walker
    // skip into `process_entry` where we can warn + count it
    // (kimi-1 dogfood #130). codewalk's size filter runs before its
    // binary-detect read, so disabling it adds ~4 KiB of extra read
    // per over-size file - negligible at the scale where users hit
    // the cap.
    let _ = max_file_size;

    WalkConfig::default()
        .max_file_size(0)
        .follow_symlinks(false)
        .respect_gitignore(true)
        .skip_hidden(false)
        .skip_binary(false)
        .exclude_extensions(exclude_extensions)
        .exclude_dirs(exclude_dirs)
        .ignore_files(vec![".keyhogignore".to_string()])
        .ignore_patterns(ignore_overrides)
}
