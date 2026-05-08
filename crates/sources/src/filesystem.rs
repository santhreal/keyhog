//! Filesystem source: recursively walks a directory tree, skips binary files,
//! respects `.gitignore`, and yields chunks for scanning.

use codewalk::{CodeWalker, WalkConfig};
use keyhog_core::merkle_index::MerkleIndex;
use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use std::collections::HashSet;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

mod read;

/// Minimum file size to use memory mapping. The crossover point is
/// platform-specific:
///
///   * Linux / macOS: mmap setup is sub-microsecond and avoids the
///     `read(2)` copy from kernel page cache to userland buffer. Worth
///     it as soon as the file is at least one page (4 KiB) — pick
///     64 KiB to keep tiny-config-file scans on the buffered path
///     where the syscall floor dominates either way.
///   * Windows: `MapViewOfFile` has more setup cost (security tokens,
///     section-object routing) and the `ReadFile` path is already
///     well-optimised by the OS for buffered I/O. Keep the historical
///     1 MiB threshold here to avoid regressing typical source-tree
///     scans.
#[cfg(unix)]
const MMAP_THRESHOLD: u64 = 64 * 1024;
#[cfg(not(unix))]
const MMAP_THRESHOLD: u64 = 1024 * 1024;
/// Default window size for the >64 MiB scanning path. Overridable on a
/// per-source basis (see `with_window_config`) so tests can exercise
/// the windowed flow without writing 64 MiB+ fixtures.
const DEFAULT_WINDOW_SIZE: usize = 64 * 1024 * 1024;
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
    /// a stored entry the file is skipped without an open() / read() —
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
            max_file_size: 100 * 1024 * 1024, // 100 MB default — large files use windowed scanning
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
    // Archives (binary — secrets inside are caught by archive source, not filesystem)
    "tar",
    // gz / zst / lz4 / sz are handled by `extract_compressed_chunks`
    // below, NOT skipped — earlier versions had them in this list,
    // which silently bypassed the streaming-decompression path. See
    // the dispatch on line ~340 for the actual decoder routing.
    "tgz",
    "bz2",
    "xz",
    "rar",
    "7z",
    "zip",
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
        // Use walk_iter (NOT walk()) so per-entry errors don't
        // collapse the entire scan. `walk()` collects into a Vec
        // via `.collect()` on a Result iterator — a single
        // permission-denied (chmod 000 sub-tree, EACCES on a
        // sibling) short-circuits the whole walk and the user
        // gets ZERO findings. Production-grade behaviour is to
        // log+skip the failed entry and keep walking everything
        // else.
        let walker = CodeWalker::new(&self.root, config);
        let mut entries: Vec<codewalk::FileEntry> = walker
            .walk_iter()
            .filter_map(|result| match result {
                Ok(entry) => Some(entry),
                Err(error) => {
                    tracing::warn!(
                        %error,
                        "skipping unreadable filesystem entry; scan continues"
                    );
                    None
                }
            })
            .collect();

        if !self.include_paths.is_empty() {
            // Canonicalize both sides for consistent comparison
            let allowed: HashSet<PathBuf> = self
                .include_paths
                .iter()
                .map(|p| p.canonicalize().unwrap_or_else(|_| p.clone()))
                .collect();
            entries.retain(|e| {
                let canonical = e.path.canonicalize().unwrap_or_else(|_| e.path.clone());
                allowed.contains(&canonical)
            });
        }

        let merkle = self.merkle.clone();
        let skipped = self.skipped.clone();
        let window_size = self.window_size;
        let window_overlap = self.window_overlap;

        Box::new(entries.into_iter().flat_map(move |entry| {
            let path = entry.path;
            let file_size = entry.size;

            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();

            if SKIP_EXTENSIONS.contains(&ext.as_str()) {
                return vec![];
            }

            // Fast-path skip: stat the file once, ask the cache "have I
            // seen this exact (path, mtime, size) tuple?" If yes, never
            // open() or read() — the dominant cost on cold-cache disk.
            // Stored alongside the chunk so the orchestrator can refresh
            // the index entry post-scan without a second stat.
            let live_mtime_ns = file_mtime_ns(&path);
            if let (Some(idx), Some(mtime_ns)) = (merkle.as_ref(), live_mtime_ns) {
                if idx.metadata_unchanged(&path, mtime_ns, file_size) {
                    skipped.fetch_add(1, Ordering::Relaxed);
                    return vec![];
                }
            }

            if ext == "zip" || ext == "apk" || ext == "ipa" || ext == "crx" || ext == "jar" {
                // Per-entry uncompressed-size cap to defeat zip-bomb DoS.
                // openpack's central directory exposes uncompressed_size; skip
                // any entry that exceeds max_size (per-file cap) and the total
                // uncompressed budget.
                let mut archive_chunks = Vec::new();
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
                            total_uncompressed = total_uncompressed
                                .saturating_add(archive_entry.uncompressed_size);
                            if total_uncompressed > total_budget {
                                tracing::warn!(
                                    archive = %path.display(),
                                    "aborting archive extraction: total uncompressed size exceeds 4x file cap (zip-bomb guard)"
                                );
                                break;
                            }
                            if let Ok(content) = pack.read_entry(&archive_entry.name) {
                                if let Ok(s) = String::from_utf8(content.clone()) {
                                    archive_chunks.push(Ok(Chunk {
                                        data: s.into(),
                                        metadata: ChunkMetadata {
                                            source_type: "filesystem/archive".into(),
                                            path: Some(format!(
                                                "{}//{}",
                                                path.display(),
                                                archive_entry.name
                                            )),
                                            ..Default::default()
                                        },
                                    }));
                                } else {
                                    let strings =
                                        crate::strings::extract_printable_strings(&content, 8);
                                    if !strings.is_empty() {
                                        archive_chunks.push(Ok(Chunk {
                                            data: keyhog_core::SensitiveString::join(&strings, "\n"),
                                            metadata: ChunkMetadata {
                                                source_type: "filesystem/archive-binary".into(),
                                                path: Some(format!(
                                                    "{}//{}",
                                                    path.display(),
                                                    archive_entry.name
                                                )),
                                                ..Default::default()
                                            },
                                        }));
                                    }
                                }
                            }
                        }
                    }
                }
                return archive_chunks;
            } else if ext == "gz" || ext == "zst" || ext == "lz4" || ext == "sz" {
                return extract_compressed_chunks(&path, max_size);
            }

            let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if is_default_excluded(filename) {
                return vec![];
            }
            if filename.contains(".min.")
                || filename.contains(".bundle.")
                || filename.ends_with(".chunk.js")
            {
                return vec![];
            }

            if file_size > window_size as u64 {
                // Fast path: mmap once and slice zero-copy into
                // overlapping `window_size` views with `window_overlap`
                // shared bytes between neighbours. Replaces a 64 MiB
                // heap buffer + per-window `seek-back+re-read`
                // round-trip with a single mmap + madvise(SEQUENTIAL).
                if let Some(windows) =
                    read::read_file_windowed_mmap(&path, window_size, window_overlap)
                {
                    return windows
                        .into_iter()
                        .map(|w| {
                            Ok(Chunk {
                                data: w.text.into(),
                                metadata: ChunkMetadata {
                                    source_type: "filesystem/windowed".to_string(),
                                    path: Some(path.display().to_string()),
                                    base_offset: w.offset,
                                    mtime_ns: live_mtime_ns,
                                    size_bytes: Some(file_size),
                                    ..Default::default()
                                },
                            })
                        })
                        .collect();
                }
                // Buffered fallback: mmap refused (locked writer,
                // unsupported filesystem). Same semantics as before —
                // working buffer + seek-back overlap. Sized to the
                // configured window so test overrides apply here too.
                let mut window_chunks = Vec::new();
                if let Ok(mut file) = std::fs::File::open(&path) {
                    let mut current_offset = 0;
                    let mut buffer = vec![0u8; window_size];
                    while let Ok(n) = file.read(&mut buffer) {
                        if n == 0 { break; }
                        let data = String::from_utf8_lossy(&buffer[..n]).into_owned();
                        window_chunks.push(Ok(Chunk {
                            data: data.into(),
                            metadata: ChunkMetadata {
                                source_type: "filesystem/windowed".to_string(),
                                path: Some(path.display().to_string()),
                                base_offset: current_offset,
                                mtime_ns: live_mtime_ns,
                                size_bytes: Some(file_size),
                                ..Default::default()
                            },
                        }));
                        if n < window_size { break; }
                        let _ = file.seek(SeekFrom::Current(-(window_overlap as i64)));
                        current_offset += n - window_overlap;
                    }
                }
                return window_chunks;
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
                            return vec![];
                        }
                        (keyhog_core::SensitiveString::join(&strings, "\n"), "filesystem:binary-strings")
                    } else {
                        return vec![];
                    }
                }
            };

            vec![Ok(Chunk {
                data: content,
                metadata: ChunkMetadata {
                    source_type: source_type.to_string(),
                    path: Some(path.display().to_string()),
                    mtime_ns: live_mtime_ns,
                    size_bytes: Some(file_size),
                    ..Default::default()
                },
            })]
        }))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn extract_compressed_chunks(path: &Path, max_size: u64) -> Vec<Result<Chunk, SourceError>> {
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

    // mmap the compressed file when possible — ziftsieve only takes a
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
        None => return Vec::new(),
    };
    let bytes = file_bytes.as_slice();

    // Decompression-bomb cap: a 4x compression-ratio multiplier on the
    // per-file size budget bounds total expanded bytes. A 1 MB gzip bomb
    // expanding to 4 GB hits this ceiling and aborts cleanly instead of
    // OOMing. See audit release-2026-04-26 filesystem.rs:308-361.
    let total_budget: usize = max_size.saturating_mul(4) as usize;

    let mut chunks = Vec::new();

    if let Ok(blocks) = ziftsieve::extract_from_bytes(format, bytes) {
        let mut current_chunk_literals = String::new();
        let mut total_decompressed: usize = 0;
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
                chunks.push(Ok(Chunk {
                    data: std::mem::take(&mut current_chunk_literals).into(),
                    metadata: ChunkMetadata {
                        source_type: "filesystem/compressed".into(),
                        path: Some(path.display().to_string()),
                        ..Default::default()
                    },
                }));
            }
        }
        if !current_chunk_literals.is_empty() {
            chunks.push(Ok(Chunk {
                data: current_chunk_literals.into(),
                metadata: ChunkMetadata {
                    source_type: "filesystem/compressed".into(),
                    path: Some(path.display().to_string()),
                    ..Default::default()
                },
            }));
        }
    }
    chunks
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

    // Directory contents — segment-walk catches both separators.
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

    // Specific filename matches (the trailing component only —
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
/// modified time — in that case the cache fast-path simply doesn't fire,
/// which is strictly better than a false skip.
fn file_mtime_ns(path: &Path) -> Option<u64> {
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    let dur = modified
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
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

    WalkConfig::default()
        .max_file_size(max_file_size)
        .follow_symlinks(false)
        .respect_gitignore(true)
        .skip_hidden(false)
        .skip_binary(false)
        .exclude_extensions(exclude_extensions)
        .exclude_dirs(exclude_dirs)
        .ignore_files(vec![".keyhogignore".to_string()])
        .ignore_patterns(ignore_overrides)
}
