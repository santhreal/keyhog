//! Filesystem source: recursively walks a directory tree, skips binary files,
//! respects `.gitignore`, and yields chunks for scanning.

use codewalk::{CodeWalker, WalkConfig};
use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

mod read;

/// Minimum file size to use memory mapping. Above 1 MB the mmap overhead is
/// amortized; below it we use buffered reads.
const MMAP_THRESHOLD: u64 = 1024 * 1024;

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
        }
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
    "gz",
    "tgz",
    "bz2",
    "xz",
    "rar",
    "7z",
    "zip",
    "zst",
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
        let mut entries = match CodeWalker::new(&self.root, config).walk() {
            Ok(entries) => entries,
            Err(error) => {
                return Box::new(std::iter::once(Err(SourceError::Other(error.to_string()))));
            }
        };

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
                                        data: s,
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
                                            data: strings.join("\n"),
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

            if file_size > max_size {
                return vec![Err(SourceError::Other(format!(
                    "skipping {}: file size {} exceeds {} byte limit",
                    path.display(),
                    file_size,
                    max_size
                )))];
            }
            let file_text = if file_size >= MMAP_THRESHOLD {
                read::read_file_mmap(&path)
            } else {
                read::read_file_buffered(&path)
            };

            let (content, source_type) = match file_text {
                Some(text) if !text.is_empty() => (text, "filesystem"),
                _ => {
                    if let Ok(bytes) = read::read_file_safe(&path) {
                        let strings = crate::strings::extract_printable_strings(&bytes, 8);
                        if strings.is_empty() {
                            return vec![];
                        }
                        (strings.join("\n"), "filesystem:binary-strings")
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

    // Read the entire compressed file so that ziftsieve receives a complete
    // stream. Passing chunked buffers breaks stateful formats like gzip.
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => return vec![Err(SourceError::Io(e))],
    };

    // Decompression-bomb cap: a 4x compression-ratio multiplier on the
    // per-file size budget bounds total expanded bytes. A 1 MB gzip bomb
    // expanding to 4 GB hits this ceiling and aborts cleanly instead of
    // OOMing. See audit release-2026-04-26 filesystem.rs:308-361.
    let total_budget: usize = max_size.saturating_mul(4) as usize;

    let mut chunks = Vec::new();

    if let Ok(blocks) = ziftsieve::extract_from_bytes(format, &bytes) {
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
                    data: std::mem::take(&mut current_chunk_literals),
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
                data: current_chunk_literals,
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
fn is_default_excluded(path: &str) -> bool {
    let lower = path.to_lowercase();

    // File suffixes
    if lower.ends_with(".min.js")
        || lower.ends_with(".min.css")
        || lower.ends_with(".bak")
        || lower.ends_with(".swp")
        || lower.ends_with(".tmp")
        || lower.ends_with(".map")
        || lower.ends_with(".cache")
    {
        return true;
    }

    // Directory contents
    if lower.contains("/node_modules/")
        || lower.contains("/.git/")
        || lower.contains("/__pycache__/")
        || lower.contains("/vendor/")
        || lower.contains("/dist/")
        || lower.contains("/build/")
        || lower.contains("/out/")
    {
        return true;
    }

    // Specific filenames / patterns
    if lower.contains("/package-lock.json")
        || lower.ends_with("package-lock.json")
        || lower.ends_with("/yarn.lock")
        || lower == "yarn.lock"
        || lower.ends_with("/pnpm-lock.yaml")
        || lower == "pnpm-lock.yaml"
        || lower.ends_with("/cache.json")
        || lower == "cache.json"
        || lower.ends_with("/cargo.lock")
        || lower == "cargo.lock"
        || lower.ends_with("/go.sum")
        || lower == "go.sum"
        || lower.ends_with("/gemfile.lock")
        || lower == "gemfile.lock"
        || lower.ends_with("/angular.json")
        || lower == "angular.json"
    {
        return true;
    }

    // tsconfig*.json
    if let Some(filename) = lower.rsplit(['/', '\\']).next() {
        if filename.starts_with("tsconfig") && filename.ends_with(".json") {
            return true;
        }
    }

    false
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
