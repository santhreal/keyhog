use codewalk::WalkConfig;
use std::collections::HashSet;
use std::sync::OnceLock;

static SKIP_EXTENSIONS_SET: OnceLock<HashSet<&'static str>> = OnceLock::new();

pub(super) fn skip_extensions() -> &'static HashSet<&'static str> {
    SKIP_EXTENSIONS_SET.get_or_init(|| SKIP_EXTENSIONS.iter().copied().collect())
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
    // the dispatch in `extract::process_entry` for the actual decoder routing.
    "tgz",
    "bz2",
    "xz",
    "rar",
    "7z",
    // NOTE: the zip extension is deliberately NOT skipped here. The per-file
    // read gate below (`if skip_extensions().contains(ext) { return }`) runs
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

/// Check if a path matches the built-in default exclusion patterns.
/// Mirrors the patterns in `crates/cli/src/sources.rs`.
///
/// ASCII case-insensitive byte comparisons; splits on both `/` and
/// `\` so Windows paths get the same treatment as POSIX. The previous
/// flow built a fully-lowercased copy of the entire path and ran
/// POSIX-only `.contains("/x/")` checks, which (a) allocated per
/// file on the walker hot path and (b) silently failed to exclude
/// `\node_modules\`, `\vendor\`, etc. on Windows checkouts.
pub(super) fn is_default_excluded(path: &str) -> bool {
    let bytes = path.as_bytes();
    let ends_ci = |suffix: &[u8]| -> bool {
        bytes.len() >= suffix.len()
            && bytes[bytes.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
    };

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

    let tsc = b"tsconfig";
    let json = b".json";
    filename.len() >= tsc.len() + json.len()
        && filename[..tsc.len()].eq_ignore_ascii_case(tsc)
        && filename[filename.len() - json.len()..].eq_ignore_ascii_case(json)
}

pub(super) fn walker_config(max_file_size: u64, ignore_paths: &[String]) -> WalkConfig {
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
    // skip into `extract::process_entry` where we can warn + count it
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
