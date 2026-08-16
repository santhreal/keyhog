//! Source trait and chunk types: the abstraction for pluggable input backends.

// Debt bucket: 9 items predating the crate floor raising `missing_docs` to
// `warn`. Remove this allow once every Source-trait item is documented.
#![allow(missing_docs)]

use crate::SensitiveString;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, LazyLock};
use thiserror::Error;

/// Machine-readable reason a requested source surface was not fully scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceCoverageGapKind {
    /// The source denied access, did not exist, or returned an unreadable response.
    Inaccessible,
    /// A configured request, item, or byte limit stopped the scan early.
    Truncated,
}

impl std::fmt::Display for SourceCoverageGapKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Inaccessible => "inaccessible",
            Self::Truncated => "truncated",
        })
    }
}

/// A scannable chunk of text with metadata about where it came from.
///
/// # Examples
///
/// ```rust
/// use keyhog_core::{Chunk, ChunkMetadata};
///
/// let chunk = Chunk {
///     data: "API_KEY=sk_live_example".into(),
///     metadata: ChunkMetadata {
///         source_type: "filesystem".into(),
///         path: Some("app.env".into()),
///         ..Default::default()
///     },
/// };
///
/// assert_eq!(chunk.metadata.path.as_deref(), Some("app.env"));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chunk {
    /// UTF-8 text content to scan.
    pub data: SensitiveString,
    /// Provenance details used in findings and reporters.
    pub metadata: ChunkMetadata,
}

impl From<String> for Chunk {
    fn from(data: String) -> Self {
        Self {
            data: data.into(),
            metadata: ChunkMetadata::default(),
        }
    }
}

impl From<&str> for Chunk {
    fn from(data: &str) -> Self {
        Self::from(data.to_string())
    }
}

/// Metadata that tracks the source location for a scanned chunk.
///
/// # Examples
///
/// ```rust
/// use keyhog_core::ChunkMetadata;
///
/// let metadata = ChunkMetadata {
///     source_type: "git-diff".into(),
///     path: Some("src/lib.rs".into()),
///     commit: Some("abc123".into()),
///     author: Some("Dev".into()),
///     date: Some("2026-03-26T00:00:00Z".into()),
///     ..Default::default()
/// };
///
/// assert_eq!(&*metadata.source_type, "git-diff");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChunkMetadata {
    /// `Arc<str>` (not `String`) so cloning a chunk's metadata, done per decode
    /// sub-chunk, where every sub-chunk of a file shares the same `source_type`
    /// and `path`: is a refcount bump, not a fresh heap allocation + copy of
    /// each string. Mirrors the `Arc<str>` convention already used by
    /// `MatchLocation` in `finding.rs`; serialized through the same
    /// `serde_arc_str` helpers so no `serde` `rc` feature is needed.
    #[serde(with = "crate::finding::serde_arc_str")]
    pub source_type: Arc<str>,
    #[serde(with = "crate::finding::serde_arc_str_opt")]
    pub path: Option<Arc<str>>,
    #[serde(with = "crate::finding::serde_arc_str_opt")]
    pub commit: Option<Arc<str>>,
    #[serde(with = "crate::finding::serde_arc_str_opt")]
    pub author: Option<Arc<str>>,
    #[serde(with = "crate::finding::serde_arc_str_opt")]
    pub date: Option<Arc<str>>,
    pub base_offset: usize,
    /// Number of lines that precede `base_offset` in the original file -
    /// the line-number analog of `base_offset`. Zero for whole-file chunks
    /// (single-pass mmap, stdin, http, git diffs). Non-zero only when a
    /// source slices one file into multiple chunks (the filesystem
    /// `>window_size` windowed path), where each window after the first
    /// starts partway through the file. The scanner computes a match's
    /// line number *within the chunk text* and adds this base so the
    /// reported line is the absolute file line, not the per-window one -
    /// exactly mirroring how `base_offset` makes the byte offset absolute.
    /// Without it, a secret on line 584307 of a 70 MiB file was reported
    /// at the window-local line (e.g. line 2), making findings impossible
    /// to locate.
    #[serde(default)]
    pub base_line: usize,
    /// File mtime in nanoseconds since UNIX epoch, when the source can
    /// surface it cheaply (filesystem walks). Optional because non-fs
    /// sources (stdin, http, git diffs) don't have a meaningful mtime.
    /// Populated to drive the merkle-index metadata fast-path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtime_ns: Option<u64>,
    /// File size in bytes, when known cheaply at chunk-production time.
    /// Same shape and rationale as `mtime_ns`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    /// For DECODE sub-chunks only: the `[start, end)` byte range of the freshly
    /// decoded text within `data`. A decode sub-chunk is a small window of
    /// already-scanned parent context with the decoded blob spliced in at this
    /// span; everything OUTSIDE the span was scanned (and any finding deduped)
    /// when the parent chunk was scanned, so the self-contained passes only need
    /// to rescan a focus window around this span instead of the whole splice.
    /// `None` for all non-decode chunks (whole-file, windowed, git-diff, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoded_span: Option<(usize, usize)>,
}

impl ChunkMetadata {
    /// Create a metadata record for the given source type and path.
    ///
    /// The source type is interned against canonical source names.
    pub fn for_source(source_type: &str, path: Option<Arc<str>>) -> Self {
        Self {
            source_type: intern_source_type(source_type),
            path,
            ..Default::default()
        }
    }

    /// Set the source type using interning against canonical source names.
    pub fn with_source_type(mut self, source_type: &str) -> Self {
        self.source_type = intern_source_type(source_type);
        self
    }

    /// Update the source type in place using interning.
    pub fn set_source_type(&mut self, source_type: &str) {
        self.source_type = intern_source_type(source_type);
    }
}

/// Canonical `source_type` for standard filesystem file chunks.
pub static SOURCE_TYPE_FILESYSTEM: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("filesystem"));
/// Canonical `source_type` for windowed filesystem file chunks.
pub static SOURCE_TYPE_FILESYSTEM_WINDOWED: LazyLock<Arc<str>> =
    LazyLock::new(|| Arc::from("filesystem/windowed"));
/// Canonical `source_type` for filesystem binary printable-strings chunks.
pub static SOURCE_TYPE_FILESYSTEM_BINARY_STRINGS: LazyLock<Arc<str>> =
    LazyLock::new(|| Arc::from("filesystem:binary-strings"));
/// Canonical `source_type` for filesystem archive member chunks.
pub static SOURCE_TYPE_FILESYSTEM_ARCHIVE: LazyLock<Arc<str>> =
    LazyLock::new(|| Arc::from("filesystem/archive"));
/// Canonical `source_type` for filesystem PDF text chunks.
pub static SOURCE_TYPE_FILESYSTEM_PDF: LazyLock<Arc<str>> =
    LazyLock::new(|| Arc::from("filesystem/pdf"));
/// Canonical `source_type` for Git source chunks.
pub static SOURCE_TYPE_GIT: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("git"));
/// Canonical `source_type` for Git diff chunks.
pub static SOURCE_TYPE_GIT_DIFF: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("git-diff"));
/// Canonical `source_type` for Git history chunks.
pub static SOURCE_TYPE_GIT_HISTORY: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("git-history"));
/// Canonical `source_type` for Git staged chunks.
pub static SOURCE_TYPE_GIT_STAGED: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("git-staged"));
/// Canonical `source_type` for Git HEAD chunks.
pub static SOURCE_TYPE_GIT_HEAD: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("git/head"));
/// Canonical `source_type` for Git tag message chunks.
pub static SOURCE_TYPE_GIT_TAG: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("git/tag"));
/// Canonical `source_type` for Git unreachable object chunks.
pub static SOURCE_TYPE_GIT_UNREACHABLE: LazyLock<Arc<str>> =
    LazyLock::new(|| Arc::from("git/unreachable"));
/// Canonical `source_type` for Git history chunks with slash separator.
pub static SOURCE_TYPE_GIT_HISTORY_SLASH: LazyLock<Arc<str>> =
    LazyLock::new(|| Arc::from("git/history"));
/// Canonical `source_type` for Git diff chunks with slash separator.
pub static SOURCE_TYPE_GIT_DIFF_SLASH: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("git/diff"));
/// Canonical `source_type` for Git staged chunks with slash separator.
pub static SOURCE_TYPE_GIT_STAGED_SLASH: LazyLock<Arc<str>> =
    LazyLock::new(|| Arc::from("git/staged"));
/// Canonical `source_type` for stdin chunks.
pub static SOURCE_TYPE_STDIN: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("stdin"));
/// Canonical `source_type` for Docker container chunks.
pub static SOURCE_TYPE_DOCKER: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("docker"));
/// Canonical `source_type` for Amazon S3 object chunks.
pub static SOURCE_TYPE_S3: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("s3"));
/// Canonical `source_type` for Google Cloud Storage object chunks.
pub static SOURCE_TYPE_GCS: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("gcs"));
/// Canonical `source_type` for Azure Blob Storage object chunks.
pub static SOURCE_TYPE_AZURE_BLOB: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("azure_blob"));
/// Canonical `source_type` for web HTTP response chunks.
pub static SOURCE_TYPE_WEB: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("web"));
/// Canonical `source_type` for GitHub collaboration chunks.
pub static SOURCE_TYPE_GITHUB: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("github"));
/// Canonical `source_type` for Slack message chunks.
pub static SOURCE_TYPE_SLACK: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("slack"));
/// Canonical `source_type` for binary file chunks.
pub static SOURCE_TYPE_BINARY: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("binary"));
/// Canonical `source_type` for binary printable strings chunks.
pub static SOURCE_TYPE_BINARY_STRINGS: LazyLock<Arc<str>> =
    LazyLock::new(|| Arc::from("binary:strings"));

/// Pre-interned common source type names.
pub fn common_source_types() -> &'static [&'static str] {
    &[
        "filesystem",
        "filesystem/windowed",
        "filesystem:binary-strings",
        "filesystem/archive",
        "filesystem/pdf",
        "git",
        "git-diff",
        "git-history",
        "git-staged",
        "git/head",
        "git/history",
        "git/tag",
        "git/unreachable",
        "git/diff",
        "git/staged",
        "stdin",
        "s3",
        "docker",
        "gcs",
        "azure_blob",
        "web",
        "github",
        "slack",
        "binary",
        "binary:strings",
    ]
}

/// Intern a source type string reference into an `Arc<str>`.
///
/// Returns a clone of a pre-allocated static `Arc<str>` for canonical source types,
/// avoiding heap allocation and string duplication.
pub fn intern_source_type(source_type: &str) -> Arc<str> {
    match source_type {
        "filesystem" => Arc::clone(&SOURCE_TYPE_FILESYSTEM),
        "filesystem/windowed" => Arc::clone(&SOURCE_TYPE_FILESYSTEM_WINDOWED),
        "filesystem:binary-strings" => Arc::clone(&SOURCE_TYPE_FILESYSTEM_BINARY_STRINGS),
        "filesystem/archive" => Arc::clone(&SOURCE_TYPE_FILESYSTEM_ARCHIVE),
        "filesystem/pdf" => Arc::clone(&SOURCE_TYPE_FILESYSTEM_PDF),
        "git" => Arc::clone(&SOURCE_TYPE_GIT),
        "git-diff" => Arc::clone(&SOURCE_TYPE_GIT_DIFF),
        "git-history" => Arc::clone(&SOURCE_TYPE_GIT_HISTORY),
        "git-staged" => Arc::clone(&SOURCE_TYPE_GIT_STAGED),
        "git/head" => Arc::clone(&SOURCE_TYPE_GIT_HEAD),
        "git/history" => Arc::clone(&SOURCE_TYPE_GIT_HISTORY_SLASH),
        "git/tag" => Arc::clone(&SOURCE_TYPE_GIT_TAG),
        "git/unreachable" => Arc::clone(&SOURCE_TYPE_GIT_UNREACHABLE),
        "git/diff" => Arc::clone(&SOURCE_TYPE_GIT_DIFF_SLASH),
        "git/staged" => Arc::clone(&SOURCE_TYPE_GIT_STAGED_SLASH),
        "stdin" => Arc::clone(&SOURCE_TYPE_STDIN),
        "s3" => Arc::clone(&SOURCE_TYPE_S3),
        "docker" => Arc::clone(&SOURCE_TYPE_DOCKER),
        "gcs" => Arc::clone(&SOURCE_TYPE_GCS),
        "azure_blob" => Arc::clone(&SOURCE_TYPE_AZURE_BLOB),
        "web" => Arc::clone(&SOURCE_TYPE_WEB),
        "github" => Arc::clone(&SOURCE_TYPE_GITHUB),
        "slack" => Arc::clone(&SOURCE_TYPE_SLACK),
        "binary" => Arc::clone(&SOURCE_TYPE_BINARY),
        "binary:strings" => Arc::clone(&SOURCE_TYPE_BINARY_STRINGS),
        other => Arc::from(other),
    }
}

/// Pre-interned common file extension constants.
pub static EXT_RS: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("rs"));
pub static EXT_GO: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("go"));
pub static EXT_PY: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("py"));
pub static EXT_JS: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("js"));
pub static EXT_TS: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("ts"));
pub static EXT_JSX: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("jsx"));
pub static EXT_TSX: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("tsx"));
pub static EXT_C: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("c"));
pub static EXT_CPP: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("cpp"));
pub static EXT_H: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("h"));
pub static EXT_HPP: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("hpp"));
pub static EXT_JAVA: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("java"));
pub static EXT_KT: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("kt"));
pub static EXT_SCALA: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("scala"));
pub static EXT_RB: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("rb"));
pub static EXT_PHP: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("php"));
pub static EXT_CS: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("cs"));
pub static EXT_SWIFT: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("swift"));
pub static EXT_DART: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("dart"));
pub static EXT_LUA: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("lua"));
pub static EXT_R: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("r"));
pub static EXT_SH: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("sh"));
pub static EXT_BASH: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("bash"));
pub static EXT_ZSH: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("zsh"));
pub static EXT_PS1: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("ps1"));
pub static EXT_BAT: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("bat"));
pub static EXT_CMD: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("cmd"));
pub static EXT_JSON: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("json"));
pub static EXT_YAML: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("yaml"));
pub static EXT_YML: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("yml"));
pub static EXT_TOML: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("toml"));
pub static EXT_XML: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("xml"));
pub static EXT_HTML: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("html"));
pub static EXT_HTM: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("htm"));
pub static EXT_CSS: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("css"));
pub static EXT_SCSS: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("scss"));
pub static EXT_ENV: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("env"));
pub static EXT_INI: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("ini"));
pub static EXT_CONF: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("conf"));
pub static EXT_CFG: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("cfg"));
pub static EXT_PROPERTIES: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("properties"));
pub static EXT_TF: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("tf"));
pub static EXT_HCL: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("hcl"));
pub static EXT_PROTO: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("proto"));
pub static EXT_GRAPHQL: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("graphql"));
pub static EXT_SQL: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("sql"));
pub static EXT_MD: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("md"));
pub static EXT_TXT: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("txt"));
pub static EXT_CSV: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("csv"));
pub static EXT_LOG: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("log"));
pub static EXT_TAR: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("tar"));
pub static EXT_GZ: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("gz"));
pub static EXT_TGZ: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("tgz"));
pub static EXT_ZIP: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("zip"));
pub static EXT_JAR: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("jar"));
pub static EXT_WAR: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("war"));
pub static EXT_APK: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("apk"));
pub static EXT_IPA: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("ipa"));
pub static EXT_CRX: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("crx"));
pub static EXT_7Z: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("7z"));
pub static EXT_RAR: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("rar"));
pub static EXT_ZST: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("zst"));
pub static EXT_LZ4: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("lz4"));
pub static EXT_SZ: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("sz"));
pub static EXT_BZ2: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("bz2"));
pub static EXT_XZ: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("xz"));
pub static EXT_HAR: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("har"));
pub static EXT_PDF: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("pdf"));
pub static EXT_PNG: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("png"));
pub static EXT_JPG: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("jpg"));
pub static EXT_JPEG: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("jpeg"));
pub static EXT_GIF: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("gif"));
pub static EXT_WEBP: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("webp"));
pub static EXT_SVG: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("svg"));
pub static EXT_ICO: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("ico"));
pub static EXT_EXE: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("exe"));
pub static EXT_DLL: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("dll"));
pub static EXT_SO: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("so"));
pub static EXT_DYLIB: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("dylib"));
pub static EXT_BIN: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("bin"));
pub static EXT_WASM: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("wasm"));
pub static EXT_LOCK: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("lock"));
pub static EXT_SUM: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from("sum"));

/// Pre-interned common file extension names.
pub fn common_file_extensions() -> &'static [&'static str] {
    &[
        "rs",
        "go",
        "py",
        "js",
        "ts",
        "jsx",
        "tsx",
        "c",
        "cpp",
        "h",
        "hpp",
        "java",
        "kt",
        "scala",
        "rb",
        "php",
        "cs",
        "swift",
        "dart",
        "lua",
        "r",
        "sh",
        "bash",
        "zsh",
        "ps1",
        "bat",
        "cmd",
        "json",
        "yaml",
        "yml",
        "toml",
        "xml",
        "html",
        "htm",
        "css",
        "scss",
        "env",
        "ini",
        "conf",
        "cfg",
        "properties",
        "tf",
        "hcl",
        "proto",
        "graphql",
        "sql",
        "md",
        "txt",
        "csv",
        "log",
        "tar",
        "gz",
        "tgz",
        "zip",
        "jar",
        "war",
        "apk",
        "ipa",
        "crx",
        "7z",
        "rar",
        "zst",
        "lz4",
        "sz",
        "bz2",
        "xz",
        "har",
        "pdf",
        "png",
        "jpg",
        "jpeg",
        "gif",
        "webp",
        "svg",
        "ico",
        "exe",
        "dll",
        "so",
        "dylib",
        "bin",
        "wasm",
        "lock",
        "sum",
    ]
}

/// Intern a common file extension into an `Arc<str>`.
///
/// Returns a clone of a pre-allocated static `Arc<str>` for common extensions,
/// avoiding per-file allocation during directory traversal.
pub fn intern_file_extension(ext: &str) -> Arc<str> {
    match ext {
        "rs" => Arc::clone(&EXT_RS),
        "go" => Arc::clone(&EXT_GO),
        "py" => Arc::clone(&EXT_PY),
        "js" => Arc::clone(&EXT_JS),
        "ts" => Arc::clone(&EXT_TS),
        "jsx" => Arc::clone(&EXT_JSX),
        "tsx" => Arc::clone(&EXT_TSX),
        "c" => Arc::clone(&EXT_C),
        "cpp" => Arc::clone(&EXT_CPP),
        "h" => Arc::clone(&EXT_H),
        "hpp" => Arc::clone(&EXT_HPP),
        "java" => Arc::clone(&EXT_JAVA),
        "kt" => Arc::clone(&EXT_KT),
        "scala" => Arc::clone(&EXT_SCALA),
        "rb" => Arc::clone(&EXT_RB),
        "php" => Arc::clone(&EXT_PHP),
        "cs" => Arc::clone(&EXT_CS),
        "swift" => Arc::clone(&EXT_SWIFT),
        "dart" => Arc::clone(&EXT_DART),
        "lua" => Arc::clone(&EXT_LUA),
        "r" => Arc::clone(&EXT_R),
        "sh" => Arc::clone(&EXT_SH),
        "bash" => Arc::clone(&EXT_BASH),
        "zsh" => Arc::clone(&EXT_ZSH),
        "ps1" => Arc::clone(&EXT_PS1),
        "bat" => Arc::clone(&EXT_BAT),
        "cmd" => Arc::clone(&EXT_CMD),
        "json" => Arc::clone(&EXT_JSON),
        "yaml" => Arc::clone(&EXT_YAML),
        "yml" => Arc::clone(&EXT_YML),
        "toml" => Arc::clone(&EXT_TOML),
        "xml" => Arc::clone(&EXT_XML),
        "html" => Arc::clone(&EXT_HTML),
        "htm" => Arc::clone(&EXT_HTM),
        "css" => Arc::clone(&EXT_CSS),
        "scss" => Arc::clone(&EXT_SCSS),
        "env" => Arc::clone(&EXT_ENV),
        "ini" => Arc::clone(&EXT_INI),
        "conf" => Arc::clone(&EXT_CONF),
        "cfg" => Arc::clone(&EXT_CFG),
        "properties" => Arc::clone(&EXT_PROPERTIES),
        "tf" => Arc::clone(&EXT_TF),
        "hcl" => Arc::clone(&EXT_HCL),
        "proto" => Arc::clone(&EXT_PROTO),
        "graphql" => Arc::clone(&EXT_GRAPHQL),
        "sql" => Arc::clone(&EXT_SQL),
        "md" => Arc::clone(&EXT_MD),
        "txt" => Arc::clone(&EXT_TXT),
        "csv" => Arc::clone(&EXT_CSV),
        "log" => Arc::clone(&EXT_LOG),
        "tar" => Arc::clone(&EXT_TAR),
        "gz" => Arc::clone(&EXT_GZ),
        "tgz" => Arc::clone(&EXT_TGZ),
        "zip" => Arc::clone(&EXT_ZIP),
        "jar" => Arc::clone(&EXT_JAR),
        "war" => Arc::clone(&EXT_WAR),
        "apk" => Arc::clone(&EXT_APK),
        "ipa" => Arc::clone(&EXT_IPA),
        "crx" => Arc::clone(&EXT_CRX),
        "7z" => Arc::clone(&EXT_7Z),
        "rar" => Arc::clone(&EXT_RAR),
        "zst" => Arc::clone(&EXT_ZST),
        "lz4" => Arc::clone(&EXT_LZ4),
        "sz" => Arc::clone(&EXT_SZ),
        "bz2" => Arc::clone(&EXT_BZ2),
        "xz" => Arc::clone(&EXT_XZ),
        "har" => Arc::clone(&EXT_HAR),
        "pdf" => Arc::clone(&EXT_PDF),
        "png" => Arc::clone(&EXT_PNG),
        "jpg" => Arc::clone(&EXT_JPG),
        "jpeg" => Arc::clone(&EXT_JPEG),
        "gif" => Arc::clone(&EXT_GIF),
        "webp" => Arc::clone(&EXT_WEBP),
        "svg" => Arc::clone(&EXT_SVG),
        "ico" => Arc::clone(&EXT_ICO),
        "exe" => Arc::clone(&EXT_EXE),
        "dll" => Arc::clone(&EXT_DLL),
        "so" => Arc::clone(&EXT_SO),
        "dylib" => Arc::clone(&EXT_DYLIB),
        "bin" => Arc::clone(&EXT_BIN),
        "wasm" => Arc::clone(&EXT_WASM),
        "lock" => Arc::clone(&EXT_LOCK),
        "sum" => Arc::clone(&EXT_SUM),
        other => Arc::from(other),
    }
}

/// Alias for [`intern_file_extension`].
pub fn intern_extension(ext: &str) -> Arc<str> {
    intern_file_extension(ext)
}

/// Produces chunks of text for the scanner to process.
/// Each implementation handles a different input source.
///
/// # Examples
///
/// ```rust
/// use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
///
/// struct StaticSource;
///
/// impl Source for StaticSource {
///     fn name(&self) -> &str {
///         "static"
///     }
///
///     fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
///         Box::new(std::iter::once(Ok(Chunk {
///             data: "TOKEN=value".into(),
///             metadata: ChunkMetadata {
///                 source_type: "static".into(),
///                 ..Default::default()
///             },
///         })))
///     }
///
///     fn as_any(&self) -> &dyn std::any::Any {
///         self
///     }
/// }
///
/// let source = StaticSource;
/// assert_eq!(source.name(), "static");
/// ```
pub trait Source: Send + Sync {
    /// Human-readable source name used in warnings and telemetry.
    fn name(&self) -> &str;
    /// Yield all readable chunks from this source.
    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_>;
    /// Support downcasting to concrete types.
    fn as_any(&self) -> &dyn std::any::Any;

    /// Whether all chunks for one exact `(source_type, path)` identity are
    /// emitted contiguously. Dispatch may use this to split unrelated routing
    /// classes without cutting a future cross-chunk dependency.
    fn chunk_identities_are_contiguous(&self) -> bool {
        false
    }
}

/// Errors returned by input sources while enumerating or reading content.
///
/// # Examples
///
/// ```rust
/// use keyhog_core::SourceError;
///
/// let error = SourceError::Other("pass a readable file or directory".into());
/// assert!(error.to_string().contains("Fix"));
/// ```
#[derive(Debug, Error)]
pub enum SourceError {
    #[error(
        "failed to read source: {0}. Fix: check the path exists, is readable, and is not a broken symlink"
    )]
    Io(#[from] std::io::Error),
    #[error(
        "failed to access git source: {0}. Fix: run inside a valid git repository and verify the requested refs exist"
    )]
    Git(String),
    #[error(
        "source coverage gap ({kind}) in {adapter} surface {surface} at {target}: {detail}. Fix: grant read access or raise the relevant source limit, then rerun the affected surface"
    )]
    Coverage {
        /// Stable source adapter name.
        adapter: String,
        /// Independently selected surface that was incomplete.
        surface: String,
        /// Credential-free target identity.
        target: String,
        /// Typed coverage classification.
        kind: SourceCoverageGapKind,
        /// Response-free operator guidance.
        detail: String,
    },
    #[error("unknown source '{name}'. Fix: use a source name listed by `keyhog scan --help`")]
    UnknownSource {
        /// Unrecognized source identifier supplied by the caller.
        name: String,
    },
    #[error(
        "source '{source_name}' is unavailable because this KeyHog artifact was built without the '{feature}' feature. Fix: install an artifact that includes '{feature}' or choose an enabled source"
    )]
    FeatureUnavailable {
        /// Canonical source identifier.
        source_name: String,
        /// Cargo feature required to construct the source.
        feature: String,
    },
    #[error(
        "invalid configuration for source '{source_name}': {detail}. Fix: use the parameter format documented by `keyhog scan --help`"
    )]
    InvalidConfiguration {
        /// Canonical source identifier.
        source_name: String,
        /// Credential-free explanation of the invalid input shape.
        detail: String,
    },
    #[error(
        "source name '{name}' is no longer accepted; use '{replacement}'. Fix: update the source identifier and rerun the scan"
    )]
    DeprecatedSourceName {
        /// Retired source identifier.
        name: String,
        /// Canonical replacement identifier.
        replacement: String,
    },
    #[error(
        "failed to read source: {0}. Fix: adjust the source settings or input so KeyHog can read plain text safely"
    )]
    Other(String),
}
