//! Source trait and chunk types: the abstraction for pluggable input backends.

// Debt bucket: 9 items predating the crate floor raising `missing_docs` to
// `warn`. Remove this allow once every Source-trait item is documented.
#![allow(missing_docs)]

use crate::SensitiveString;
use serde::Serialize;
use std::sync::Arc;
use thiserror::Error;

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
#[derive(Debug, Clone, Serialize)]
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
#[derive(Debug, Clone, Serialize, Default)]
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
        "failed to read source: {0}. Fix: adjust the source settings or input so KeyHog can read plain text safely"
    )]
    Other(String),
}
