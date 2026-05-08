//! Source trait and chunk types: the abstraction for pluggable input backends.

use crate::SensitiveString;
use serde::Serialize;
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
/// assert_eq!(metadata.source_type, "git-diff");
/// ```
#[derive(Debug, Clone, Serialize, Default)]
pub struct ChunkMetadata {
    pub source_type: String,
    pub path: Option<String>,
    pub commit: Option<String>,
    pub author: Option<String>,
    pub date: Option<String>,
    pub base_offset: usize,
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
