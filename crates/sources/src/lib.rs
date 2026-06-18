//! Pluggable input sources for KeyHog.
//!
//! Each source implements the [`keyhog_core::Source`] trait and yields [`keyhog_core::Chunk`]
//! values for the scanner. Sources are gated behind cargo features so only the
//! transitive dependencies you actually need are compiled.

#![allow(clippy::too_many_arguments)]

pub mod api;
mod limits;
pub(crate) mod timeouts;

use std::sync::atomic::AtomicUsize;

/// How many files the filesystem walker skipped because they exceeded
/// the active `--max-file-size` cap. Bumped once per skipped entry
/// inside `FilesystemSource::process_entry`; the orchestrator reads
/// it at end-of-scan to emit a single summary line so users see what
/// the previously-silent walker filter dropped (kimi-1 dogfood #130).
/// Counter is process-global; reset between scans by the test harness
/// via `reset_skipped_over_max_size()`.
pub(crate) static SKIPPED_OVER_MAX_SIZE: AtomicUsize = AtomicUsize::new(0);

/// How many files the filesystem walker skipped because their extension (or a
/// content-sniffed magic header / NUL byte) marked them binary, before any
/// content scan. Previously a silent `return` (Law 10): a `.bin`/`.dat`/no-ext
/// file that is actually a planted-credential blob vanished with no trace. Bumped
/// at each binary skip site in `process_entry`; surfaced at end-of-scan.
pub(crate) static SKIPPED_BINARY: AtomicUsize = AtomicUsize::new(0);

/// How many files were skipped by the default-exclusion filter (lock files,
/// minified/bundled JS, vendored trees). Also previously a silent `return`.
pub(crate) static SKIPPED_EXCLUDED: AtomicUsize = AtomicUsize::new(0);

/// How many files the walker could not read (permission denied / I/O error) and
/// therefore did NOT scan. This is the most important to surface: an unreadable
/// file is an UNKNOWN, not a clean file — silently dropping it is a false-clean
/// (Law 10). Bumped on the walk's error path.
pub(crate) static SKIPPED_UNREADABLE: AtomicUsize = AtomicUsize::new(0);

/// How many archives (zip/apk/jar/tar/.gz/.tgz/...) had their extraction
/// TRUNCATED by a decompression-bomb guard — the per-archive 4x-of-`--max-file-size`
/// uncompressed budget was exceeded, so the remaining entries were NOT scanned.
/// A truncated archive is partial coverage, not a clean archive: silently
/// dropping the unscanned tail is a false-clean (Law 10). Bumped once per
/// archive that hit a bomb guard; surfaced at end-of-scan alongside the other
/// skip categories.
pub(crate) static SKIPPED_ARCHIVE_TRUNCATED: AtomicUsize = AtomicUsize::new(0);

/// How many binary (ELF/PE/Mach-O) sections were SKIPPED because their name
/// could not be resolved from the object's section-name string table — a
/// corrupt/truncated strtab in a malformed binary. The previous code substituted
/// an empty name (`unwrap_or("")`) and then silently dropped the section because
/// `""` is never in the high-value target list: a `.rodata`/`.data` section whose
/// name lookup failed vanished from the scan with no trace (Law 10 false-clean —
/// embedded secrets in that section were never scanned). Bumped once per section
/// whose name lookup fails; surfaced so the operator knows the binary parse was
/// partial. Reset via `reset_skip_counters`.
pub(crate) static BINARY_SECTION_NAME_UNRESOLVED: AtomicUsize = AtomicUsize::new(0);

/// How many source scans stopped before exhausting their input because a
/// source-level aggregate cap fired. This is distinct from per-file
/// over-max-size skips: e.g. Git history may stop after the aggregate
/// byte/chunk ceiling even though every individual blob was below its own cap.
pub(crate) static SOURCE_TRUNCATED: AtomicUsize = AtomicUsize::new(0);

/// How many structured source files matched a format-specific source expander
/// but failed to parse, so only the raw text fallback was scanned. This is
/// partial coverage, not a whole-file skip: e.g. a malformed HAR still gets
/// scanned as text, but request/response/body expansion is missing.
pub(crate) static STRUCTURED_SOURCE_PARSE_FAILURES: AtomicUsize = AtomicUsize::new(0);

/// Immutable snapshot of the skip counters, read once at end-of-scan so every
/// reporter (human summary + structured JSON/SARIF) surfaces the same numbers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SkipCounts {
    pub over_max_size: usize,
    pub binary: usize,
    pub excluded: usize,
    pub unreadable: usize,
    /// Archives truncated by a decompression-bomb guard (partial coverage).
    pub archive_truncated: usize,
    /// Binary sections dropped because their name could not be resolved from a
    /// corrupt section-name string table (partial binary parse).
    pub binary_section_name_unresolved: usize,
    /// Source scans stopped early by a source-level aggregate cap.
    pub source_truncated: usize,
    /// Structured source files whose format-specific parser failed; raw text was
    /// still scanned, but derived chunks/decoded bodies were not expanded.
    pub structured_source_parse_failures: usize,
}

impl SkipCounts {
    /// Total files skipped (not scanned) across all categories.
    ///
    /// `binary_section_name_unresolved`, `source_truncated`, and
    /// `structured_source_parse_failures` are partial-coverage signals, not
    /// whole-file skips, so they are surfaced separately and are NOT added into
    /// this file-skip total.
    pub fn total(&self) -> usize {
        self.over_max_size + self.binary + self.excluded + self.unreadable + self.archive_truncated
    }
}

/// Typed source coverage gap recorded when input bytes are deliberately not
/// scanned or only partially scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceSkipEvent {
    OverMaxSize,
    Binary,
    Excluded,
    Unreadable,
    ArchiveTruncated,
    #[cfg(feature = "binary")]
    BinarySectionNameUnresolved,
    SourceTruncated,
    StructuredSourceParseFailure,
}

impl SourceSkipEvent {
    fn counter(self) -> &'static AtomicUsize {
        match self {
            Self::OverMaxSize => &SKIPPED_OVER_MAX_SIZE,
            Self::Binary => &SKIPPED_BINARY,
            Self::Excluded => &SKIPPED_EXCLUDED,
            Self::Unreadable => &SKIPPED_UNREADABLE,
            Self::ArchiveTruncated => &SKIPPED_ARCHIVE_TRUNCATED,
            #[cfg(feature = "binary")]
            Self::BinarySectionNameUnresolved => &BINARY_SECTION_NAME_UNRESOLVED,
            Self::SourceTruncated => &SOURCE_TRUNCATED,
            Self::StructuredSourceParseFailure => &STRUCTURED_SOURCE_PARSE_FAILURES,
        }
    }
}

/// Receipt proving a source skip event passed through the typed recorder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "source skip events must be recorded through the typed recorder so coverage gaps remain surfaced"]
pub(crate) struct RecordedSkipEvent {
    event: SourceSkipEvent,
    previous: usize,
    delta: usize,
}

pub(crate) fn record_skip_event(event: SourceSkipEvent) -> RecordedSkipEvent {
    record_skip_events(event, 1)
}

pub(crate) fn record_skip_events(event: SourceSkipEvent, delta: usize) -> RecordedSkipEvent {
    use std::sync::atomic::Ordering::Relaxed;

    let previous = event.counter().fetch_add(delta, Relaxed);
    RecordedSkipEvent {
        event,
        previous,
        delta,
    }
}

/// Decode a file's raw bytes into scannable text using the EXACT logic the
/// filesystem walker uses: UTF-8 fast path, UTF-16 BOM dispatch, lossy recovery
/// for partially-corrupt text (so a config with one stray non-UTF-8 byte still
/// yields its secrets), and binary rejection. Returns `None` when the bytes are
/// binary (genuinely no text to scan).
///
/// Exposed so non-walker entry points decode IDENTICALLY to `keyhog scan`. The
/// `keyhog watch` daemon previously used `std::fs::read_to_string`, which fails
/// on the first non-UTF-8 byte and silently dropped the whole file — a recall
/// divergence between `watch` and `scan` invisible to the operator (Law 10).
/// Routing both through this one function makes their text extraction the same.
pub fn decode_file_bytes(bytes: &[u8]) -> Option<String> {
    filesystem::decode_text_file(bytes)
}

/// Read the current skip counters into a snapshot.
pub fn skip_counts() -> SkipCounts {
    use std::sync::atomic::Ordering::Relaxed;
    SkipCounts {
        over_max_size: SKIPPED_OVER_MAX_SIZE.load(Relaxed),
        binary: SKIPPED_BINARY.load(Relaxed),
        excluded: SKIPPED_EXCLUDED.load(Relaxed),
        unreadable: SKIPPED_UNREADABLE.load(Relaxed),
        archive_truncated: SKIPPED_ARCHIVE_TRUNCATED.load(Relaxed),
        binary_section_name_unresolved: BINARY_SECTION_NAME_UNRESOLVED.load(Relaxed),
        source_truncated: SOURCE_TRUNCATED.load(Relaxed),
        structured_source_parse_failures: STRUCTURED_SOURCE_PARSE_FAILURES.load(Relaxed),
    }
}

/// Reset every skip counter. Public so test fixtures and the orchestrator can
/// baseline between scans in one process.
pub(crate) fn reset_skip_counters() {
    use std::sync::atomic::Ordering::Relaxed;
    SKIPPED_OVER_MAX_SIZE.store(0, Relaxed);
    SKIPPED_BINARY.store(0, Relaxed);
    SKIPPED_EXCLUDED.store(0, Relaxed);
    SKIPPED_UNREADABLE.store(0, Relaxed);
    SKIPPED_ARCHIVE_TRUNCATED.store(0, Relaxed);
    BINARY_SECTION_NAME_UNRESOLVED.store(0, Relaxed);
    SOURCE_TRUNCATED.store(0, Relaxed);
    STRUCTURED_SOURCE_PARSE_FAILURES.store(0, Relaxed);
}

/// Reset the over-max-size counter. Retained for API compatibility (Law 3);
/// resets every skip counter so a fixture baselining between runs clears them
/// all, not just the size counter.
pub fn reset_skipped_over_max_size() {
    reset_skip_counters();
}

/// Local HTTP compatibility shim backed by reqwest. Only present when
/// at least one feature that pulls in `reqwest` is enabled -
/// otherwise this module would `pub use reqwest::*` against a crate
/// that wasn't compiled in, which fails resolution on stable rustc
/// (especially on Windows where `--no-default-features` is the
/// release profile we ship for the no-Hyperscan build).
#[cfg(any(
    feature = "azure",
    feature = "web",
    feature = "github",
    feature = "gitlab",
    feature = "bitbucket",
    feature = "slack",
    feature = "s3",
    feature = "gcs"
))]
pub mod reqwest {
    pub use reqwest::*;
}

/// Shared HTTP-client policy (proxy, TLS, UA) used by every source
/// + verifier site that talks to the network. Always compiled - the
/// `HttpClientConfig` type is the thread-through even when the
/// reqwest-backed builders are feature-gated out - so the CLI can
/// construct one without caring about which feature set is active.
pub mod http;

#[cfg(feature = "binary")]
mod binary;
#[cfg(feature = "bitbucket")]
mod bitbucket_workspace;
#[cfg(any(feature = "azure", feature = "s3", feature = "gcs"))]
mod cloud;
#[cfg(feature = "docker")]
mod docker;
mod filesystem;
#[cfg(feature = "gcs")]
mod gcs;
#[cfg(feature = "git")]
mod git;
#[cfg(feature = "github")]
mod github_org;
#[cfg(feature = "gitlab")]
mod gitlab_group;
mod har;
#[cfg(any(feature = "github", feature = "gitlab", feature = "bitbucket"))]
mod hosted_git;
#[cfg(feature = "s3")]
pub mod s3;
#[cfg(feature = "slack")]
mod slack;
mod stdin;
pub mod strings;
#[cfg(feature = "web")]
mod web;

pub use api::*;
pub use limits::{SourceLimits, DEFAULT_SOURCE_LIMITS};

/// Create a source instance from a name and optional parameters.
/// This allows the CLI to remain agnostic of specific source implementations.
pub fn create_source(
    name: &str,
    params: Option<&str>,
) -> Result<Box<dyn keyhog_core::Source>, keyhog_core::SourceError> {
    create_source_with_http_config(name, params, crate::http::HttpClientConfig::default())
}

/// Create a source while applying the shared outbound HTTP policy to
/// network-backed source implementations.
pub fn create_source_with_http_config(
    name: &str,
    params: Option<&str>,
    _http: crate::http::HttpClientConfig,
) -> Result<Box<dyn keyhog_core::Source>, keyhog_core::SourceError> {
    create_source_with_http_config_and_limits(name, params, _http, crate::SourceLimits::default())
}

/// Create a source while applying shared HTTP policy and source byte/count
/// limits to network/container implementations.
pub fn create_source_with_http_config_and_limits(
    name: &str,
    params: Option<&str>,
    _http: crate::http::HttpClientConfig,
    limits: crate::SourceLimits,
) -> Result<Box<dyn keyhog_core::Source>, keyhog_core::SourceError> {
    match name {
        "slack" => {
            if let Some(token) = params {
                #[cfg(feature = "slack")]
                return Ok(Box::new(SlackSource::new(token).with_http_config(_http)));
                #[cfg(not(feature = "slack"))]
                {
                    let _ = token; // LAW10: unused-binding marker; no runtime effect, not a fallback
                    return Err(keyhog_core::SourceError::Other(
                        "slack feature not enabled".into(),
                    ));
                }
            }
            Err(keyhog_core::SourceError::Other(
                "slack source requires a token: slack:TOKEN".into(),
            ))
        }
        "docker" => {
            if let Some(image) = params {
                #[cfg(feature = "docker")]
                return Ok(Box::new(DockerImageSource::new(image).with_limits(limits)));
                #[cfg(not(feature = "docker"))]
                {
                    let _ = image; // LAW10: unused-binding marker; no runtime effect, not a fallback
                    return Err(keyhog_core::SourceError::Other(
                        "docker feature not enabled".into(),
                    ));
                }
            }
            Err(keyhog_core::SourceError::Other(
                "docker source requires an image name: docker:IMAGE".into(),
            ))
        }
        "s3" => {
            if let Some(bucket) = params {
                #[cfg(feature = "s3")]
                return Ok(Box::new(
                    S3Source::new(bucket)
                        .with_http_config(_http)
                        .with_limits(limits),
                ));
                #[cfg(not(feature = "s3"))]
                {
                    let _ = bucket; // LAW10: unused-binding marker; no runtime effect, not a fallback
                    return Err(keyhog_core::SourceError::Other(
                        "s3 feature not enabled".into(),
                    ));
                }
            }
            Err(keyhog_core::SourceError::Other(
                "s3 source requires a bucket name: s3:BUCKET".into(),
            ))
        }
        "gcs" => {
            if let Some(bucket) = params {
                #[cfg(feature = "gcs")]
                return Ok(Box::new(
                    GcsSource::new(bucket)
                        .with_http_config(_http)
                        .with_limits(limits),
                ));
                #[cfg(not(feature = "gcs"))]
                {
                    let _ = bucket; // LAW10: unused-binding marker; no runtime effect, not a fallback
                    return Err(keyhog_core::SourceError::Other(
                        "gcs feature not enabled".into(),
                    ));
                }
            }
            Err(keyhog_core::SourceError::Other(
                "gcs source requires a bucket name: gcs:BUCKET".into(),
            ))
        }
        "azure_blob" => {
            if let Some(container_url) = params {
                #[cfg(feature = "azure")]
                return Ok(Box::new(
                    AzureBlobSource::new(container_url)
                        .with_http_config(_http)
                        .with_limits(limits),
                ));
                #[cfg(not(feature = "azure"))]
                {
                    let _ = container_url; // LAW10: unused-binding marker; no runtime effect, not a fallback
                    return Err(keyhog_core::SourceError::Other(
                        "azure feature not enabled".into(),
                    ));
                }
            }
            Err(keyhog_core::SourceError::Other(
                "azure_blob source requires a container URL: azure_blob:URL".into(),
            ))
        }
        "gitlab-group" | "gitlab_group" => {
            if let Some(params) = params {
                #[cfg(feature = "gitlab")]
                return Ok(Box::new(crate::gitlab_group::source_from_params(
                    params, _http,
                )?));
                #[cfg(not(feature = "gitlab"))]
                {
                    let _ = params; // LAW10: unused-binding marker; feature-disabled path returns a loud source error
                    return Err(keyhog_core::SourceError::Other(
                        "gitlab feature not enabled".into(),
                    ));
                }
            }
            Err(keyhog_core::SourceError::Other(
                "gitlab-group source requires GROUP, TOKEN, and optional ENDPOINT parameters"
                    .into(),
            ))
        }
        "bitbucket-workspace" | "bitbucket_workspace" => {
            if let Some(params) = params {
                #[cfg(feature = "bitbucket")]
                return Ok(Box::new(crate::bitbucket_workspace::source_from_params(
                    params, _http,
                )?));
                #[cfg(not(feature = "bitbucket"))]
                {
                    let _ = params; // LAW10: unused-binding marker; feature-disabled path returns a loud source error
                    return Err(keyhog_core::SourceError::Other(
                        "bitbucket feature not enabled".into(),
                    ));
                }
            }
            Err(keyhog_core::SourceError::Other(
                "bitbucket-workspace source requires WORKSPACE, USERNAME, APP_PASSWORD, and optional ENDPOINT parameters".into(),
            ))
        }
        _ => Err(keyhog_core::SourceError::Other(format!(
            "unknown source plugin: {}",
            name
        ))),
    }
}

/// Register built-in source plugins.
///
/// Built-ins are created by [`create_source_with_http_config_and_limits`] from
/// explicit CLI/TOML source specs. This function intentionally has no ambient
/// env side effects: source targets and credentials must not appear from
/// `SLACK_TOKEN`, `S3_BUCKET`, `GCS_BUCKET`, or `AZURE_BLOB_CONTAINER_URL`.
/// The function stays as a compatibility hook for callers that used to invoke
/// it during startup.
pub fn register_plugins() {
}

#[doc(hidden)]
pub mod testing {
    pub use crate::testing_facade::testing::*;
}

mod testing_facade;
