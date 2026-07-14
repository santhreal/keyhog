//! Binary analysis source: extract secrets from compiled executables.
//!
//! Two-tier approach:
//! 1. **Ghidra mode** (when `analyzeHeadless` is on PATH): runs Ghidra's headless
//!    analyzer + decompiler, parses decompiled C output for string literals, data
//!    section dumps, and cross-references. Catches secrets embedded in optimized code.
//! 2. **Strings mode** (fallback): extracts printable ASCII runs ≥ 8 chars from raw
//!    bytes. Fast but shallow - misses encoded or split secrets.
//!
//! The Ghidra integration is a runtime dependency, not compile-time.
//! `cargo build -F binary` pulls in `goblin` for format detection; Ghidra is optional.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicUsize;

/// How many binaries had their requested Ghidra deep-decompiler analysis
/// degrade to shallow strings-only extraction (Ghidra failed, timed out, or
/// produced decompiled output too large to process). Each degradation is a
/// recall loss the operator chose against by enabling Ghidra, so it is both
/// printed loudly on stderr AND counted here for auditability (Law 10). Read
/// it via [`binary_degraded_to_strings`].
pub(crate) static GHIDRA_DEGRADED_TO_STRINGS: AtomicUsize = AtomicUsize::new(0);

/// How many binaries could not be read at all for strings extraction
/// (permission denied / I/O error) and were therefore dropped from the scan
/// entirely, an UNKNOWN, never a clean file (Law 10). Surfaced loudly +
/// counted at each drop site.
pub(crate) static BINARY_UNREADABLE: AtomicUsize = AtomicUsize::new(0);

/// Snapshot of the binary-source degradation counters for end-of-scan
/// reporting. Reset by the test harness via [`reset_binary_counters`].
pub fn binary_degraded_to_strings() -> usize {
    GHIDRA_DEGRADED_TO_STRINGS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Read the count of binaries dropped from the scan as unreadable.
pub fn binary_unreadable() -> usize {
    BINARY_UNREADABLE.load(std::sync::atomic::Ordering::Relaxed)
}

/// Reset both binary-source counters. Public so test fixtures baselining
/// between runs in one process clear them.
pub fn reset_binary_counters() {
    GHIDRA_DEGRADED_TO_STRINGS.store(0, std::sync::atomic::Ordering::Relaxed);
    BINARY_UNREADABLE.store(0, std::sync::atomic::Ordering::Relaxed);
}

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};

use analyzers::{
    BinaryAnalysisDegradation, BinaryAnalysisOutcome, BinaryAnalysisRequest, BinaryAnalyzer,
    GhidraAnalyzer,
};

/// Binary analysis source for executables and shared libraries.
///
/// # Examples
///
/// ```rust
/// use keyhog_core::Source;
/// use keyhog_sources::BinarySource;
///
/// let source = BinarySource::new("target/app");
/// assert_eq!(source.name(), "binary");
/// ```
pub struct BinarySource {
    path: PathBuf,
    ghidra_path: Option<PathBuf>,
    limits: crate::SourceLimits,
}

impl BinarySource {
    /// Create a binary source and auto-detect Ghidra when available.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::Source;
    /// use keyhog_sources::BinarySource;
    ///
    /// let source = BinarySource::new("target/app");
    /// assert_eq!(source.name(), "binary");
    /// ```
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let ghidra_path = analyzers::find_ghidra_headless();
        Self {
            path: path.into(),
            ghidra_path,
            limits: crate::SourceLimits::default(),
        }
    }

    /// Force strings-only mode (skip Ghidra even if available).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::Source;
    /// use keyhog_sources::BinarySource;
    ///
    /// let source = BinarySource::new("target/app");
    /// assert_eq!(source.name(), "binary");
    /// ```
    pub(crate) fn strings_only(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            ghidra_path: None,
            limits: crate::SourceLimits::default(),
        }
    }

    pub fn with_limits(mut self, limits: crate::SourceLimits) -> Self {
        self.limits = limits;
        self
    }

    fn analyzer_chunks(
        &self,
        analyzer: &dyn BinaryAnalyzer,
    ) -> Result<Vec<Result<Chunk, SourceError>>, SourceError> {
        let request = BinaryAnalysisRequest {
            path: &self.path,
            decompiled_bytes_limit: self.limits.binary_decompiled_bytes,
            timeout: crate::timeouts::GHIDRA_ANALYSIS,
        };
        match analyzer.analyze(request)? {
            BinaryAnalysisOutcome::Complete(chunks) => {
                let mut rows = chunks.into_iter().map(Ok).collect::<Vec<_>>();
                rows.extend(self.strings_chunks());
                Ok(rows)
            }
            BinaryAnalysisOutcome::Degraded(degradation) => {
                self.report_analysis_degradation(&degradation);
                GHIDRA_DEGRADED_TO_STRINGS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(self.strings_chunks())
            }
        }
    }

    fn report_analysis_degradation(&self, degradation: &BinaryAnalysisDegradation) {
        match degradation {
            BinaryAnalysisDegradation::ToolFailure {
                reason,
                stderr_excerpt,
            } => {
                let diagnostic = if stderr_excerpt.is_empty() {
                    String::new()
                } else {
                    format!("; ghidra stderr: {stderr_excerpt}")
                };
                eprintln!(
                    "keyhog: WARNING: Ghidra decompiler analysis failed for {} ({reason}{diagnostic}); \
                     falling back to shallow strings-only extraction, encoded/split secrets \
                     this binary may carry will NOT be recovered. Re-run after fixing Ghidra to \
                     restore deep analysis.",
                    self.path.display()
                );
            }
            BinaryAnalysisDegradation::OutputTooLarge {
                actual_bytes,
                limit_bytes,
            } => {
                eprintln!(
                    "keyhog: WARNING: Ghidra decompiled output for {} is {} bytes (> {} cap); \
                     falling back to shallow strings-only extraction, encoded/split secrets may \
                     be missed.",
                    self.path.display(),
                    actual_bytes,
                    limit_bytes
                );
            }
        }
    }

    fn strings_chunks(&self) -> Vec<Result<Chunk, SourceError>> {
        let path_display = crate::filesystem::display_path(&self.path);
        let mut chunks = Vec::new();
        let bytes = match read_binary_capped(&self.path, self.limits.binary_read_bytes) {
            Ok(read) => {
                if read.truncated {
                    chunks.push(Err(report_binary_truncation(
                        &path_display,
                        self.limits.binary_read_bytes,
                    )));
                }
                read.bytes
            }
            Err(error) => {
                // Law 10: an unreadable binary is an UNKNOWN dropped from the scan,
                // not a clean file. The old `tracing::debug!` made that drop
                // invisible at default verbosity. Surface it loudly + count it so
                // a "no secrets found" result is not mistaken for full coverage.
                eprintln!(
                    "keyhog: WARNING: cannot read binary {} ({error}); it was NOT scanned for secrets.",
                    self.path.display()
                );
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                BINARY_UNREADABLE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return vec![Err(SourceError::Other(format!(
                    "failed to scan binary {}: cannot read file ({error}); it was not scanned for secrets",
                    self.path.display()
                )))];
            }
        };

        // Try section-aware extraction using goblin (ELF/PE/Mach-O)
        #[cfg(feature = "binary")]
        {
            if let Some(section_chunks) = sections::extract_sections(&bytes, &path_display) {
                chunks.extend(section_chunks.into_iter().map(Ok));
            }
        }

        // Always do full strings extraction as fallback/supplement
        let strings = extract_printable_strings(&bytes, crate::strings::MIN_PRINTABLE_STRING_LEN);
        if !strings.is_empty() {
            chunks.push(Ok(Chunk {
                data: crate::strings::join_sensitive_strings(&strings, "\n"),
                metadata: ChunkMetadata {
                    base_offset: 0,
                    base_line: 0,
                    source_type: "binary:strings".into(),
                    path: Some(path_display.into()),
                    commit: None,
                    author: None,
                    date: None,
                    mtime_ns: None,
                    size_bytes: None,
                    decoded_span: None,
                },
            }));
        }

        if chunks.is_empty() {
            eprintln!(
                "keyhog: WARNING: binary {} yielded no scannable sections or printable strings; it was NOT scanned for secrets.",
                self.path.display()
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Binary);
            return vec![Err(SourceError::Other(format!(
                "failed to scan binary {}: yielded no scannable sections or printable strings, so no binary bytes were scanned for secrets",
                self.path.display()
            )))];
        }

        chunks
    }
}

fn report_binary_truncation(path_display: &str, cap: usize) -> SourceError {
    eprintln!(
        "keyhog: WARNING: binary {path_display} exceeded the {cap} byte strings-read cap; only the first {cap} bytes were scanned."
    );
    let _event = crate::record_skip_event(crate::SourceSkipEvent::SourceTruncated);
    SourceError::Other(format!(
        "binary {path_display} exceeded the {cap}-byte strings-read cap; remaining binary bytes were not scanned"
    ))
}

impl Source for BinarySource {
    fn name(&self) -> &str {
        "binary"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        // Hold the scan read lease across collection so a counter-asserting test's
        // exclusive scope serializes this source's skip recording (unresolved
        // section names, unreadable binaries). The collect is synchronous, so the
        // lease covers its whole recording window. A no-op in production where the
        // gate is never armed; see `skip::gate_scan`.
        crate::gate_scan(|| {
            let rows = if let Some(ghidra_bin) = &self.ghidra_path {
                let analyzer = GhidraAnalyzer::new(ghidra_bin);
                match self.analyzer_chunks(&analyzer) {
                    Ok(rows) => rows,
                    Err(e) => vec![Err(e)],
                }
            } else {
                self.strings_chunks()
            };

            Box::new(rows.into_iter())
        })
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Read at most `cap` bytes from `path` for strings extraction (OOM guard).
struct CappedBinaryRead {
    bytes: Vec<u8>,
    truncated: bool,
}

fn read_binary_capped(path: &Path, cap: usize) -> std::io::Result<CappedBinaryRead> {
    // Open through the crate's single safe-open boundary (O_NOFOLLOW + O_NONBLOCK
    // + post-open fd fstat + advisory shared lock), the same one every filesystem
    // content read uses. A raw `File::open` here would (a) BLOCK FOREVER on a FIFO
    // target (no O_NONBLOCK and no reader), (b) follow a symlinked binary path to
    // an off-target file, and (c) stream a character device (`/dev/zero`) until the
    // read cap. The binary source is constructed with an explicit path, but the
    // FIFO-hang and special-file reads are robustness bugs regardless of trust, and
    // one open boundary keeps every content read consistent (NO DUPLICATION).
    let file = crate::filesystem::open_file_safe(path)?;
    let capacity_hint = file.metadata()?.len();
    let cap = u64::try_from(cap).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "binary read cap is too large for this platform",
        )
    })?;
    let read = crate::capped_read::read_to_cap(file, cap, Some(capacity_hint))?;
    Ok(CappedBinaryRead {
        bytes: read.bytes,
        truncated: read.truncated,
    })
}

pub(crate) fn extract_printable_strings(
    bytes: &[u8],
    min_len: usize,
) -> Vec<keyhog_core::SensitiveString> {
    crate::strings::extract_printable_strings(bytes, min_len)
}

mod analyzers;
pub(crate) mod literals;
#[cfg(feature = "binary")]
pub(crate) mod sections;

#[cfg(test)]
mod tests;
