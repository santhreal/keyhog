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

use std::io::BufRead;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
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
/// entirely — an UNKNOWN, never a clean file (Law 10). Surfaced loudly +
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
use wait_timeout::ChildExt;

/// Minimum printable string length for strings-mode extraction.
pub(crate) const MIN_STRING_LEN: usize = 8;
const GHIDRA_STDERR_EXCERPT_BYTES: usize = 4096;

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
        let ghidra_path = ghidra::find_ghidra_headless();
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

    fn ghidra_chunks(&self, ghidra_bin: &Path) -> Result<Vec<Chunk>, SourceError> {
        let tmp_dir = tempfile::tempdir().map_err(SourceError::Io)?;
        let project_dir = tmp_dir.path().join("ghidra_project");
        std::fs::create_dir_all(&project_dir).map_err(SourceError::Io)?;

        let script_path = tmp_dir.path().join("ExportDecompiled.java");
        let output_path = tmp_dir.path().join("decompiled.c");
        ghidra::write_ghidra_script(&script_path, &output_path)?;

        let mut child = Command::new(ghidra_bin)
            .arg(&project_dir)
            .arg("keyhog_analysis")
            .arg("-import")
            .arg(&self.path)
            .arg("-postScript")
            .arg(&script_path)
            .arg("-deleteProject")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(SourceError::Io)?;
        let stderr_capture = child.stderr.take().map(capture_ghidra_stderr_excerpt);
        let timeout = crate::timeouts::GHIDRA_ANALYSIS;
        let status = match child.wait_timeout(timeout) {
            Ok(Some(status)) => Ok(status),
            Ok(None) => {
                let _ = child.kill(); // LAW10: unused-binding marker; no runtime effect, not a fallback
                let _ = child.wait(); // LAW10: unused-binding marker; no runtime effect, not a fallback
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("Ghidra analysis timed out after {}s", timeout.as_secs()),
                ))
            }
            Err(error) => {
                let _ = child.kill(); // LAW10: unused-binding marker; no runtime effect, not a fallback
                let _ = child.wait(); // LAW10: unused-binding marker; no runtime effect, not a fallback
                Err(std::io::Error::other(format!(
                    "Ghidra process wait failed: {error}"
                )))
            }
        };
        let stderr_excerpt = match stderr_capture {
            Some(handle) => match handle.join() {
                Ok(excerpt) => excerpt,
                Err(panic) => {
                    drop(panic);
                    eprintln!(
                        "keyhog: WARNING: internal Ghidra stderr capture failed; \
                         deep-analysis failure reporting will use process status only."
                    );
                    String::new()
                }
            },
            None => String::new(), // LAW10: stderr was requested as piped; absent handle only removes extra diagnostics, while the status warning below still fires.
        };

        match status {
            Ok(s) if s.success() && output_path.exists() => {
                self.parse_decompiled_output(&output_path)
            }
            // Law 10: NOT silent — the operator explicitly enabled Ghidra (deep
            // decompiler analysis); a failure/timeout that silently degrades to
            // shallow strings-only would hide that the deeper analysis was skipped
            // (a recall loss the operator cannot see). Surface it LOUDLY on stderr
            // (the old `tracing::debug!` was invisible at default verbosity) AND
            // count it so the degradation is auditable.
            other => {
                let reason = match &other {
                    Ok(s) => format!("exited unsuccessfully (status {s}) or produced no output"),
                    Err(e) => e.to_string(),
                };
                let diagnostic = if stderr_excerpt.is_empty() {
                    String::new()
                } else {
                    format!("; ghidra stderr: {stderr_excerpt}")
                };
                eprintln!(
                    "keyhog: WARNING: Ghidra decompiler analysis failed for {} ({reason}{diagnostic}); \
                     falling back to shallow strings-only extraction — encoded/split secrets \
                     this binary may carry will NOT be recovered. Re-run after fixing Ghidra to \
                     restore deep analysis.",
                    self.path.display()
                );
                GHIDRA_DEGRADED_TO_STRINGS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(self.strings_chunks())
            }
        }
    }

    fn parse_decompiled_output(&self, output_path: &Path) -> Result<Vec<Chunk>, SourceError> {
        let metadata = std::fs::metadata(output_path).map_err(SourceError::Io)?;
        if metadata.len() > self.limits.binary_decompiled_bytes {
            // Law 10: loud, not silent — the deep-analysis output was discarded
            // (too large to process) and we fall back to shallow strings. Same
            // recall-loss surfacing + count as the Ghidra-failure arm.
            eprintln!(
                "keyhog: WARNING: Ghidra decompiled output for {} is {} bytes (> {} cap); \
                 falling back to shallow strings-only extraction — encoded/split secrets may \
                 be missed.",
                self.path.display(),
                metadata.len(),
                self.limits.binary_decompiled_bytes
            );
            GHIDRA_DEGRADED_TO_STRINGS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Ok(self.strings_chunks());
        }

        let file = std::fs::File::open(output_path).map_err(SourceError::Io)?;
        let reader = std::io::BufReader::new(file);

        let mut decompiled_text = String::new();
        let mut string_literals = Vec::new();

        for line in reader.lines() {
            let line = line.map_err(SourceError::Io)?;
            decompiled_text.push_str(&line);
            decompiled_text.push('\n');

            literals::extract_string_literals(&line, &mut string_literals);
        }

        let mut chunks = Vec::new();

        // Chunk 1: full decompiled output (for pattern matching on variable names, etc.)
        if !decompiled_text.is_empty() {
            chunks.push(Chunk {
                data: decompiled_text.into(),
                metadata: ChunkMetadata {
                    base_offset: 0,
                    base_line: 0,
                    source_type: "binary:ghidra:decompiled".to_string(),
                    path: Some(crate::filesystem::display_path(&self.path)),
                    commit: None,
                    author: None,
                    date: None,
                    mtime_ns: None,
                    size_bytes: None,
                    decoded_span: None,
                },
            });
        }

        // Chunk 2: extracted string literals (higher signal, less noise)
        if !string_literals.is_empty() {
            chunks.push(Chunk {
                data: string_literals.join("\n").into(),
                metadata: ChunkMetadata {
                    base_offset: 0,
                    base_line: 0,
                    source_type: "binary:ghidra:strings".to_string(),
                    path: Some(crate::filesystem::display_path(&self.path)),
                    commit: None,
                    author: None,
                    date: None,
                    mtime_ns: None,
                    size_bytes: None,
                    decoded_span: None,
                },
            });
        }

        // Also run basic strings extraction for anything Ghidra might miss
        let strings_chunk = self.strings_chunks();
        chunks.extend(strings_chunk);

        Ok(chunks)
    }

    fn strings_chunks(&self) -> Vec<Chunk> {
        let bytes = match read_binary_capped(&self.path, self.limits.binary_read_bytes) {
            Ok(read) => {
                if read.truncated {
                    eprintln!(
                        "keyhog: WARNING: binary {} exceeded the {} byte strings-read cap; \
                         only the first {} bytes were scanned.",
                        self.path.display(),
                        self.limits.binary_read_bytes,
                        self.limits.binary_read_bytes
                    );
                    let _event = crate::record_skip_event(crate::SourceSkipEvent::SourceTruncated);
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
                return Vec::new();
            }
        };

        let mut chunks = Vec::new();
        let path_str = crate::filesystem::display_path(&self.path);

        // Try section-aware extraction using goblin (ELF/PE/Mach-O)
        #[cfg(feature = "binary")]
        {
            if let Some(section_chunks) = sections::extract_sections(&bytes, &path_str) {
                chunks.extend(section_chunks);
            }
        }

        // Always do full strings extraction as fallback/supplement
        let strings = extract_printable_strings(&bytes, MIN_STRING_LEN);
        if !strings.is_empty() {
            chunks.push(Chunk {
                data: keyhog_core::SensitiveString::join(&strings, "\n"),
                metadata: ChunkMetadata {
                    base_offset: 0,
                    base_line: 0,
                    source_type: "binary:strings".to_string(),
                    path: Some(path_str),
                    commit: None,
                    author: None,
                    date: None,
                    mtime_ns: None,
                    size_bytes: None,
                    decoded_span: None,
                },
            });
        }

        chunks
    }
}

fn capture_ghidra_stderr_excerpt(
    mut stderr: std::process::ChildStderr,
) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut captured = Vec::with_capacity(GHIDRA_STDERR_EXCERPT_BYTES);
        let mut buffer = [0_u8; 1024];
        loop {
            match stderr.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    let remaining = GHIDRA_STDERR_EXCERPT_BYTES.saturating_sub(captured.len());
                    if remaining > 0 {
                        captured.extend_from_slice(&buffer[..n.min(remaining)]);
                    }
                }
                Err(error) => {
                    let suffix = format!(" [stderr capture read failed: {error}]");
                    let remaining = GHIDRA_STDERR_EXCERPT_BYTES.saturating_sub(captured.len());
                    if remaining > 0 {
                        let bytes = suffix.as_bytes();
                        captured.extend_from_slice(&bytes[..bytes.len().min(remaining)]);
                    }
                    break;
                }
            }
        }
        sanitize_ghidra_stderr_excerpt(&captured)
    })
}

fn sanitize_ghidra_stderr_excerpt(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut out = String::new();
    let mut pending_space = false;
    for ch in text.chars() {
        if ch.is_whitespace() {
            pending_space = !out.is_empty();
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        if ch.is_control() {
            continue;
        }
        out.push(ch);
    }
    out
}

impl Source for BinarySource {
    fn name(&self) -> &str {
        "binary"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        let result = if let Some(ghidra_bin) = &self.ghidra_path {
            self.ghidra_chunks(ghidra_bin)
        } else {
            Ok(self.strings_chunks())
        };

        match result {
            Ok(chunks) => Box::new(chunks.into_iter().map(Ok)),
            Err(e) => Box::new(std::iter::once(Err(e))),
        }
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
    let file = std::fs::File::open(path)?;
    let mut limited = file.take(cap as u64 + 1);
    let mut bytes = Vec::new();
    limited.read_to_end(&mut bytes)?;
    let truncated = bytes.len() > cap;
    if truncated {
        bytes.truncate(cap);
    }
    Ok(CappedBinaryRead { bytes, truncated })
}

pub(crate) fn extract_printable_strings(
    bytes: &[u8],
    min_len: usize,
) -> Vec<keyhog_core::SensitiveString> {
    crate::strings::extract_printable_strings(bytes, min_len)
}

mod ghidra;
pub(crate) mod literals;
#[cfg(feature = "binary")]
pub(crate) mod sections;
