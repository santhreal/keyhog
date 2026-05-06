//! Binary analysis source: extract secrets from compiled executables.
//!
//! Two-tier approach:
//! 1. **Ghidra mode** (when `analyzeHeadless` is on PATH): runs Ghidra's headless
//!    analyzer + decompiler, parses decompiled C output for string literals, data
//!    section dumps, and cross-references. Catches secrets embedded in optimized code.
//! 2. **Strings mode** (fallback): extracts printable ASCII runs ≥ 8 chars from raw
//!    bytes. Fast but shallow — misses encoded or split secrets.
//!
//! The Ghidra integration is a runtime dependency, not compile-time.
//! `cargo build -F binary` pulls in `goblin` for format detection; Ghidra is optional.

use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::Command;

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use wait_timeout::ChildExt;

/// Minimum printable string length for strings-mode extraction.
pub(crate) const MIN_STRING_LEN: usize = 8;

/// Maximum decompiled output size we'll process (50 MB).
const MAX_DECOMPILED_SIZE: u64 = 50 * 1024 * 1024;

/// Binary analysis source for executables and shared libraries.
///
/// # Examples
///
/// ```rust
/// use keyhog_core::Source;
/// use keyhog_sources::BinarySource;
///
/// let source = BinarySource::strings_only("target/app");
/// assert_eq!(source.name(), "binary");
/// ```
pub struct BinarySource {
    path: PathBuf,
    ghidra_path: Option<PathBuf>,
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
        }
    }

    /// Explicitly set the Ghidra analyzeHeadless path.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::Source;
    /// use keyhog_sources::BinarySource;
    /// use std::path::PathBuf;
    ///
    /// let source = BinarySource::new("target/app").with_ghidra(PathBuf::from("/opt/ghidra/support/analyzeHeadless"));
    /// assert_eq!(source.name(), "binary");
    /// ```
    pub fn with_ghidra(mut self, ghidra_path: PathBuf) -> Self {
        self.ghidra_path = Some(ghidra_path);
        self
    }

    /// Force strings-only mode (skip Ghidra even if available).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::Source;
    /// use keyhog_sources::BinarySource;
    ///
    /// let source = BinarySource::strings_only("target/app");
    /// assert_eq!(source.name(), "binary");
    /// ```
    pub fn strings_only(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            ghidra_path: None,
        }
    }

    fn ghidra_chunks(&self, ghidra_bin: &Path) -> Result<Vec<Chunk>, SourceError> {
        let tmp_dir = tempfile::tempdir().map_err(SourceError::Io)?;
        let project_dir = tmp_dir.path().join("ghidra_project");
        std::fs::create_dir_all(&project_dir).map_err(SourceError::Io)?;

        let script_path = tmp_dir.path().join("ExportDecompiled.java");
        let output_path = tmp_dir.path().join("decompiled.c");
        ghidra::write_ghidra_script(&script_path, &output_path)?;

        let status = Command::new(ghidra_bin)
            .arg(&project_dir)
            .arg("keyhog_analysis")
            .arg("-import")
            .arg(&self.path)
            .arg("-postScript")
            .arg(&script_path)
            .arg("-deleteProject")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .and_then(|mut child| {
                let timeout = crate::timeouts::GHIDRA_ANALYSIS;
                match child.wait_timeout(timeout).map_err(std::io::Error::other)? {
                    Some(status) => Ok(status),
                    None => {
                        let _ = child.kill();
                        let _ = child.wait();
                        Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!("Ghidra analysis timed out after {}s", timeout.as_secs()),
                        ))
                    }
                }
            });

        match status {
            Ok(s) if s.success() && output_path.exists() => {
                self.parse_decompiled_output(&output_path)
            }
            Ok(_) | Err(_) => {
                tracing::debug!(
                    path = %self.path.display(),
                    "Ghidra analysis failed or produced no output, falling back to strings"
                );
                Ok(self.strings_chunks())
            }
        }
    }

    fn parse_decompiled_output(&self, output_path: &Path) -> Result<Vec<Chunk>, SourceError> {
        let metadata = std::fs::metadata(output_path).map_err(SourceError::Io)?;
        if metadata.len() > MAX_DECOMPILED_SIZE {
            tracing::warn!(
                path = %self.path.display(),
                size = metadata.len(),
                "Decompiled output too large, falling back to strings"
            );
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
                    source_type: "binary:ghidra:decompiled".to_string(),
                    path: Some(self.path.display().to_string()),
                    commit: None,
                    author: None,
                    date: None,
                },
            });
        }

        // Chunk 2: extracted string literals (higher signal, less noise)
        if !string_literals.is_empty() {
            chunks.push(Chunk {
                data: string_literals.join("\n").into(),
                metadata: ChunkMetadata {
                    base_offset: 0,
                    source_type: "binary:ghidra:strings".to_string(),
                    path: Some(self.path.display().to_string()),
                    commit: None,
                    author: None,
                    date: None,
                },
            });
        }

        // Also run basic strings extraction for anything Ghidra might miss
        let strings_chunk = self.strings_chunks();
        chunks.extend(strings_chunk);

        Ok(chunks)
    }

    fn strings_chunks(&self) -> Vec<Chunk> {
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(_) => return Vec::new(),
        };

        let mut chunks = Vec::new();
        let path_str = self.path.display().to_string();

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
                    source_type: "binary:strings".to_string(),
                    path: Some(path_str),
                    commit: None,
                    author: None,
                    date: None,
                },
            });
        }

        chunks
    }
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

pub(crate) fn extract_printable_strings(
    bytes: &[u8],
    min_len: usize,
) -> Vec<keyhog_core::SensitiveString> {
    crate::strings::extract_printable_strings(bytes, min_len)
}

mod ghidra;
mod literals;
#[cfg(feature = "binary")]
mod sections;
