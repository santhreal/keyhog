//! Standard input source: reads piped input as a single chunk for scanning.

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use std::io::Read;

/// Reads all of stdin as a single chunk.
///
/// # Examples
///
/// ```rust
/// use keyhog_sources::StdinSource;
/// use keyhog_core::Source;
///
/// let source = StdinSource;
/// assert_eq!(source.name(), "stdin");
/// ```
pub struct StdinSource;

/// Stdin source with caller-resolved source limits.
pub struct ConfiguredStdinSource {
    limits: crate::SourceLimits,
}

/// An already acquired stdin payload with the same decoding, limits, chunk
/// metadata, and source identity as [`StdinSource`].
///
/// This is useful for long-lived processes and calibration harnesses that own
/// the input bytes before source construction. It avoids mutating process
/// stdin or recreating its metadata contract in another crate.
pub struct BufferedStdinSource {
    bytes: std::sync::Arc<[u8]>,
    limits: crate::SourceLimits,
}

impl StdinSource {
    pub fn with_limits(self, limits: crate::SourceLimits) -> ConfiguredStdinSource {
        ConfiguredStdinSource { limits }
    }
}

impl BufferedStdinSource {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into().into(),
            limits: crate::SourceLimits::default(),
        }
    }

    #[must_use]
    pub fn with_limits(mut self, limits: crate::SourceLimits) -> Self {
        self.limits = limits;
        self
    }
}

impl Source for StdinSource {
    fn name(&self) -> &str {
        "stdin"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        chunks_with_limit(crate::SourceLimits::default().stdin_bytes)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl Source for ConfiguredStdinSource {
    fn name(&self) -> &str {
        "stdin"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        chunks_with_limit(self.limits.stdin_bytes)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl Source for BufferedStdinSource {
    fn name(&self) -> &str {
        "stdin"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        crate::gate_scan(|| {
            let mut reader = std::io::Cursor::new(self.bytes.as_ref());
            one_stdin_chunk(read_to_string_limited(&mut reader, self.limits.stdin_bytes))
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn chunks_with_limit(max_bytes: usize) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>>> {
    crate::gate_scan(|| one_stdin_chunk(read_stdin_limited(max_bytes)))
}

fn one_stdin_chunk(
    result: std::io::Result<String>,
) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>>> {
    Box::new(std::iter::once(match result {
        Ok(data) => Ok(Chunk {
            data: data.into(),
            metadata: ChunkMetadata {
                base_offset: 0,
                base_line: 0,
                source_type: "stdin".into(),
                path: None,
                commit: None,
                author: None,
                date: None,
                mtime_ns: None,
                size_bytes: None,
                decoded_span: None,
            },
        }),
        Err(error) => Err(SourceError::Io(error)),
    }))
}

fn read_stdin_limited(max_bytes: usize) -> std::io::Result<String> {
    read_to_string_limited(&mut std::io::stdin().lock(), max_bytes)
}

pub(crate) fn read_to_string_limited(
    reader: &mut impl Read,
    max_bytes: usize,
) -> std::io::Result<String> {
    let cap = u64::try_from(max_bytes).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "stdin cap is too large for this platform",
        )
    })?;
    // Read at most `max_bytes + 1` so oversized stdin is rejected before we
    // hand a giant buffer to the scanner.
    let read = crate::capped_read::read_to_cap(reader, cap, None)?;

    if read.truncated {
        let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
        return Err(std::io::Error::other(format!(
            "stdin exceeds {} byte limit",
            max_bytes
        )));
    }

    // Lossy UTF-8 decode, matching the filesystem source's windowed/mmap reads
    // (`String::from_utf8_lossy`): binary or mixed-encoding stdin is scanned for
    // the text it does contain rather than rejected. Rejecting it made
    // `cat binaryfile | keyhog scan --stdin` a source failure (exit 2 under the
    // KH-GAP-096 fail-closed) while `keyhog scan binaryfile` happily lossy-scans
    // the same bytes, an inconsistency, and real secrets do live in otherwise
    // non-UTF-8 inputs (embedded configs, archive members, latin-1 logs). The
    // size cap above already bounds memory.
    //
    // `from_utf8` (consuming the owned `Vec`) reuses the buffer's allocation on
    // the common valid-UTF-8 path, zero copy, and only the rare invalid input
    // pays the lossy re-encode; `from_utf8_lossy(&bytes).into_owned()` copied the
    // whole stdin buffer even when it was already valid UTF-8.
    match String::from_utf8(read.bytes) {
        Ok(text) => Ok(text),
        Err(err) => Ok(String::from_utf8_lossy(&err.into_bytes()).into_owned()),
    }
}
