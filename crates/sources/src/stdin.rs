//! Standard input source: spools piped input and scans bounded windows.

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use std::io::{Read, Seek, SeekFrom, Write};

/// Spools stdin under its byte cap and emits bounded overlapping windows.
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

const STDIN_WINDOW_SIZE: usize = 1024 * 1024;
const STDIN_WINDOW_OVERLAP: usize = 128 * 1024;

struct SpooledStdinChunks {
    file: std::fs::File,
    len: usize,
    next_offset: usize,
    next_line: usize,
    done: bool,
}

struct BufferedStdinChunks {
    bytes: std::sync::Arc<[u8]>,
    next_offset: usize,
    next_line: usize,
    done: bool,
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
    pub fn new(bytes: impl Into<std::sync::Arc<[u8]>>) -> Self {
        Self {
            bytes: bytes.into(),
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
            buffered_chunks_with_limit(std::sync::Arc::clone(&self.bytes), self.limits.stdin_bytes)
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn chunks_with_limit(max_bytes: usize) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>>> {
    crate::gate_scan(|| match spool_stdin_limited(max_bytes) {
        Ok((file, len)) => Box::new(SpooledStdinChunks {
            file,
            len,
            next_offset: 0,
            next_line: 0,
            done: false,
        }),
        Err(error) => Box::new(std::iter::once(Err(SourceError::Io(error)))),
    })
}

fn buffered_chunks_with_limit(
    bytes: std::sync::Arc<[u8]>,
    max_bytes: usize,
) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>>> {
    // Same acquire/read boundary as spooling stdin: accepting a pre-owned
    // payload is still one acquisition, and preparing its scan windows is one
    // buffering read. Without these spans BufferedStdinSource looked unprofiled
    // while still charging input totals.
    let _acquire = crate::profile::acquire_span();
    if bytes.len() > max_bytes {
        let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
        return Box::new(std::iter::once(Err(SourceError::Io(
            std::io::Error::other(format!("stdin exceeds {max_bytes} byte limit")),
        ))));
    }
    let _buffering = crate::profile::read_span();
    crate::profile::add_input_units(1);
    crate::profile::add_input_bytes(bytes.len() as u64);
    Box::new(BufferedStdinChunks {
        bytes,
        next_offset: 0,
        next_line: 0,
        done: false,
    })
}

impl Iterator for BufferedStdinChunks {
    type Item = Result<Chunk, SourceError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let start = self.next_offset;
        let end = start
            .saturating_add(STDIN_WINDOW_SIZE)
            .min(self.bytes.len());
        let bytes = &self.bytes[start..end];
        let advanced = (end < self.bytes.len()).then_some(STDIN_WINDOW_SIZE - STDIN_WINDOW_OVERLAP);
        let advanced_lines = advanced
            .map(|len| memchr::memchr_iter(b'\n', &bytes[..len]).count())
            .unwrap_or(0); // LAW10: a terminal stdin window advances no overlap bytes, so its exact advanced-line count is zero.
        let text = match std::str::from_utf8(bytes) {
            Ok(text) => text.to_owned(),
            Err(_) => String::from_utf8_lossy(bytes).into_owned(), // LAW10: lossy decoding preserves every valid ASCII secret byte and replaces only invalid UTF-8 sequences.
        };
        let base_line = self.next_line;
        if end >= self.bytes.len() {
            self.done = true;
        } else if let Some(advanced) = advanced {
            self.next_offset += advanced;
            self.next_line += advanced_lines;
        }
        Some(Ok(stdin_chunk(text, start, base_line)))
    }
}

impl Iterator for SpooledStdinChunks {
    type Item = Result<Chunk, SourceError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        let start = self.next_offset;
        let read_len = self.len.saturating_sub(start).min(STDIN_WINDOW_SIZE);
        let mut bytes = vec![0; read_len];
        if let Err(error) = self
            .file
            .seek(SeekFrom::Start(start as u64))
            .and_then(|_| self.file.read_exact(&mut bytes))
        {
            self.done = true;
            return Some(Err(SourceError::Io(error)));
        }

        let end = start + read_len;
        let advanced = if end < self.len {
            Some(read_len - STDIN_WINDOW_OVERLAP)
        } else {
            None
        };
        let advanced_lines = advanced
            .map(|len| memchr::memchr_iter(b'\n', &bytes[..len]).count())
            .unwrap_or(0); // LAW10: a terminal stdin window advances no overlap bytes, so its exact advanced-line count is zero.
        let text = match String::from_utf8(bytes) {
            Ok(text) => text,
            Err(error) => String::from_utf8_lossy(&error.into_bytes()).into_owned(),
        };
        let base_line = self.next_line;
        if end >= self.len {
            self.done = true;
        } else if let Some(advanced) = advanced {
            self.next_line += advanced_lines;
            self.next_offset += advanced;
        }

        Some(Ok(stdin_chunk(text, start, base_line)))
    }
}

fn stdin_chunk(text: String, base_offset: usize, base_line: usize) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            base_offset,
            base_line,
            source_type: "stdin".into(),
            path: None,
            commit: None,
            author: None,
            date: None,
            mtime_ns: None,
            size_bytes: None,
            decoded_span: None,
        },
    }
}

fn spool_stdin_limited(max_bytes: usize) -> std::io::Result<(std::fs::File, usize)> {
    let _acquire = crate::profile::acquire_span();
    let mut input = std::io::stdin().lock();
    let mut file = tempfile::tempfile()?;
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0usize;
    let _buffering = crate::profile::read_span();

    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "stdin byte count overflow")
        })?;
        if total > max_bytes {
            let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
            return Err(std::io::Error::other(format!(
                "stdin exceeds {} byte limit",
                max_bytes
            )));
        }
        file.write_all(&buffer[..read])?;
    }
    drop(_buffering);

    crate::profile::add_input_units(1);
    crate::profile::add_input_bytes(total as u64);
    Ok((file, total))
}

pub(crate) fn read_to_string_limited(
    reader: &mut impl Read,
    max_bytes: usize,
) -> std::io::Result<String> {
    let _acquire = crate::profile::acquire_span();
    let cap = u64::try_from(max_bytes).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "stdin cap is too large for this platform",
        )
    })?;
    // Read at most `max_bytes + 1` so oversized stdin is rejected before we
    // hand a giant buffer to the scanner.
    // The helper owns one bounded decode buffer and has no queue handoff.
    let _buffering = crate::profile::read_span();
    let read = crate::capped_read::read_to_cap(reader, cap, None)?;
    drop(_buffering);

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
