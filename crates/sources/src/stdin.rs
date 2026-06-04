//! Standard input source: reads piped input as a single chunk for scanning.

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use std::io::Read;

// Security boundary: stdin is intentionally capped so piped input cannot force
// an unbounded allocation during scan startup.
const MAX_STDIN_BYTES: usize = 10 * 1024 * 1024;

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

impl Source for StdinSource {
    fn name(&self) -> &str {
        "stdin"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        let stdin_read = read_stdin_limited(MAX_STDIN_BYTES);

        Box::new(std::iter::once(match stdin_read {
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
                },
            }),
            Err(e) => Err(SourceError::Io(e)),
        }))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn read_stdin_limited(max_bytes: usize) -> std::io::Result<String> {
    read_to_string_limited(&mut std::io::stdin().lock(), max_bytes)
}

fn read_to_string_limited(reader: &mut impl Read, max_bytes: usize) -> std::io::Result<String> {
    let mut bytes = Vec::new();
    // Read at most `max_bytes + 1` so oversized stdin is rejected before we
    // hand a giant buffer to the scanner.
    reader.take(max_bytes as u64 + 1).read_to_end(&mut bytes)?;

    if bytes.len() > max_bytes {
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
    // the same bytes — an inconsistency, and real secrets do live in otherwise
    // non-UTF-8 inputs (embedded configs, archive members, latin-1 logs). The
    // size cap above already bounds memory.
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}
