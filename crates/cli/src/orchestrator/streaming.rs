use super::DefaultScanRuntime;
use anyhow::Result;
use keyhog_core::{RawMatch, Source};
use std::path::Path;

pub(crate) enum StreamingSourceEvent {
    UnreadableChunk,
    Matches {
        chunk_len: usize,
        matches: Vec<RawMatch>,
    },
}

pub(crate) fn scan_streaming_source(
    scan_runtime: &DefaultScanRuntime,
    source: &dyn Source,
    source_kind: &'static str,
    root: &Path,
    mut should_stop_before_chunk: impl FnMut(usize) -> bool,
    mut handle_event: impl FnMut(StreamingSourceEvent) -> Result<()>,
) -> Result<()> {
    for chunk_result in source.chunks() {
        let chunk = match chunk_result {
            Ok(chunk) => chunk,
            // Law 10: an unreadable source chunk is unscanned bytes. This shared
            // loop owns the loud trace; callers own the visible summary/counting
            // policy through `record_unreadable_chunk`.
            Err(error) => {
                tracing::warn!(
                    source_kind,
                    root = %root.display(),
                    %error,
                    "streaming source chunk could not be read; counted as skipped"
                );
                handle_event(StreamingSourceEvent::UnreadableChunk)?;
                continue;
            }
        };
        let chunk_len = chunk.data.len();
        if should_stop_before_chunk(chunk_len) {
            return Ok(());
        }
        let matches = scan_runtime.scan_chunk(&chunk)?;
        handle_event(StreamingSourceEvent::Matches { chunk_len, matches })?;
    }
    Ok(())
}
