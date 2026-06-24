use super::extractor::ExtractedValue;
use keyhog_core::{Chunk, ChunkMetadata};

pub(in crate::decode) fn push_decoded_text_chunk(
    decoded_chunks: &mut Vec<Chunk>,
    chunk: &Chunk,
    text: String,
    decoder_name: &str,
) {
    // Legacy entrypoint with no source-blob info. Forwards to the
    // splice-aware variant with `original_encoded = ""`, which falls
    // back to the old "decoded text alone" chunk shape. New decoders
    // should call `push_decoded_text_chunk_spliced` so the parent's
    // companion context lands adjacent to the decoded credential.
    push_decoded_text_chunk_spliced(decoded_chunks, chunk, "", text, decoder_name);
}

/// Push a decoded chunk that **splices** the decoded text back into
/// the parent at the position of the original encoded blob. This
/// keeps the parent's companion context (the `aws_secret =` /
/// `Authorization: Bearer` / `api_key:` anchors) adjacent to the
/// decoded credential, which is what detector regexes need to fire.
///
/// Pass an empty `original_encoded` to fall back to the legacy
/// "decoded text alone" behavior.
pub(in crate::decode) fn push_decoded_text_chunk_spliced(
    decoded_chunks: &mut Vec<Chunk>,
    chunk: &Chunk,
    original_encoded: &str,
    text: String,
    decoder_name: &str,
) {
    push_decoded_text_chunk_spliced_at(
        decoded_chunks,
        chunk,
        None,
        original_encoded,
        text,
        decoder_name,
    );
}

pub(in crate::decode) fn push_decoded_text_chunk_spliced_at(
    decoded_chunks: &mut Vec<Chunk>,
    chunk: &Chunk,
    original_span: Option<(usize, usize)>,
    original_encoded: &str,
    text: String,
    decoder_name: &str,
) {
    // Fast ASCII check: control chars are always in 0x00-0x1F range.
    // Byte-level iteration avoids UTF-8 decode overhead.
    let bytes = text.as_bytes();
    if text.is_empty()
        || bytes
            .iter()
            .any(|&b| b < 0x20 && b != b'\n' && b != b'\r' && b != b'\t')
    {
        return;
    }

    // Build the new chunk's payload. Default: just the decoded text
    // (legacy shape). If we know the original encoded blob AND it
    // appears in the parent, splice the decoded text in at the first
    // occurrence so the companion context survives. The splice helper
    // keeps only a bounded parent window, so parent file size must not
    // disable context preservation.
    let text_len = text.len();
    let (base_offset, payload, decoded_span) = if !original_encoded.is_empty() {
        let spliced = match original_span {
            Some((start, end)) => {
                splice_decoded_payload_at(chunk.data.as_ref(), start, end, &text, decoder_name)
            }
            None => {
                splice_decoded_payload(chunk.data.as_ref(), original_encoded, &text, decoder_name)
            }
        };
        match spliced {
            Some((win_start, spliced, decoded_at)) => (
                chunk.metadata.base_offset.saturating_add(win_start),
                spliced,
                Some((decoded_at, decoded_at + text_len)),
            ),
            None => (chunk.metadata.base_offset, text, Some((0, text_len))),
        }
    } else {
        (chunk.metadata.base_offset, text, Some((0, text_len)))
    };

    decoded_chunks.push(Chunk {
        data: payload.into(),
        metadata: ChunkMetadata {
            base_offset,
            base_line: chunk.metadata.base_line,
            source_type: format!("{}/{}", chunk.metadata.source_type, decoder_name),
            path: chunk.metadata.path.clone(),
            commit: chunk.metadata.commit.clone(),
            author: chunk.metadata.author.clone(),
            date: chunk.metadata.date.clone(),
            mtime_ns: chunk.metadata.mtime_ns,
            size_bytes: chunk.metadata.size_bytes,
            decoded_span,
        },
    });
}

/// Bytes of surrounding parent text kept on each side of the spliced-in decoded
/// credential. The splice exists only to keep adjacent companion context near
/// the decoded value without cloning the whole parent file per candidate.
const SPLICE_CONTEXT_WINDOW: usize = 512;

fn splice_decoded_payload(
    parent: &str,
    original_encoded: &str,
    decoded_text: &str,
    decoder_name: &str,
) -> Option<(usize, String, usize)> {
    let start = parent.find(original_encoded)?;
    let end = start + original_encoded.len();

    splice_decoded_payload_at(parent, start, end, decoded_text, decoder_name)
}

fn splice_decoded_payload_at(
    parent: &str,
    start: usize,
    end: usize,
    decoded_text: &str,
    decoder_name: &str,
) -> Option<(usize, String, usize)> {
    if start > end || end > parent.len() {
        return None;
    }
    if !parent.is_char_boundary(start) || !parent.is_char_boundary(end) {
        return None;
    }
    let mut end = end;

    if decoder_name == "base64" {
        end = consume_adjacent_base64_padding(parent.as_bytes(), end);
    }

    let win_start =
        crate::engine::floor_char_boundary(parent, start.saturating_sub(SPLICE_CONTEXT_WINDOW));
    let win_end =
        crate::engine::ceil_char_boundary(parent, end.saturating_add(SPLICE_CONTEXT_WINDOW));

    let mut payload =
        String::with_capacity((win_end - win_start) - (end - start) + decoded_text.len());
    payload.push_str(&parent[win_start..start]);
    let decoded_at = start - win_start;
    payload.push_str(decoded_text);
    payload.push_str(&parent[end..win_end]);
    Some((win_start, payload, decoded_at))
}

fn consume_adjacent_base64_padding(parent: &[u8], start: usize) -> usize {
    let mut end = start;
    while end < parent.len() && parent[end] == b'=' && end - start < 2 {
        end += 1;
    }
    if end == start {
        return start;
    }
    match parent.get(end).copied() {
        None
        | Some(
            b'\n' | b'\r' | b'\t' | b' ' | b';' | b',' | b'"' | b'\'' | b'`' | b'}' | b']' | b'&',
        ) => end,
        _ => start,
    }
}

pub(in crate::decode) fn decode_candidate_refs_exact<'a, I, F>(
    chunk: &Chunk,
    candidates: I,
    mut decode: F,
    decoder_name: &str,
) -> Vec<Chunk>
where
    I: IntoIterator<Item = &'a ExtractedValue>,
    F: FnMut(&str) -> Result<String, ()>,
{
    let mut decoded_chunks = Vec::new();
    for candidate in candidates {
        if let Ok(text) = decode(&candidate.value) {
            // LAW10: failed trial decode keeps the original candidate-bearing chunk in the scan path unchanged.
            push_decoded_text_chunk_spliced_at(
                &mut decoded_chunks,
                chunk,
                candidate.span(),
                &candidate.value,
                text,
                decoder_name,
            );
        }
    }
    decoded_chunks
}

pub(in crate::decode) fn decode_candidate_spans_exact<F>(
    chunk: &Chunk,
    candidates: Vec<ExtractedValue>,
    mut decode: F,
    decoder_name: &str,
) -> Vec<Chunk>
where
    F: FnMut(&str) -> Result<String, ()>,
{
    let mut decoded_chunks = Vec::new();
    for candidate in candidates {
        if let Ok(text) = decode(&candidate.value) {
            // LAW10: failed trial decode keeps the original candidate-bearing chunk in the scan path unchanged.
            push_decoded_text_chunk_spliced_at(
                &mut decoded_chunks,
                chunk,
                candidate.span(),
                &candidate.value,
                text,
                decoder_name,
            );
        }
    }
    decoded_chunks
}
