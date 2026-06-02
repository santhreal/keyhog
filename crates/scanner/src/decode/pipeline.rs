use super::base64::{Base64Decoder, Z85Decoder};
use super::caesar::CaesarDecoder;
use super::hex::HexDecoder;
use super::json::JsonDecoder;
use super::reverse::ReverseDecoder;
use super::url::{
    HexEscapeDecoder, HtmlNamedEntityDecoder, HtmlNumericEntityDecoder, MimeEncodedWordDecoder,
    OctalEscapeDecoder, QuotedPrintableDecoder, UnicodeEscapeDecoder, UrlDecoder,
};
use super::Decoder;
use keyhog_core::{Chunk, ChunkMetadata};
use std::collections::{HashSet, VecDeque};

static DECODERS: std::sync::OnceLock<Vec<Box<dyn Decoder>>> = std::sync::OnceLock::new();

const MAX_DECODED_CHUNKS_PER_ROOT: usize = 1000;
const MAX_DECODED_TOTAL_BYTES: usize = 64 * 1024 * 1024;
/// Hard ceiling on the wall-clock time decode_chunk may spend on ONE chunk
/// when the caller didn't pass an explicit deadline. Mitigates decode-bomb
/// inputs (multi-layer base64 of unrelated data) that the existing
/// MAX_DECODED_TOTAL_BYTES cap doesn't catch when each layer fits under the
/// total budget but together blow the wall budget. Tuned generously: 50 ms
/// is ~10x the cost of a normal chunk's full decode-through; pathological
/// inputs hit it before the user notices.
const DEFAULT_DECODE_WALL_BUDGET_MS: u64 = 50;

fn get_decoders() -> &'static [Box<dyn Decoder>] {
    DECODERS.get_or_init(|| {
        vec![
            Box::new(Base64Decoder),
            Box::new(HexDecoder),
            Box::new(UrlDecoder),
            Box::new(QuotedPrintableDecoder),
            Box::new(HtmlNamedEntityDecoder),
            Box::new(HtmlNumericEntityDecoder),
            Box::new(HexEscapeDecoder),
            Box::new(OctalEscapeDecoder),
            Box::new(MimeEncodedWordDecoder),
            Box::new(UnicodeEscapeDecoder),
            // JSON unescape - strips `\"` / `\\` / `\n` style escapes
            // inside JSON string values so credentials stored as
            // JSON-encoded fields (the most common shape after .env)
            // survive into the scanner. Originally implemented but
            // never registered - the adversarial_explosion_runner's
            // `json` wrapper class surfaced ~73 misses that wiring
            // this in closed (5792/5792 variants now fire).
            Box::new(JsonDecoder),
            Box::new(Z85Decoder),
            Box::new(ReverseDecoder),
            Box::new(CaesarDecoder),
        ]
    })
}

/// Register a custom decoder. Must be called BEFORE any scan runs.
/// Panics if the decoder list has already been initialized.
pub fn register_decoder(decoder: Box<dyn Decoder>) {
    // After initialization, the decoder list is immutable for lock-free reads.
    // Custom decoders must be registered before the first scan.
    if DECODERS.get().is_some() {
        tracing::warn!("register_decoder called after initialization: decoder ignored. Fix: register custom decoders before scanning.");
        return;
    }
    // KEEP THIS LIST IN SYNC with `get_decoders()` above - they're
    // two paths to the same initialized state, and a decoder missing
    // here would silently vanish from any custom-decoder-registered
    // run.
    let mut decoders: Vec<Box<dyn Decoder>> = vec![
        Box::new(Base64Decoder),
        Box::new(HexDecoder),
        Box::new(UrlDecoder),
        Box::new(QuotedPrintableDecoder),
        Box::new(HtmlNamedEntityDecoder),
        Box::new(HtmlNumericEntityDecoder),
        Box::new(HexEscapeDecoder),
        Box::new(OctalEscapeDecoder),
        Box::new(MimeEncodedWordDecoder),
        Box::new(UnicodeEscapeDecoder),
        Box::new(JsonDecoder),
        Box::new(Z85Decoder),
        Box::new(ReverseDecoder),
        Box::new(CaesarDecoder),
    ];
    decoders.push(decoder);
    let _ = DECODERS.set(decoders);
}

pub fn decode_chunk(
    chunk: &Chunk,
    max_depth: usize,
    validate: bool,
    deadline: Option<std::time::Instant>,
    screen: Option<&crate::alphabet_filter::AlphabetScreen>,
) -> Vec<Chunk> {
    let mut decoded_chunks = Vec::new();
    let mut queue = VecDeque::from([(chunk.clone(), 0usize)]);
    // Use hash of data instead of full string to save memory on large files.
    let mut seen = HashSet::from([hash_fast(chunk.data.as_bytes())]);
    let mut total_bytes = 0usize;
    // Count EVERY unique decoded chunk against the per-root fan-out cap,
    // not just the ones that pass the alphabet screen and get returned
    // (M2). Screen-failing chunks were still queued and recursively
    // re-decoded but never incremented `decoded_chunks.len()`, so on the
    // live screen-enabled path the 1000-chunk DoS guard never bound a
    // high-fan-out decoder (Caesar emits up to 25 variants/candidate,
    // most failing the screen). The screen decides whether a chunk is
    // RETURNED for scanning; this counter decides the recursion budget.
    let mut produced = 0usize;

    let registry = get_decoders();

    // Per-chunk wall-clock ceiling. Always apply the TIGHTER of the
    // caller-supplied `deadline` and our own `DEFAULT_DECODE_WALL_BUDGET_MS`
    // ceiling. kimi-wave1 audit finding 5.2: previously the caller's
    // (long) scan deadline overrode this guard, letting a decode-bomb
    // chunk consume the entire scan budget.
    let local_ceiling =
        std::time::Instant::now() + std::time::Duration::from_millis(DEFAULT_DECODE_WALL_BUDGET_MS);
    let effective_deadline = match deadline {
        Some(d) => d.min(local_ceiling),
        None => local_ceiling,
    };

    while let Some((current, depth)) = queue.pop_front() {
        if std::time::Instant::now() > effective_deadline {
            tracing::debug!(
                path = ?chunk.metadata.path,
                budget_ms = DEFAULT_DECODE_WALL_BUDGET_MS,
                "decode budget exhausted; stopping decode-through"
            );
            break;
        }
        if depth >= max_depth {
            continue;
        }

        for decoder in registry.iter() {
            // Re-check the wall-clock budget BEFORE each decoder's
            // candidate fan-out (C9). The top-of-loop check only fires
            // once per BFS dequeue, so a single chunk could run all 14
            // decoders to completion with no budget check, blowing far past
            // DEFAULT_DECODE_WALL_BUDGET_MS on one chunk. This check stops us
            // from even invoking the next decoder once the deadline trips;
            // the matching check inside the inner loop below stops us
            // consuming the CURRENT decoder's (un-bounded) output.
            if std::time::Instant::now() > effective_deadline {
                tracing::debug!(
                    path = ?chunk.metadata.path,
                    budget_ms = DEFAULT_DECODE_WALL_BUDGET_MS,
                    "decode budget exhausted mid-fan-out; stopping decode-through"
                );
                return decoded_chunks;
            }
            for decoded in decoder.decode_chunk(&current) {
                // Re-check the budget WHILE consuming this decoder's output
                // (C9 root cause). The pre-decoder check above only fires
                // once per decoder, but `decode_chunk` returns a fully
                // materialized Vec whose length is O(chunk size) -
                // `extract_encoded_values` yields one candidate per quoted
                // string / `key=value` / base64 run, and Caesar fans each out
                // 25x. Without this check the pipeline still hashes, screens,
                // clones, and queues every one of those results AFTER the
                // deadline has passed, so a single dense chunk's fan-out
                // (tens of thousands of results) ran the per-result work to
                // completion regardless of the wall budget. The
                // `decoder.decode_chunk` call itself cannot be interrupted
                // (trait returns an owned Vec), but bailing here bounds the
                // post-deadline overrun to one decoder's fan-out at most -
                // and stops the (dominant) per-result processing cost dead.
                if std::time::Instant::now() > effective_deadline {
                    tracing::debug!(
                        path = ?chunk.metadata.path,
                        budget_ms = DEFAULT_DECODE_WALL_BUDGET_MS,
                        "decode budget exhausted while consuming decoder output; \
                         stopping decode-through"
                    );
                    return decoded_chunks;
                }
                if seen.insert(hash_fast(decoded.data.as_bytes())) {
                    // Optional sanitization (kimi-wave1 audit finding 5.1).
                    // When `validate=true`, drop decoded chunks containing
                    // NUL bytes - these are typically buggy-decoder output
                    // (mis-decoded binary, broken-encoded base64) and feed
                    // garbage into downstream regex scanning. C1 controls
                    // (0x80-0x9F) are kept because legitimate UTF-8 multi-
                    // byte sequences include those bytes.
                    if validate && decoded.data.as_bytes().contains(&0u8) {
                        continue;
                    }
                    let passes_screen = if let Some(screen) = screen {
                        screen.screen(decoded.data.as_bytes())
                    } else {
                        true
                    };

                    // Count this unique decoded chunk against the fan-out
                    // budget REGARDLESS of screen result (M2): a chunk that
                    // fails the screen is still queued and recursively
                    // re-decoded, so it must consume the recursion budget.
                    produced += 1;
                    total_bytes += decoded.data.len();
                    if produced > MAX_DECODED_CHUNKS_PER_ROOT
                        || total_bytes > MAX_DECODED_TOTAL_BYTES
                    {
                        // Demoted from `warn!` - hitting the recursive
                        // decode limit is a benign cap, not an error.
                        // Files with dense nested encoding (audit logs,
                        // sealed blobs, base64-of-base64-of-zlib...)
                        // trip it routinely on every scan, which made
                        // routine output (e.g. `keyhog scan ~/.config`)
                        // look like the scanner was failing. Real
                        // scanner failures use `warn!`/`error!`.
                        tracing::debug!(
                            path = ?chunk.metadata.path,
                            "decode depth/size cap reached: chunk truncated to limit"
                        );
                        return decoded_chunks;
                    }

                    queue.push_back((decoded.clone(), depth + 1));
                    if passes_screen {
                        decoded_chunks.push(decoded);
                    }
                }
            }
        }
    }
    decoded_chunks
}

pub(super) fn push_decoded_text_chunk(
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
///
/// Why this exists
/// ---------------
/// Before the splice path, `push_decoded_text_chunk` always emitted
/// the decoded bytes in a brand-new chunk with NO surrounding text.
/// The `encoding_explosion_runner` (tests/encoding_explosion_runner.rs)
/// surfaced the resulting recall gap: base64/hex/url-percent
/// encodings recovered only ~30% of contract credentials because
/// every companion-anchored detector lost its anchor when the chunk
/// was reduced to a bare decoded string. Splicing preserves the
/// anchor and is the single biggest decode-through recall lever.
pub(super) fn push_decoded_text_chunk_spliced(
    decoded_chunks: &mut Vec<Chunk>,
    chunk: &Chunk,
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
    // occurrence so the companion context survives. Cap the splice
    // path on chunk size so a multi-MB parent doesn't blow memory.
    const MAX_SPLICE_PARENT_BYTES: usize = 256 * 1024;
    let (base_offset, payload) = if !original_encoded.is_empty()
        && chunk.data.len() <= MAX_SPLICE_PARENT_BYTES
    {
        match splice_decoded_payload(chunk.data.as_str(), original_encoded, &text, decoder_name) {
            // The decoded credential now sits `win_start` bytes into the
            // windowed payload's parent slice, so shift base_offset to keep
            // the reported file offset anchored to the real position.
            Some((win_start, spliced)) => (
                chunk.metadata.base_offset.saturating_add(win_start),
                spliced,
            ),
            None => (chunk.metadata.base_offset, text),
        }
    } else {
        (chunk.metadata.base_offset, text)
    };

    decoded_chunks.push(Chunk {
        data: payload.into(),
        metadata: ChunkMetadata {
            // Defect #80 (root cause D): decoded-chunk findings used to
            // report `offset: 0` regardless of where the encoded blob
            // sat in the parent file - a Z85-decoded credential at
            // offset 166332 of a 156955-byte file is meaningless to
            // anyone trying to navigate to it. Inherit the parent's
            // `base_offset` so the reported file offset is at least
            // anchored to the parent window/file, not the decoded
            // synthetic stream. Per-blob precision (offset OF the
            // encoded blob in parent) would need `extract_encoded_values`
            // to return positions too - a follow-up. This is strictly
            // closer to the truth. When splicing succeeds we additionally
            // shift by the context-window start so the offset points near the
            // blob's real position, not just the parent's origin.
            base_offset,
            source_type: format!("{}/{}", chunk.metadata.source_type, decoder_name),
            path: chunk.metadata.path.clone(),
            commit: chunk.metadata.commit.clone(),
            author: chunk.metadata.author.clone(),
            date: chunk.metadata.date.clone(),
            // Decoded chunks inherit the parent's metadata; mtime/size
            // are deliberately copied so the orchestrator's cache key
            // tracks the underlying file even after a decode pass.
            mtime_ns: chunk.metadata.mtime_ns,
            size_bytes: chunk.metadata.size_bytes,
        },
    });
}

/// Bytes of surrounding parent text kept on each side of the spliced-in
/// decoded credential. The splice exists ONLY to keep the decoded value's
/// companion anchor (assignment key / `Authorization:` header / `api_key=`
/// prefix) adjacent so companion-anchored detectors still fire. That anchor
/// always sits within a line or two of the credential, so a few hundred bytes
/// of context on each side is plenty.
///
/// Why this is bounded (perf, not cosmetics): the previous implementation
/// spliced the decoded text into a copy of the ENTIRE parent, producing one
/// parent-sized decoded chunk PER candidate. On a 156 KB source file with
/// ~1800 splice candidates (every quoted string / `key=value` / hex/base64
/// run) that spawned ~280 MB of decoded chunks - each then rescanned by the
/// full engine and recursively re-decoded - an O(candidates × file_size)
/// blowup that pinned a single b43/main.c scan at ~15s. Windowing makes each
/// spliced chunk O(window), turning the whole pass linear. Recall is
/// unaffected because no detector reaches across hundreds of bytes for its
/// anchor.
const SPLICE_CONTEXT_WINDOW: usize = 512;

/// Round `idx` down to the nearest UTF-8 char boundary in `s` (stable-Rust
/// stand-in for the unstable `str::floor_char_boundary`). Used to snap the
/// splice context window so it never slices a multi-byte codepoint.
fn floor_char_boundary(s: &str, mut idx: usize) -> usize {
    if idx >= s.len() {
        return s.len();
    }
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

fn ceil_char_boundary(s: &str, mut idx: usize) -> usize {
    if idx >= s.len() {
        return s.len();
    }
    while idx < s.len() && !s.is_char_boundary(idx) {
        idx += 1;
    }
    idx
}

/// Returns `(window_start, payload)` where `window_start` is the byte offset
/// in `parent` at which `payload` begins, so the caller can keep the reported
/// finding offset anchored to the real file position.
fn splice_decoded_payload(
    parent: &str,
    original_encoded: &str,
    decoded_text: &str,
    decoder_name: &str,
) -> Option<(usize, String)> {
    let start = parent.find(original_encoded)?;
    let mut end = start + original_encoded.len();

    if decoder_name == "base64" {
        end = consume_adjacent_base64_padding(parent.as_bytes(), end);
    }

    // Keep only a bounded window of parent context around the encoded blob.
    let win_start = floor_char_boundary(parent, start.saturating_sub(SPLICE_CONTEXT_WINDOW));
    let win_end = ceil_char_boundary(parent, end.saturating_add(SPLICE_CONTEXT_WINDOW));

    let mut payload =
        String::with_capacity((win_end - win_start) - (end - start) + decoded_text.len());
    payload.push_str(&parent[win_start..start]);
    payload.push_str(decoded_text);
    payload.push_str(&parent[end..win_end]);
    Some((win_start, payload))
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
        None | Some(b'\n' | b'\r' | b'\t' | b' ' | b';' | b',' | b'"' | b'\'' | b'`') => end,
        _ => start,
    }
}

pub(super) fn decode_candidates<F>(
    chunk: &Chunk,
    candidates: Vec<String>,
    mut decode: F,
    decoder_name: &str,
) -> Vec<Chunk>
where
    F: FnMut(&str) -> Result<String, ()>,
{
    let mut decoded_chunks = Vec::new();
    for candidate in candidates {
        if let Ok(text) = decode(&candidate) {
            // Splice each decoded value back over its original
            // candidate string in the parent - keeps companion
            // context (assignment keys, format-specific anchors)
            // adjacent to the decoded credential. Same recall-gap
            // fix as base64/hex/json.
            push_decoded_text_chunk_spliced(
                &mut decoded_chunks,
                chunk,
                &candidate,
                text,
                decoder_name,
            );
        }
    }
    decoded_chunks
}

mod extractor;
pub(super) use extractor::{extract_encoded_values, hash_fast};
