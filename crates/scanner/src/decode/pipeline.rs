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
            // JSON unescape — strips `\"` / `\\` / `\n` style escapes
            // inside JSON string values so credentials stored as
            // JSON-encoded fields (the most common shape after .env)
            // survive into the scanner. Originally implemented but
            // never registered — the adversarial_explosion_runner's
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
        tracing::warn!("register_decoder called after initialization — decoder ignored. Fix: register custom decoders before scanning.");
        return;
    }
    // KEEP THIS LIST IN SYNC with `get_decoders()` above — they're
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
            for decoded in decoder.decode_chunk(&current) {
                if seen.insert(hash_fast(decoded.data.as_bytes())) {
                    // Optional sanitization (kimi-wave1 audit finding 5.1).
                    // When `validate=true`, drop decoded chunks containing
                    // NUL bytes — these are typically buggy-decoder output
                    // (mis-decoded binary, broken-encoded base64) and feed
                    // garbage into downstream regex scanning. C1 controls
                    // (0x80-0x9F) are kept because legitimate UTF-8 multi-
                    // byte sequences include those bytes.
                    if validate && decoded.data.as_bytes().contains(&0u8) {
                        continue;
                    }
                    if let Some(screen) = screen {
                        if !screen.screen(decoded.data.as_bytes()) {
                            continue;
                        }
                    }

                    total_bytes += decoded.data.len();
                    if decoded_chunks.len() >= MAX_DECODED_CHUNKS_PER_ROOT
                        || total_bytes > MAX_DECODED_TOTAL_BYTES
                    {
                        // Demoted from `warn!` — hitting the recursive
                        // decode limit is a benign cap, not an error.
                        // Files with dense nested encoding (audit logs,
                        // sealed blobs, base64-of-base64-of-zlib...)
                        // trip it routinely on every scan, which made
                        // routine output (e.g. `keyhog scan ~/.config`)
                        // look like the scanner was failing. Real
                        // scanner failures use `warn!`/`error!`.
                        tracing::debug!(
                            path = ?chunk.metadata.path,
                            "decode depth/size cap reached — chunk truncated to limit"
                        );
                        return decoded_chunks;
                    }

                    queue.push_back((decoded.clone(), depth + 1));
                    decoded_chunks.push(decoded);
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
    let payload = if !original_encoded.is_empty()
        && chunk.data.len() <= MAX_SPLICE_PARENT_BYTES
        && chunk.data.as_str().contains(original_encoded)
    {
        chunk.data.as_str().replacen(original_encoded, &text, 1)
    } else {
        text
    };

    decoded_chunks.push(Chunk {
        data: payload.into(),
        metadata: ChunkMetadata {
            // Defect #80 (root cause D): decoded-chunk findings used to
            // report `offset: 0` regardless of where the encoded blob
            // sat in the parent file — a Z85-decoded credential at
            // offset 166332 of a 156955-byte file is meaningless to
            // anyone trying to navigate to it. Inherit the parent's
            // `base_offset` so the reported file offset is at least
            // anchored to the parent window/file, not the decoded
            // synthetic stream. Per-blob precision (offset OF the
            // encoded blob in parent) would need `extract_encoded_values`
            // to return positions too — a follow-up. This is strictly
            // closer to the truth.
            base_offset: chunk.metadata.base_offset,
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
            // candidate string in the parent — keeps companion
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

pub(super) fn extract_encoded_values(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    // Base64 block accumulator — collected in the SAME pass as quoted/assigned values.
    let mut b64_block = String::new();
    // Percent-encoded run accumulator — picks up freestanding `%41%57…`
    // blobs that don't sit immediately after `=`/`:` (e.g.
    // `Authorization: Bearer %41%57…` where the b64 accumulator
    // breaks on `%` and the assignment-value extractor stops at the
    // first whitespace after `Bearer`). Without this the url-percent
    // decode-through path lost ~25% of contract positives whose
    // credential lived past a non-trivial prefix word. Tracked by
    // `encoding_explosion_runner` url-percent floor.
    let mut pct_block = String::new();

    let is_b64_char = |ch: char| -> bool {
        ch.is_ascii_alphanumeric() || ch == '+' || ch == '/' || ch == '=' || ch == '-' || ch == '_'
    };
    // Members of a percent-run AFTER the leading `%`: hex digits + the
    // `%` itself (which restarts a fresh triplet). Anything else
    // terminates the run.
    let is_pct_run_char = |ch: char| -> bool { ch == '%' || ch.is_ascii_hexdigit() };

    // Flush a pending percent run if it covers at least 2 triplets
    // (6 chars). Shorter runs are usually printf/URL noise; 2 triplets
    // is enough for compact percent-encoded dev IDs in contracts.
    fn flush_pct(values: &mut Vec<String>, pct_block: &mut String) {
        // Two triplets (6 decoded bytes) covers short numeric dev IDs and
        // other compact secrets that `encoding_explosion_runner` percent-
        // encodes wholesale. Three triplets remains the default bar for
        // freestanding runs to keep `%2F`-style URL noise out.
        const MIN_PCT_TRIPLETS: usize = 1;
        if pct_block.len() >= MIN_PCT_TRIPLETS * 3
            && pct_block.matches('%').count() >= MIN_PCT_TRIPLETS
        {
            values.push(std::mem::take(pct_block));
        }
        pct_block.clear();
    }

    // Single-pass char-level iteration. Safe for UTF-8 (no mid-codepoint splits).
    let mut chars = text.char_indices().peekable();
    while let Some(&(_, ch)) = chars.peek() {
        // ── Quoted strings ──────────────────────────────────────────
        if ch == '"' || ch == '\'' || ch == '`' {
            // Flush any pending b64 block
            if b64_block.len() >= 16 {
                values.push(std::mem::take(&mut b64_block));
            }
            b64_block.clear();
            flush_pct(&mut values, &mut pct_block);

            let quote = ch;
            chars.next();
            let mut escaping = false;
            let mut cleaned = String::with_capacity(32);

            while let Some(&(_, current)) = chars.peek() {
                chars.next();
                if escaping {
                    cleaned.push(current);
                    escaping = false;
                } else if current == '\\' {
                    escaping = true;
                } else if current == quote {
                    if cleaned.len() >= 4 {
                        values.push(cleaned);
                    }
                    break;
                } else if !current.is_ascii_whitespace() {
                    cleaned.push(current);
                }
            }
            continue;
        }

        // ── Assignment values (key=value / key: value) ──────────────
        if ch == ':' || ch == '=' {
            if b64_block.len() >= 16 {
                values.push(std::mem::take(&mut b64_block));
            }
            b64_block.clear();
            flush_pct(&mut values, &mut pct_block);

            chars.next();
            // Skip whitespace after delimiter
            while chars.peek().is_some_and(|&(_, c)| c.is_ascii_whitespace()) {
                chars.next();
            }
            let mut cleaned = String::with_capacity(32);
            while let Some(&(_, c)) = chars.peek() {
                if c.is_ascii_whitespace()
                    || c == ';'
                    || c == ','
                    || c == '"'
                    || c == '\''
                    || c == '`'
                {
                    break;
                }
                cleaned.push(c);
                chars.next();
            }
            if cleaned.len() >= 4 {
                values.push(cleaned);
            }
            continue;
        }

        // ── Percent-run accumulation ────────────────────────────────
        // Percent starts a new triplet. Hex digits extend it. Anything
        // else terminates the run; a sufficiently long run is pushed
        // as its own candidate so the url_decode pass picks it up
        // regardless of whether it sat after `=`/`:` or inside quotes.
        if is_pct_run_char(ch) {
            // A run can only LEGITIMATELY start with '%'. If we see a
            // bare hex digit and the block is empty, ignore it (it's
            // ordinary text, not the leading byte of a percent run).
            if pct_block.is_empty() && ch != '%' {
                // fallthrough to b64 accumulator below
            } else {
                pct_block.push(ch);
                // Don't fall into the b64 accumulator branch on the
                // same char; `%` and the hex digits are still valid
                // base64 chars only for the alphanumerics, and we
                // don't want a `%41%57` blob to ALSO accumulate as a
                // base64 candidate (`4157`) — which would generate
                // spurious decode candidates downstream.
                chars.next();
                continue;
            }
        } else if !pct_block.is_empty() {
            flush_pct(&mut values, &mut pct_block);
        }

        // ── Base64 block accumulation (merged from old second pass) ─
        if is_b64_char(ch) {
            b64_block.push(ch);
        } else if !ch.is_whitespace() {
            if b64_block.len() >= 16 {
                values.push(std::mem::take(&mut b64_block));
            }
            b64_block.clear();
        }
        // else: whitespace inside b64 blocks is allowed (line continuations)

        chars.next();
    }

    // Flush trailing b64 block
    if b64_block.len() >= 16 {
        values.push(b64_block);
    }
    flush_pct(&mut values, &mut pct_block);

    values
}

/// Fast non-cryptographic hash for dedup. FNV-1a is simple and fast enough
/// for collision avoidance in a small set of decoded chunks.
fn hash_fast(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}
