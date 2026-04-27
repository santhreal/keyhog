use super::base64::{Base64Decoder, Z85Decoder};
use super::caesar::CaesarDecoder;
use super::hex::HexDecoder;
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
    // Force initialization with the custom decoder appended.
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
                        tracing::warn!(
                            path = ?chunk.metadata.path,
                            "Recursive decoding limit reached. Fix: reduce decode depth or decode size limits"
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
    if text.is_empty()
        || !text
            .chars()
            .all(|ch| !ch.is_control() || ch == '\n' || ch == '\r' || ch == '\t')
    {
        return;
    }

    decoded_chunks.push(Chunk {
        data: text,
        metadata: ChunkMetadata {
            source_type: format!("{}/{}", chunk.metadata.source_type, decoder_name),
            path: chunk.metadata.path.clone(),
            commit: chunk.metadata.commit.clone(),
            author: chunk.metadata.author.clone(),
            date: chunk.metadata.date.clone(),
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
            push_decoded_text_chunk(&mut decoded_chunks, chunk, text, decoder_name);
        }
    }
    decoded_chunks
}

pub(super) fn extract_encoded_values(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    // Base64 block accumulator — collected in the SAME pass as quoted/assigned values.
    let mut b64_block = String::new();

    let is_b64_char = |ch: char| -> bool {
        ch.is_ascii_alphanumeric() || ch == '+' || ch == '/' || ch == '=' || ch == '-' || ch == '_'
    };

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
