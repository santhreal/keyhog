use super::pipeline::push_decoded_text_chunk_spliced;
use super::util::take_hex_digits;
use super::Decoder;
use keyhog_core::Chunk;

/// JSON-aware decoder that unescapes string values before scanning.
pub(super) struct JsonDecoder;

impl Decoder for JsonDecoder {
    fn name(&self) -> &'static str {
        "json"
    }

    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        let mut decoded_chunks = Vec::new();
        for json_string in extract_json_strings(&chunk.data) {
            // Cheap gate: json_unescape() is a copy-through for strings
            // that contain no `\` escape. Without this gate, every plain
            // string ≥ 4 chars in JSON would produce a duplicate spliced
            // chunk that the engine re-scans for nothing — every
            // `{"k": "EXAMPLE"}` triggered a full extra scan pass.
            // Kimi-decode audit finding #1.
            if !json_string.contains('\\') {
                continue;
            }
            if let Ok(unescaped) = json_unescape(&json_string) {
                // Splice the unescaped value over its escaped form
                // in the parent so the JSON key (`"api_key": "…"`)
                // stays adjacent — exactly the companion anchor most
                // detectors need. Closes the JSON-wrapper miss class
                // surfaced by adversarial_explosion_runner.
                push_decoded_text_chunk_spliced(
                    &mut decoded_chunks,
                    chunk,
                    &json_string,
                    unescaped,
                    self.name(),
                );
            }
        }
        decoded_chunks
    }
}

/// Extract JSON string values from text.
/// Returns the raw content inside JSON string quotes (including escape backslashes).
///
/// UTF-8 correctness: the inner loop iterates `text` by `char_indices`
/// (not by raw bytes) so multi-byte UTF-8 sequences (e.g. CJK strings,
/// emoji) inside JSON values are preserved as a single `char` push,
/// not split into Latin-1 garbage. The earlier byte-oriented loop
/// pushed `bytes[i] as char` which interprets every high byte as
/// U+0080..U+00FF and corrupts any non-ASCII content in the JSON
/// values keyhog scans for secrets (some service tokens carry CJK
/// metadata or non-ASCII URLs inside surrounding JSON).
fn extract_json_strings(text: &str) -> Vec<String> {
    let mut strings = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        // memchr is byte-safe even at UTF-8 boundaries because b'"' is
        // ASCII (< 0x80) and therefore never appears inside a multi-
        // byte UTF-8 continuation. Same for b'\\' and the line
        // terminators below.
        if let Some(quote_idx) = memchr::memchr(b'"', &bytes[index..]) {
            index += quote_idx;
        } else {
            break;
        }

        // Found opening quote — step past it and walk the body as
        // chars, tracking the byte index so we can resume the outer
        // memchr scan correctly.
        index += 1;
        let mut content = String::with_capacity(32);
        let mut escaping = false;
        let mut closed = false;

        for (ci, ch) in text[index..].char_indices() {
            if escaping {
                content.push(ch);
                escaping = false;
            } else if ch == '\\' {
                escaping = true;
                content.push('\\');
            } else if ch == '"' {
                closed = true;
                index += ci + ch.len_utf8();
                if content.len() >= 4 {
                    strings.push(content);
                }
                break;
            } else if ch == '\n' || ch == '\r' {
                // JSON strings cannot span lines unescaped — break
                // BEFORE advancing index so the outer loop resumes
                // at this line terminator and re-scans for the next
                // opening quote on the next line.
                index += ci;
                break;
            } else {
                content.push(ch);
            }
        }

        if closed {
            continue;
        }

        // Either no closing quote OR we broke on a line terminator;
        // advance one byte to avoid an infinite loop on the unmatched
        // opening quote.
        index += 1;
    }

    strings
}

/// Unescape a JSON string. The input must include backslash escape sequences.
fn json_unescape(input: &str) -> Result<String, ()> {
    let mut decoded = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch != '\\' {
            decoded.push(ch);
            continue;
        }

        match chars.next() {
            Some('"') => decoded.push('"'),
            Some('\\') => decoded.push('\\'),
            Some('/') => decoded.push('/'),
            Some('b') => decoded.push('\x08'),
            Some('f') => decoded.push('\x0C'),
            Some('n') => decoded.push('\n'),
            Some('r') => decoded.push('\r'),
            Some('t') => decoded.push('\t'),
            Some('u') => {
                let code = take_hex_digits(&mut chars, 4)?;
                decoded.push(char::from_u32(code).ok_or(())?);
            }
            _ => return Err(()),
        }
    }

    Ok(decoded)
}
