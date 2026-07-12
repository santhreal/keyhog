use super::pipeline::push_decoded_text_chunk_spliced;
use super::util::{resolve_escaped_codepoint, take_hex_digits};
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
        for json_string in extract_escaped_json_strings(&chunk.data) {
            if let Ok(unescaped) = json_unescape(json_string) {
                // LAW10: failed trial unescape leaves the original JSON text scanned unchanged.
                // Splice the unescaped value over its escaped form
                // in the parent so the JSON key (`"api_key": "…"`)
                // stays adjacent - exactly the companion anchor most
                // detectors need. Closes the JSON-wrapper miss class
                // surfaced by adversarial_explosion_runner.
                push_decoded_text_chunk_spliced(
                    &mut decoded_chunks,
                    chunk,
                    json_string,
                    unescaped,
                    self.name(),
                );
            }
        }
        decoded_chunks
    }
}

/// Extract JSON string values that actually contain escapes.
/// Returns borrowed raw content inside quotes (including escape backslashes).
///
/// Most JSON/NDJSON fixture files are packed with plain keys and values. The
/// decoder only needs strings containing `\` escapes, so this scanner avoids
/// allocating a `String` for every ordinary JSON value and borrows only the
/// escaped spans that can produce a distinct decoded chunk.
fn extract_escaped_json_strings(text: &str) -> Vec<&str> {
    // Shortest escaped JSON string worth a distinct decoded chunk: below 4 chars
    // an unescaped body cannot carry a credential-length value.
    const MIN_ESCAPED_JSON_STRING_LEN: usize = 4;
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

        // Found opening quote. Walk bytes: `"`, `\`, CR and LF are ASCII and
        // cannot appear inside a UTF-8 continuation byte, so byte scanning is
        // UTF-8 safe while avoiding per-character allocation.
        index += 1;
        let content_start = index;
        let mut saw_escape = false;
        let mut closed = false;

        while index < bytes.len() {
            match bytes[index] {
                b'\\' => {
                    saw_escape = true;
                    // Skip the escaped byte so `\"` does not terminate this
                    // string. If the escape is truncated, the string is
                    // malformed and the outer loop will advance below.
                    index = index.saturating_add(2);
                }
                b'"' => {
                    let content_end = index;
                    index += 1;
                    closed = true;
                    if saw_escape
                        && content_end.saturating_sub(content_start) >= MIN_ESCAPED_JSON_STRING_LEN
                    {
                        strings.push(&text[content_start..content_end]);
                    }
                    break;
                }
                b'\n' | b'\r' => {
                    // JSON strings cannot span lines unescaped. Leave index
                    // on the terminator; the outer loop advances once below.
                    break;
                }
                _ => index += 1,
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
                // Shared surrogate-pair resolution (see `util`): reads a
                // following `\u` low-surrogate code unit from `chars` itself.
                decoded.push(resolve_escaped_codepoint(code, &mut chars)?);
            }
            _ => return Err(()),
        }
    }

    Ok(decoded)
}
