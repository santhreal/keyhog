use super::pipeline::push_decoded_text_chunk;
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
            if let Ok(unescaped) = json_unescape(&json_string) {
                push_decoded_text_chunk(&mut decoded_chunks, chunk, unescaped, self.name());
            }
        }
        decoded_chunks
    }
}

/// Extract JSON string values from text.
/// Returns the raw content inside JSON string quotes (including escape backslashes).
fn extract_json_strings(text: &str) -> Vec<String> {
    let mut strings = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        if let Some(quote_idx) = memchr::memchr(b'"', &bytes[index..]) {
            index += quote_idx;
        } else {
            break;
        }

        // Found opening quote
        index += 1;
        let mut content = String::with_capacity(32);
        let mut escaping = false;
        let mut closed = false;

        while index < bytes.len() {
            let current = bytes[index];
            if escaping {
                content.push(current as char);
                escaping = false;
            } else if current == b'\\' {
                escaping = true;
                content.push('\\');
            } else if current == b'"' {
                closed = true;
                index += 1;
                if content.len() >= 4 {
                    strings.push(content);
                }
                break;
            } else if current == b'\n' || current == b'\r' {
                // JSON strings cannot span lines unescaped
                break;
            } else {
                content.push(current as char);
            }
            index += 1;
        }

        if closed {
            continue;
        }

        // No closing quote found — advance to avoid infinite loop
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

fn take_hex_digits<I>(chars: &mut std::iter::Peekable<I>, count: usize) -> Result<u32, ()>
where
    I: Iterator<Item = char>,
{
    let mut value = 0u32;
    for _ in 0..count {
        let ch = chars.next().ok_or(())?;
        value = (value << 4) | ch.to_digit(16).ok_or(())?;
    }
    Ok(value)
}
