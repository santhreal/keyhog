use super::pipeline::push_decoded_text_chunk;
use super::Decoder;
use keyhog_core::Chunk;

/// Decodes `\uNNNN` and `\xNN` style unicode/hex escapes (JavaScript/Python/Java).
pub(super) struct UnicodeEscapeDecoder;

impl Decoder for UnicodeEscapeDecoder {
    fn name(&self) -> &'static str {
        "unicode-escape"
    }

    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        let mut decoded_chunks = Vec::new();
        for candidate in find_unicode_escape_candidates(&chunk.data) {
            if let Ok(text) = unicode_escape_decode(&candidate) {
                push_decoded_text_chunk(&mut decoded_chunks, chunk, text, self.name());
            }
        }
        decoded_chunks
    }
}

fn find_unicode_escape_candidates(text: &str) -> Vec<String> {
    let mut candidates = Vec::new();
    if text.contains("\\u") || text.contains("\\x") {
        candidates.push(text.to_string());
    }

    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let ch = bytes[index];
        if ch == b'"' || ch == b'\'' || ch == b'`' {
            let quote = ch;
            index += 1;
            let mut content = String::with_capacity(32);
            let mut escaping = false;
            while index < bytes.len() {
                let current = bytes[index];
                if escaping {
                    content.push('\\');
                    content.push(current as char);
                    escaping = false;
                } else if current == b'\\' {
                    escaping = true;
                } else if current == quote {
                    break;
                } else {
                    content.push(current as char);
                }
                index += 1;
            }
            if (content.contains("\\u") || content.contains("\\x")) && content.len() >= 4 {
                candidates.push(content);
            }
        }
        index += 1;
    }

    candidates
}

/// Decode `\uNNNN` and `\xNN` escape sequences.
pub fn unicode_escape_decode(input: &str) -> Result<String, ()> {
    let mut decoded = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut changed = false;

    while let Some(ch) = chars.next() {
        if ch != '\\' {
            decoded.push(ch);
            continue;
        }
        match chars.next() {
            Some('u') => {
                let code = take_hex_digits(&mut chars, 4)?;
                decoded.push(char::from_u32(code).ok_or(())?);
                changed = true;
            }
            Some('x') => {
                let code = take_hex_digits(&mut chars, 2)?;
                decoded.push(char::from_u32(code).ok_or(())?);
                changed = true;
            }
            Some(escaped) => {
                decoded.push('\\');
                decoded.push(escaped);
            }
            None => return Err(()),
        }
    }

    changed.then_some(decoded).ok_or(())
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
