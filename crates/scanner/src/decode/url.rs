use super::base64::base64_decode;
use super::hex::hex_val;
use super::pipeline::{decode_candidates, extract_encoded_values};
use super::Decoder;
use crate::context;
use keyhog_core::Chunk;

pub(super) struct UrlDecoder;
pub(super) struct QuotedPrintableDecoder;
pub(super) struct HtmlNamedEntityDecoder;
pub(super) struct HtmlNumericEntityDecoder;
pub(super) struct HexEscapeDecoder;
pub(super) struct OctalEscapeDecoder;
pub(super) struct MimeEncodedWordDecoder;
pub(super) struct UnicodeEscapeDecoder;

impl Decoder for UrlDecoder {
    fn name(&self) -> &'static str {
        "url"
    }

    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        decode_candidates(
            chunk,
            extract_encoded_values(&chunk.data)
                .into_iter()
                .filter(|candidate| candidate.contains('%'))
                .collect(),
            url_decode,
            self.name(),
        )
    }
}

impl Decoder for QuotedPrintableDecoder {
    fn name(&self) -> &'static str {
        "quoted-printable"
    }

    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        let mut decoded_chunks = Vec::new();
        let lines: Vec<&str> = chunk.data.lines().collect();
        for (line_idx, line) in lines.iter().enumerate() {
            if context::is_false_positive_context(&lines, line_idx, chunk.metadata.path.as_deref())
            {
                continue;
            }
            let mut candidates = extract_encoded_values(line);
            let trimmed = line.trim();
            if trimmed.contains('=') && !trimmed.is_empty() {
                candidates.push(trimmed.to_string());
            }
            decoded_chunks.extend(decode_candidates(
                chunk,
                candidates
                    .into_iter()
                    .filter(|candidate| candidate.contains('='))
                    .collect(),
                quoted_printable_decode,
                self.name(),
            ));
        }
        decoded_chunks
    }
}

macro_rules! simple_decoder {
    ($decoder:ty, $name:literal, $filter:expr, $decode:ident) => {
        impl Decoder for $decoder {
            fn name(&self) -> &'static str {
                $name
            }

            fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
                let mut candidates = extract_encoded_values(&chunk.data);
                let trimmed = chunk.data.trim();
                if ($filter)(trimmed) && !trimmed.is_empty() {
                    candidates.push(trimmed.to_string());
                }
                decode_candidates(
                    chunk,
                    candidates
                        .into_iter()
                        .filter(|candidate| ($filter)(candidate))
                        .collect(),
                    $decode,
                    self.name(),
                )
            }
        }
    };
}

simple_decoder!(
    HtmlNamedEntityDecoder,
    "html-named-entity",
    |s: &str| s.contains('&'),
    html_named_entity_decode
);
simple_decoder!(
    HtmlNumericEntityDecoder,
    "html-numeric-entity",
    |s: &str| s.contains("&#"),
    html_numeric_entity_decode
);
simple_decoder!(
    HexEscapeDecoder,
    "hex-escape",
    |s: &str| s.contains("\\x"),
    hex_escape_decode
);
simple_decoder!(
    OctalEscapeDecoder,
    "octal-escape",
    contains_octal_escape,
    octal_escape_decode
);
simple_decoder!(
    UnicodeEscapeDecoder,
    "unicode-escape",
    |s: &str| s.contains("\\u") || s.contains("\\x"),
    unicode_escape_decode
);

impl Decoder for MimeEncodedWordDecoder {
    fn name(&self) -> &'static str {
        "mime-encoded-word"
    }

    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        let mut candidates = Vec::new();
        for line in chunk.data.lines() {
            candidates.extend(find_mime_encoded_words(line));
        }
        decode_candidates(chunk, candidates, mime_encoded_word_decode, self.name())
    }
}

fn percent_decode(input: &str) -> Result<String, ()> {
    let mut bytes = Vec::with_capacity(input.len());
    let mut index = 0;
    let input_bytes = input.as_bytes();
    while index < input_bytes.len() {
        if let Some(pct_idx) = memchr::memchr(b'%', &input_bytes[index..]) {
            bytes.extend_from_slice(&input_bytes[index..index + pct_idx]);
            index += pct_idx;

            if index + 2 < input_bytes.len() {
                let high = hex_val(input_bytes[index + 1])?;
                let low = hex_val(input_bytes[index + 2])?;
                bytes.push((high << 4) | low);
                index += 3;
            } else {
                bytes.push(b'%');
                index += 1;
            }
        } else {
            bytes.extend_from_slice(&input_bytes[index..]);
            break;
        }
    }
    String::from_utf8(bytes).map_err(|_| ())
}

fn url_decode(input: &str) -> Result<String, ()> {
    let decoded = percent_decode(input)?;
    if contains_percent_escape(&decoded) {
        percent_decode(&decoded)
    } else {
        Ok(decoded)
    }
}

fn contains_percent_escape(input: &str) -> bool {
    input
        .as_bytes()
        .windows(3)
        .any(|window| window[0] == b'%' && hex_val(window[1]).is_ok() && hex_val(window[2]).is_ok())
}

fn quoted_printable_decode(input: &str) -> Result<String, ()> {
    let mut bytes = Vec::with_capacity(input.len());
    let mut index = 0;
    let input_bytes = input.as_bytes();
    while index < input_bytes.len() {
        if let Some(eq_idx) = memchr::memchr(b'=', &input_bytes[index..]) {
            bytes.extend_from_slice(&input_bytes[index..index + eq_idx]);
            index += eq_idx;

            if index + 2 < input_bytes.len() {
                if input_bytes[index + 1] == b'\r' && input_bytes[index + 2] == b'\n' {
                    index += 3;
                    continue;
                }
                let high = hex_val(input_bytes[index + 1])?;
                let low = hex_val(input_bytes[index + 2])?;
                bytes.push((high << 4) | low);
                index += 3;
            } else {
                bytes.push(b'=');
                index += 1;
            }
        } else {
            bytes.extend_from_slice(&input_bytes[index..]);
            break;
        }
    }
    String::from_utf8(bytes).map_err(|_| ())
}

fn html_named_entity_decode(input: &str) -> Result<String, ()> {
    let mut decoded = String::with_capacity(input.len());
    let mut changed = false;
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch != '&' {
            decoded.push(ch);
            continue;
        }

        let mut entity = String::new();
        while let Some(&next) = chars.peek() {
            entity.push(next);
            chars.next();
            if next == ';' || entity.len() > 10 {
                break;
            }
        }

        let replacement = match entity.as_str() {
            "amp;" => Some('&'),
            "lt;" => Some('<'),
            "gt;" => Some('>'),
            "quot;" => Some('"'),
            "apos;" => Some('\''),
            "nbsp;" => Some('\u{00A0}'),
            _ => None,
        };

        if let Some(replacement) = replacement {
            decoded.push(replacement);
            changed = true;
        } else {
            decoded.push('&');
            decoded.push_str(&entity);
        }
    }

    changed.then_some(decoded).ok_or(())
}

fn html_numeric_entity_decode(input: &str) -> Result<String, ()> {
    let mut decoded = String::with_capacity(input.len());
    let mut changed = false;
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch != '&' || chars.peek() != Some(&'#') {
            decoded.push(ch);
            continue;
        }

        chars.next();
        let is_hex = matches!(chars.peek(), Some('x') | Some('X'));
        if is_hex {
            chars.next();
        }

        let mut digits = String::new();
        while let Some(&next) = chars.peek() {
            if next == ';' {
                chars.next();
                break;
            }
            if (is_hex && next.is_ascii_hexdigit()) || (!is_hex && next.is_ascii_digit()) {
                digits.push(next);
                chars.next();
            } else {
                decoded.push('&');
                decoded.push('#');
                if is_hex {
                    decoded.push('x');
                }
                decoded.push_str(&digits);
                decoded.push(next);
                chars.next();
                digits.clear();
                break;
            }
        }

        if digits.is_empty() {
            decoded.push('&');
            decoded.push('#');
            if is_hex {
                decoded.push('x');
            }
            continue;
        }

        let radix = if is_hex { 16 } else { 10 };
        let code = u32::from_str_radix(&digits, radix).map_err(|_| ())?;
        let replacement = char::from_u32(code).ok_or(())?;
        decoded.push(replacement);
        changed = true;
    }

    changed.then_some(decoded).ok_or(())
}

fn hex_escape_decode(input: &str) -> Result<String, ()> {
    let mut decoded = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut changed = false;

    while let Some(ch) = chars.next() {
        if ch != '\\' || chars.peek() != Some(&'x') {
            decoded.push(ch);
            continue;
        }

        chars.next();
        let high = chars.next().ok_or(())?.to_digit(16).ok_or(())?;
        let low = chars.next().ok_or(())?.to_digit(16).ok_or(())?;
        decoded.push(char::from(((high << 4) | low) as u8));
        changed = true;
    }

    changed.then_some(decoded).ok_or(())
}

fn octal_escape_decode(input: &str) -> Result<String, ()> {
    let mut decoded = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut changed = false;

    while let Some(ch) = chars.next() {
        if ch != '\\' {
            decoded.push(ch);
            continue;
        }

        let Some(&next) = chars.peek() else {
            return Err(());
        };
        if !('0'..='7').contains(&next) {
            decoded.push(ch);
            continue;
        }

        let mut value = 0u8;
        for _ in 0..3 {
            let digit = chars.next().ok_or(())?;
            value = (value << 3) | digit.to_digit(8).ok_or(())? as u8;
        }
        decoded.push(char::from(value));
        changed = true;
    }

    changed.then_some(decoded).ok_or(())
}

fn contains_octal_escape(input: &str) -> bool {
    let bytes = input.as_bytes();
    bytes.windows(4).any(|window| {
        window[0] == b'\\'
            && (b'0'..=b'7').contains(&window[1])
            && (b'0'..=b'7').contains(&window[2])
            && (b'0'..=b'7').contains(&window[3])
    })
}

fn mime_encoded_word_decode(input: &str) -> Result<String, ()> {
    if !input.starts_with("=?") || !input.ends_with("?=") {
        return Err(());
    }
    let inner = &input[2..input.len() - 2];
    let mut parts = inner.splitn(3, '?');
    let _charset = parts.next().ok_or(())?;
    let encoding = parts.next().ok_or(())?;
    let encoded = parts.next().ok_or(())?;
    let bytes = match encoding {
        "B" | "b" => base64_decode(encoded)?,
        "Q" | "q" => mime_q_decode(encoded)?,
        _ => return Err(()),
    };
    String::from_utf8(bytes).map_err(|_| ())
}

fn mime_q_decode(input: &str) -> Result<Vec<u8>, ()> {
    let normalized = input.replace('_', " ");
    let mut bytes = Vec::with_capacity(normalized.len());
    let mut index = 0;
    let input_bytes = normalized.as_bytes();
    while index < input_bytes.len() {
        match input_bytes[index] {
            b'=' if index + 2 < input_bytes.len() => {
                let high = hex_val(input_bytes[index + 1])?;
                let low = hex_val(input_bytes[index + 2])?;
                bytes.push((high << 4) | low);
                index += 3;
            }
            byte => {
                bytes.push(byte);
                index += 1;
            }
        }
    }
    Ok(bytes)
}

fn find_mime_encoded_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut offset = 0;
    while let Some(start) = line[offset..].find("=?") {
        let absolute_start = offset + start;
        if let Some(end) = line[absolute_start + 2..].find("?=") {
            let absolute_end = absolute_start + 2 + end + 2;
            words.push(line[absolute_start..absolute_end].to_string());
            offset = absolute_end;
        } else {
            break;
        }
    }
    words
}

fn unicode_escape_decode(input: &str) -> Result<String, ()> {
    let mut decoded_text = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            decoded_text.push(ch);
            continue;
        }
        match chars.next() {
            Some('u') => {
                let code = take_hex_digits(&mut chars, 4)?;
                decoded_text.push(char::from_u32(code).ok_or(())?);
            }
            Some('x') => {
                let code = take_hex_digits(&mut chars, 2)?;
                decoded_text.push(char::from_u32(code).ok_or(())?);
            }
            Some(escaped) => decoded_text.push(escaped),
            None => return Err(()),
        }
    }
    Ok(decoded_text)
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
