use super::pipeline::{
    ExtractedValue, extract_encoded_value_spans, push_decoded_text_chunk_spliced_at,
};
use super::{Decoder, EncodedString};
use keyhog_core::Chunk;

pub(super) struct Base64Decoder;

impl Decoder for Base64Decoder {
    fn name(&self) -> &'static str {
        "base64"
    }

    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        let mut decoded_chunks = Vec::new();
        // Floor lowered from 20→12 so short contract credentials (7–15
        // chars) survive encode-through in `encoding_explosion_runner`.
        // `extract_encoded_values` already rejects noise shorter than 4.
        for b64_match in find_classified_base64_string_spans(&chunk.data, 12) {
            if let Ok(decoded) =
                base64_decode_with_variant(&b64_match.value.value, b64_match.variant)
            {
                if let Ok(text) = String::from_utf8(decoded) {
                    // Splice the decoded text back over the original
                    // base64 blob in the parent so companion context
                    // (e.g. `aws_secret = "…"`) stays adjacent to the
                    // decoded credential. Without this the decoded
                    // chunk is bare-bytes-only and every detector
                    // anchored on an adjacent keyword misses.
                    push_decoded_text_chunk_spliced_at(
                        &mut decoded_chunks,
                        chunk,
                        b64_match.span(),
                        &b64_match.value.value,
                        text,
                        self.name(),
                    );
                }
            }
        }
        decoded_chunks
    }
}

pub(super) struct Z85Decoder;

impl Decoder for Z85Decoder {
    fn name(&self) -> &'static str {
        "z85"
    }

    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        let mut decoded_chunks = Vec::new();
        for z_match in find_z85_string_spans(&chunk.data, 20) {
            if let Ok(decoded) = z85_decode(&z_match.value) {
                if let Ok(text) = String::from_utf8(decoded) {
                    push_decoded_text_chunk_spliced_at(
                        &mut decoded_chunks,
                        chunk,
                        z_match.span(),
                        &z_match.value,
                        text.trim_end_matches('\0').to_string(),
                        self.name(),
                    );
                }
            }
        }
        decoded_chunks
    }
}

#[derive(Clone, Copy)]
enum Base64Variant {
    Standard,
    StandardNoPad,
    UrlSafe,
    UrlSafeNoPad,
}

struct Base64ExtractedValue {
    value: ExtractedValue,
    variant: Base64Variant,
}

impl Base64ExtractedValue {
    fn span(&self) -> Option<(usize, usize)> {
        self.value.span()
    }
}

#[derive(Clone, Copy)]
pub(crate) struct StandardBase64Shape {
    pub(crate) has_padding: bool,
    pub(crate) length_multiple_of_four: bool,
    pub(crate) has_plus: bool,
    pub(crate) has_slash: bool,
    pub(crate) distinct_alnum: u32,
}

pub(crate) fn is_base64_candidate_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_')
}

pub(crate) fn is_standard_base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
}

pub(crate) fn standard_base64_shape(candidate: &str) -> Option<StandardBase64Shape> {
    match classify_base64(candidate)? {
        Base64Variant::Standard | Base64Variant::StandardNoPad => {}
        Base64Variant::UrlSafe | Base64Variant::UrlSafeNoPad => return None,
    }

    let mut has_plus = false;
    let mut has_slash = false;
    let mut seen = [false; 256];
    let mut distinct_alnum = 0u32;

    for byte in candidate.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' => {
                if !seen[byte as usize] {
                    seen[byte as usize] = true;
                    distinct_alnum += 1;
                }
            }
            b'+' => has_plus = true,
            b'/' => has_slash = true,
            b'=' => {}
            _ => return None,
        }
    }

    Some(StandardBase64Shape {
        has_padding: candidate.ends_with('='),
        length_multiple_of_four: candidate.len().is_multiple_of(4),
        has_plus,
        has_slash,
        distinct_alnum,
    })
}

pub fn find_base64_strings(text: &str, min_length: usize) -> Vec<EncodedString> {
    find_base64_string_spans(text, min_length)
        .into_iter()
        .map(|candidate| EncodedString {
            value: candidate.value,
        })
        .collect()
}

fn find_base64_string_spans(text: &str, min_length: usize) -> Vec<ExtractedValue> {
    let mut results = Vec::new();

    for candidate in find_classified_base64_string_spans(text, min_length) {
        results.push(candidate.value);
    }
    results
}

fn find_classified_base64_string_spans(text: &str, min_length: usize) -> Vec<Base64ExtractedValue> {
    let mut results = Vec::new();

    for candidate in extract_encoded_value_spans(text) {
        if candidate.value.len() < min_length
            || !candidate.value.bytes().all(is_base64_candidate_byte)
        {
            continue;
        }
        if let Some(variant) = classify_base64(&candidate.value) {
            results.push(Base64ExtractedValue {
                value: candidate,
                variant,
            });
        }
    }
    results
}

fn classify_base64(candidate: &str) -> Option<Base64Variant> {
    if !has_valid_base64_padding(candidate) {
        return None;
    }

    let has_standard = candidate.contains('+') || candidate.contains('/');
    let has_urlsafe = candidate.contains('-') || candidate.contains('_');
    if has_standard && has_urlsafe {
        return None;
    }

    let padded = candidate.contains('=');
    match (has_urlsafe, padded, candidate.len() % 4) {
        (_, true, 0) => Some(if has_urlsafe {
            Base64Variant::UrlSafe
        } else {
            Base64Variant::Standard
        }),
        (_, true, _) => None,
        (_, false, 1) => None,
        (true, false, _) => Some(Base64Variant::UrlSafeNoPad),
        (false, false, 0) => Some(Base64Variant::Standard),
        (false, false, _) => Some(Base64Variant::StandardNoPad),
    }
}

fn has_valid_base64_padding(candidate: &str) -> bool {
    let first_padding = match candidate.find('=') {
        Some(index) => index,
        None => return true,
    };

    let padding = &candidate[first_padding..];
    first_padding > 0
        && padding.len() <= 2
        && padding.bytes().all(|byte| byte == b'=')
        && candidate[..first_padding].bytes().all(|byte| byte != b'=')
}

/// Maximum base64 input length we'll decode (prevents OOM from malicious input).
pub(crate) const MAX_BASE64_INPUT_LEN: usize = 16 * 1024 * 1024; // 16 MB -> ~12 MB decoded

#[allow(clippy::result_unit_err)]
pub fn base64_decode(input: &str) -> Result<Vec<u8>, ()> {
    if input.len() > MAX_BASE64_INPUT_LEN {
        return Err(());
    }

    let variant = classify_base64(input).ok_or(())?;
    base64_decode_with_variant(input, variant)
}

#[allow(clippy::result_unit_err)]
fn base64_decode_with_variant(input: &str, variant: Base64Variant) -> Result<Vec<u8>, ()> {
    match variant {
        Base64Variant::Standard => base64_simd::STANDARD.decode_to_vec(input.as_bytes()),
        Base64Variant::StandardNoPad => {
            base64_simd::STANDARD_NO_PAD.decode_to_vec(input.as_bytes())
        }
        Base64Variant::UrlSafe => base64_simd::URL_SAFE.decode_to_vec(input.as_bytes()),
        Base64Variant::UrlSafeNoPad => base64_simd::URL_SAFE_NO_PAD.decode_to_vec(input.as_bytes()),
    }
    .map_err(|_| ())
}

fn find_z85_string_spans(text: &str, min_length: usize) -> Vec<ExtractedValue> {
    let mut results = Vec::new();
    let is_z85_char =
        |ch: char| ch.is_ascii_alphanumeric() || ".-:+=^!/*?&<>()[]{}@%$#".contains(ch);

    for candidate in extract_encoded_value_spans(text) {
        let cleaned = if candidate.value.chars().any(char::is_whitespace) {
            candidate
                .value
                .chars()
                .filter(|ch| !ch.is_whitespace())
                .collect()
        } else {
            candidate.value
        };
        if cleaned.len() >= min_length
            && cleaned.len().is_multiple_of(5)
            && cleaned.chars().all(is_z85_char)
        {
            results.push(ExtractedValue {
                value: cleaned,
                start: candidate.start,
                end: candidate.end,
            });
        }
    }
    results
}

/// Maximum Z85 input length we'll decode.
const MAX_Z85_INPUT_LEN: usize = 16 * 1024 * 1024;

#[allow(clippy::result_unit_err)]
pub fn z85_decode(input: &str) -> Result<Vec<u8>, ()> {
    if !input.len().is_multiple_of(5) || input.len() > MAX_Z85_INPUT_LEN {
        return Err(());
    }
    let mut decoded = Vec::with_capacity(input.len() * 4 / 5);
    let bytes = input.as_bytes();
    for chunk in bytes.chunks_exact(5) {
        let mut value = 0u64;
        for &byte in chunk {
            value = value * 85 + z85_val(byte)? as u64;
        }
        if value > u32::MAX as u64 {
            return Err(());
        }
        let value = value as u32;
        decoded.push((value >> 24) as u8);
        decoded.push((value >> 16) as u8);
        decoded.push((value >> 8) as u8);
        decoded.push(value as u8);
    }
    Ok(decoded)
}

fn z85_val(byte: u8) -> Result<u8, ()> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'g'..=b'z' => Ok(byte - b'g' + 16),
        b'A'..=b'Z' => Ok(byte - b'A' + 36),
        b'.' => Ok(62),
        b'-' => Ok(63),
        b':' => Ok(64),
        b'+' => Ok(65),
        b'=' => Ok(66),
        b'^' => Ok(67),
        b'!' => Ok(68),
        b'/' => Ok(69),
        b'*' => Ok(70),
        b'?' => Ok(71),
        b'&' => Ok(72),
        b'<' => Ok(73),
        b'>' => Ok(74),
        b'(' => Ok(75),
        b')' => Ok(76),
        b'[' => Ok(77),
        b']' => Ok(78),
        b'{' => Ok(79),
        b'}' => Ok(80),
        b'@' => Ok(81),
        b'%' => Ok(82),
        b'$' => Ok(83),
        b'#' => Ok(84),
        _ => Err(()),
    }
}
