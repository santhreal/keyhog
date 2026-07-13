use super::pipeline::{
    push_decoded_text_chunk_spliced_at, with_extracted_value_spans, ExtractedValue,
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
        visit_classified_base64_string_spans(&chunk.data, 12, |b64_match, variant| {
            if let Ok(decoded) = base64_decode_with_variant(&b64_match.value, variant) {
                // LAW10: failed trial decode means this span is not valid base64; recall-preserving (the original chunk stays scanned unchanged).
                // Pre-UTF8-gate decode-through: a base64 blob whose decoded
                // bytes are a gzip/zlib stream (`secret -> gzip -> base64`
                // exfil) is not valid UTF-8, so the plain `from_utf8` gate
                // below would drop it. Try a bounded inflate first; when it
                // yields UTF-8 text, emit that so the compressed credential is
                // rescanned. Non-container / malformed / binary-output bytes
                // fall through to the normal UTF-8 path unchanged.
                if let Some(inflated) = crate::decode::inflate::try_inflate_to_text(&decoded) {
                    push_decoded_text_chunk_spliced_at(
                        &mut decoded_chunks,
                        chunk,
                        b64_match.span(),
                        &b64_match.value,
                        inflated,
                        self.name(),
                    );
                } else if let Ok(text) = String::from_utf8(decoded) {
                    // LAW10: non-UTF8 decoded bytes are not source text; recall-preserving (the original encoded text stays scanned unchanged).
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
                        &b64_match.value,
                        text,
                        self.name(),
                    );
                }
            }
        });
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
        visit_z85_string_spans(&chunk.data, 20, |z_match, value| {
            if let Ok(decoded) = z85_decode(value.as_ref()) {
                // LAW10: failed trial decode means this span is not valid z85; recall-preserving (the original chunk stays scanned unchanged).
                if let Ok(text) = String::from_utf8(decoded) {
                    // LAW10: non-UTF8 decoded bytes are not source text; recall-preserving (the original encoded text stays scanned unchanged).
                    push_decoded_text_chunk_spliced_at(
                        &mut decoded_chunks,
                        chunk,
                        z_match.span(),
                        value.as_ref(),
                        text.trim_end_matches('\0').to_string(),
                        self.name(),
                    );
                }
            }
        });
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

#[derive(Clone, Copy)]
pub(crate) struct StandardBase64Shape {
    pub(crate) has_padding: bool,
    pub(crate) length_multiple_of_four: bool,
    pub(crate) has_plus: bool,
    pub(crate) has_slash: bool,
    pub(crate) distinct_alnum: u32,
}

/// Whether a byte can appear in a standard or URL-safe base64 string: ASCII
/// alphanumeric or one of `+ / = - _`.
pub fn is_base64_candidate_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_')
}

pub(crate) fn is_standard_base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
}

/// `true` iff `value` contains an `=` that is NOT valid base64 padding.
///
/// In base64 the only legal `=` is trailing padding, of which there are at most
/// two. So a non-padding `=` is either a third (or later) trailing `=`, or any
/// `=` that appears before the trailing padding run, both signal that the `=`
/// is an assignment / key-value separator rather than base64 padding. This is
/// the discriminator the isolated-bare entropy path uses to tell an opaque
/// base64 token (`AbC123…==`, kept) from an embedded `key=value` fragment
/// (rejected). `=` is single-byte ASCII, so the prefix slice is always on a char
/// boundary regardless of any multibyte content before the padding run.
pub(crate) fn contains_non_padding_equals(value: &str) -> bool {
    let padding = value.bytes().rev().take_while(|&b| b == b'=').count();
    padding > 2 || value[..value.len() - padding].contains('=')
}

pub(crate) fn standard_base64_shape(candidate: &str) -> Option<StandardBase64Shape> {
    let facts = scan_base64_candidate(candidate)?;
    let has_urlsafe = facts.has_urlsafe;
    if facts.has_standard && has_urlsafe {
        return None;
    }
    let remainder = candidate.len() % 4;
    if has_urlsafe || (facts.padded && remainder != 0) || (!facts.padded && remainder == 1) {
        return None;
    }

    Some(StandardBase64Shape {
        has_padding: facts.padded,
        length_multiple_of_four: candidate.len().is_multiple_of(4),
        has_plus: facts.has_plus,
        has_slash: facts.has_slash,
        distinct_alnum: facts.distinct_alnum,
    })
}

/// Find every base64/base64url substring of at least `min_length` bytes in
/// `text`, returned as decodable [`EncodedString`] spans.
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

    visit_classified_base64_string_spans(text, min_length, |candidate, _variant| {
        results.push(candidate.clone());
    });
    results
}

fn visit_classified_base64_string_spans(
    text: &str,
    min_length: usize,
    mut visit: impl FnMut(&ExtractedValue, Base64Variant),
) {
    with_extracted_value_spans(text, |candidates| {
        for candidate in candidates {
            if candidate.value.len() < min_length
                || !candidate.value.bytes().all(is_base64_candidate_byte)
            {
                continue;
            }
            if let Some(variant) = classify_base64(&candidate.value) {
                visit(candidate, variant);
            }
        }
    });
}

fn classify_base64(candidate: &str) -> Option<Base64Variant> {
    let facts = scan_base64_candidate(candidate)?;
    let has_standard = facts.has_standard;
    let has_urlsafe = facts.has_urlsafe;
    if has_standard && has_urlsafe {
        return None;
    }

    match (has_urlsafe, facts.padded, candidate.len() % 4) {
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

#[derive(Clone, Copy)]
struct Base64CandidateFacts {
    has_standard: bool,
    has_urlsafe: bool,
    padded: bool,
    has_plus: bool,
    has_slash: bool,
    distinct_alnum: u32,
}

fn scan_base64_candidate(candidate: &str) -> Option<Base64CandidateFacts> {
    let mut facts = Base64CandidateFacts {
        has_standard: false,
        has_urlsafe: false,
        padded: false,
        has_plus: false,
        has_slash: false,
        distinct_alnum: 0,
    };
    let mut seen_alnum = [false; 256];
    let mut padding_len = 0usize;
    for (index, byte) in candidate.bytes().enumerate() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' if !facts.padded => {
                if !seen_alnum[byte as usize] {
                    seen_alnum[byte as usize] = true;
                    facts.distinct_alnum += 1;
                }
            }
            b'+' if !facts.padded => {
                facts.has_standard = true;
                facts.has_plus = true;
            }
            b'/' if !facts.padded => {
                facts.has_standard = true;
                facts.has_slash = true;
            }
            b'-' | b'_' if !facts.padded => facts.has_urlsafe = true,
            b'=' => {
                if index == 0 {
                    return None;
                }
                facts.padded = true;
                padding_len += 1;
                if padding_len > 2 {
                    return None;
                }
            }
            _ if facts.padded => return None,
            _ => return None,
        }
    }
    Some(facts)
}

/// Maximum base64 input length we'll decode (prevents OOM from malicious input).
pub(crate) const MAX_BASE64_INPUT_LEN: usize = 16 * 1024 * 1024; // 16 MB -> ~12 MB decoded

/// Decode a standard or URL-safe base64 string, bounded to
/// `MAX_BASE64_INPUT_LEN` bytes for DoS safety. `Err(())` on invalid or
/// over-length input.
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

fn visit_z85_string_spans(
    text: &str,
    min_length: usize,
    mut visit: impl FnMut(&ExtractedValue, std::borrow::Cow<'_, str>),
) {
    let is_z85_char =
        |ch: char| ch.is_ascii_alphanumeric() || ".-:+=^!/*?&<>()[]{}@%$#".contains(ch);
    with_extracted_value_spans(text, |candidates| {
        for candidate in candidates {
            let value = if candidate.value.chars().any(char::is_whitespace) {
                std::borrow::Cow::Owned(
                    candidate
                        .value
                        .chars()
                        .filter(|ch| !ch.is_whitespace())
                        .collect(),
                )
            } else {
                std::borrow::Cow::Borrowed(candidate.value.as_str())
            };
            if value.len() >= min_length
                && value.len().is_multiple_of(5)
                && value.chars().all(is_z85_char)
            {
                visit(candidate, value);
            }
        }
    });
}

/// Maximum Z85 input length we'll decode.
const MAX_Z85_INPUT_LEN: usize = 16 * 1024 * 1024;

/// Decode a Z85-encoded string (length must be a multiple of 5), bounded to
/// `MAX_Z85_INPUT_LEN` bytes for DoS safety. `Err(())` on invalid input.
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
