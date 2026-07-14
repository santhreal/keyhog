use super::limits::{MAX_HEX_INPUT_LEN, MIN_HEX_CANDIDATE_LEN};
use super::pipeline::{decode_candidate_refs_exact, with_extracted_value_spans, ExtractedValue};
use super::{Decoder, EncodedString};
use keyhog_core::Chunk;

pub(super) struct HexDecoder;

impl Decoder for HexDecoder {
    fn name(&self) -> &'static str {
        "hex"
    }

    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        with_extracted_value_spans(&chunk.data, |candidates| {
            decode_candidate_refs_exact(
                chunk,
                candidates.iter().filter_map(|candidate| {
                    is_hex_candidate(candidate, MIN_HEX_CANDIDATE_LEN).then_some(candidate)
                }),
                |value| {
                    hex_decode(value).and_then(|decoded| String::from_utf8(decoded).map_err(|_| ()))
                },
                self.name(),
            )
        })
    }
}

/// Find every hex substring of at least `min_length` bytes in `text`, returned
/// as decodable [`EncodedString`] spans.
pub fn find_hex_strings(text: &str, min_length: usize) -> Vec<EncodedString> {
    find_hex_string_spans(text, min_length)
        .into_iter()
        .map(|candidate| EncodedString {
            value: candidate.value,
        })
        .collect()
}

fn find_hex_string_spans(text: &str, min_length: usize) -> Vec<ExtractedValue> {
    let mut results = Vec::new();
    with_extracted_value_spans(text, |candidates| {
        for candidate in candidates {
            if is_hex_candidate(candidate, min_length) {
                results.push(candidate.clone());
            }
        }
    });
    results
}

fn is_hex_candidate(candidate: &ExtractedValue, min_length: usize) -> bool {
    // Hex literals in firmware dumps and config files commonly use `_`
    // every 2/4/8 chars for readability (`A1_B2_C3_...`). Tolerate those
    // when validating - audit class #5 (release-2026-04-26) noted the
    // previous all-hex check missed this evasion entirely. Validate over
    // the raw bytes (hex digits and `_` are all single-byte ASCII, so the
    // non-`_` byte count equals the decoded-input char count) instead of
    // allocating a throwaway cleaned `String` per candidate on the hot
    // decode path; `hex_decode` does the final underscore stripping.
    let hex_len = candidate.value.bytes().filter(|byte| *byte != b'_').count();
    hex_len >= min_length
        && hex_len.is_multiple_of(2)
        && candidate
            .value
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_hexdigit())
}

/// Decode a hex string (optionally `_`-separated), bounded to
/// `MAX_HEX_INPUT_LEN` bytes for DoS safety. `Err(())` on odd length or
/// non-hex input.
#[allow(clippy::result_unit_err)]
pub fn hex_decode(input: &str) -> Result<Vec<u8>, ()> {
    if !input.as_bytes().contains(&b'_') {
        if !input.len().is_multiple_of(2) || input.len() > MAX_HEX_INPUT_LEN {
            return Err(());
        }
        return hex_simd::decode_to_vec(input.as_bytes()).map_err(|_| ());
    }

    let cleaned: String = input.chars().filter(|c| *c != '_').collect();
    if !cleaned.len().is_multiple_of(2) || cleaned.len() > MAX_HEX_INPUT_LEN {
        return Err(());
    }
    hex_simd::decode_to_vec(cleaned.as_bytes()).map_err(|_| ())
}
