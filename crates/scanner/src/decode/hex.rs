use super::pipeline::{
    extract_encoded_value_spans, push_decoded_text_chunk_spliced_at, ExtractedValue,
};
use super::{Decoder, EncodedString};
use keyhog_core::Chunk;

pub(super) struct HexDecoder;

impl Decoder for HexDecoder {
    fn name(&self) -> &'static str {
        "hex"
    }

    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        let mut decoded_chunks = Vec::new();
        // Floor lowered from 32→16 hex chars (8 decoded bytes) so
        // short API keys encode-through in `encoding_explosion_runner`.
        for hex_match in find_hex_string_spans(&chunk.data, 16) {
            if let Ok(decoded) = hex_decode(&hex_match.value) {
                if let Ok(text) = String::from_utf8(decoded) {
                    // Splice over the *original* encoded blob (with `_` if present)
                    // so companion context survives.
                    push_decoded_text_chunk_spliced_at(
                        &mut decoded_chunks,
                        chunk,
                        hex_match.span(),
                        &hex_match.value,
                        text,
                        self.name(),
                    );
                }
            }
        }
        decoded_chunks
    }
}

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
    for candidate in extract_encoded_value_spans(text) {
        // Hex literals in firmware dumps and config files commonly use `_`
        // every 2/4/8 chars for readability (`A1_B2_C3_...`). Tolerate those
        // when validating - audit class #5 (release-2026-04-26) noted the
        // previous all-hex check missed this evasion entirely. Validate over
        // the raw bytes (hex digits and `_` are all single-byte ASCII, so the
        // non-`_` byte count equals the decoded-input char count) instead of
        // allocating a throwaway cleaned `String` per candidate on the hot
        // decode path; `hex_decode` does the final underscore stripping.
        let hex_len = candidate.value.bytes().filter(|byte| *byte != b'_').count();
        if hex_len >= min_length
            && hex_len.is_multiple_of(2)
            && candidate
                .value
                .bytes()
                .all(|byte| byte == b'_' || byte.is_ascii_hexdigit())
        {
            results.push(candidate);
        }
    }
    results
}

/// Maximum hex input length we'll decode (prevents OOM from malicious input).
const MAX_HEX_INPUT_LEN: usize = 32 * 1024 * 1024; // 32 MB -> 16 MB decoded

#[allow(clippy::result_unit_err)]
pub fn hex_decode(input: &str) -> Result<Vec<u8>, ()> {
    let cleaned: String = input.chars().filter(|c| *c != '_').collect();
    if !cleaned.len().is_multiple_of(2) || cleaned.len() > MAX_HEX_INPUT_LEN {
        return Err(());
    }
    hex_simd::decode_to_vec(&cleaned).map_err(|_| ())
}

pub(super) fn hex_val(byte: u8) -> Result<u8, ()> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(()),
    }
}
