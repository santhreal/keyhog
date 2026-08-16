use super::limits::{MAX_HEX_INPUT_LEN, MIN_HEX_CANDIDATE_LEN};
use super::pipeline::{with_extracted_value_spans, DecodedReplacementBatcher, ExtractedValue};
use super::{DecodeAdmissionSketch, DecodeOutputSink, Decoder, EncodedString};
use keyhog_core::Chunk;
use zeroize::{Zeroize, Zeroizing};
pub(super) struct HexDecoder;

impl Decoder for HexDecoder {
    fn name(&self) -> &'static str {
        "hex"
    }

    fn admission_sketch(&self, chunk: &Chunk) -> DecodeAdmissionSketch {
        with_extracted_value_spans(&chunk.data, |candidates| {
            let mut count = 0usize;
            let mut bytes = 0usize;
            for candidate in candidates
                .iter()
                .filter(|candidate| is_hex_candidate(candidate, MIN_HEX_CANDIDATE_LEN))
            {
                count = count.saturating_add(1);
                bytes = bytes.saturating_add(candidate.value.len());
            }
            if count == 0 {
                DecodeAdmissionSketch::NONE
            } else {
                DecodeAdmissionSketch::possible(DecodeAdmissionSketch::HEX, count, bytes)
            }
        })
    }

    fn decode_chunk_into(&self, chunk: &Chunk, sink: &mut dyn DecodeOutputSink) {
        let mut batch = DecodedReplacementBatcher::new(sink, chunk, self.name());
        let mut open = true;
        with_extracted_value_spans(&chunk.data, |candidates| {
            for candidate in candidates
                .iter()
                .filter(|candidate| is_hex_candidate(candidate, MIN_HEX_CANDIDATE_LEN))
            {
                if !open {
                    break;
                }
                let Some(text) = try_decode_hex_candidate_to_utf8(&candidate.value) else {
                    // LAW10: recall-preserving: the original encoded bytes still
                    // take the whole-chunk scan path unchanged; this trial decode failed.
                    continue;
                };
                let (start, end) = candidate.span();
                open = batch.push(start, end, text);
            }
        });
        if open {
            batch.finish();
        }
    }
}

/// Decode a hex string into a stack-allocated buffer (up to 128 decoded bytes).
/// Intermediate buffers are zeroized on drop.
fn hex_decode_to_stack_buf(input: &str, stack_dst: &mut [u8; 128]) -> Result<usize, ()> {
    if !input.as_bytes().contains(&b'_') {
        if !input.len().is_multiple_of(2) || input.len() > 256 {
            return Err(());
        }
        let len = input.len() / 2;
        hex_simd::decode(
            input.as_bytes(),
            hex_simd::Out::from_slice(&mut stack_dst[..len]),
        )
        .map_err(|_| ())?;
        Ok(len)
    } else {
        let mut cleaned = Zeroizing::new([0u8; 256]);
        let mut len = 0usize;
        for &b in input.as_bytes() {
            if b != b'_' {
                if len >= 256 {
                    return Err(());
                }
                cleaned[len] = b;
                len += 1;
            }
        }
        if !len.is_multiple_of(2) {
            return Err(());
        }
        let decoded_len = len / 2;
        hex_simd::decode(
            &cleaned[..len],
            hex_simd::Out::from_slice(&mut stack_dst[..decoded_len]),
        )
        .map_err(|_| ())?;
        Ok(decoded_len)
    }
}

/// Fast-path trial decode and UTF-8 validation for hex candidate strings.
///
/// Decodes into a stack buffer for inputs up to 256 bytes (covering standard 16-byte
/// MD5 and 32-byte SHA256 hex string candidates) to validate UTF-8 without heap
/// allocations for binary hash tokens.
fn try_decode_hex_candidate_to_utf8(value: &str) -> Option<String> {
    if value.len() <= 256 {
        let mut stack_dst = Zeroizing::new([0u8; 128]);
        let decoded_len = hex_decode_to_stack_buf(value, &mut *stack_dst).ok()?;
        let text = std::str::from_utf8(&stack_dst[..decoded_len]).ok()?;
        return Some(text.to_string());
    }

    // Large inputs fallback to heap-allocated decode with zeroized buffers.
    let decoded = hex_decode(value).ok()?;
    String::from_utf8(decoded).ok()
}

/// Find every hex substring of at least `min_length` bytes in `text`, returned
/// as decodable [`EncodedString`] spans.
pub fn find_hex_strings(text: &str, min_length: usize) -> Vec<EncodedString> {
    find_hex_string_spans(text, min_length)
        .into_iter()
        .map(|candidate| EncodedString {
            value: candidate.value.to_string(),
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
    if input.len() <= 256 {
        let mut stack_dst = Zeroizing::new([0u8; 128]);
        let len = hex_decode_to_stack_buf(input, &mut *stack_dst)?;
        return Ok(stack_dst[..len].to_vec());
    }

    if !input.as_bytes().contains(&b'_') {
        if !input.len().is_multiple_of(2) || input.len() > MAX_HEX_INPUT_LEN {
            return Err(());
        }
        let decoded_len = input.len() / 2;
        let mut out = vec![0u8; decoded_len];
        if hex_simd::decode(input.as_bytes(), hex_simd::Out::from_slice(&mut out)).is_err() {
            out.zeroize();
            return Err(());
        }
        return Ok(out);
    }

    let mut cleaned = Zeroizing::new(Vec::with_capacity(input.len()));
    for &b in input.as_bytes() {
        if b != b'_' {
            cleaned.push(b);
        }
    }
    if !cleaned.len().is_multiple_of(2) || cleaned.len() > MAX_HEX_INPUT_LEN {
        return Err(());
    }
    let decoded_len = cleaned.len() / 2;
    let mut out = vec![0u8; decoded_len];
    if hex_simd::decode(&cleaned, hex_simd::Out::from_slice(&mut out)).is_err() {
        out.zeroize();
        return Err(());
    }
    Ok(out)
}

#[cfg(test)]
#[path = "../../tests/unit/decode_hex.rs"]
mod tests;
