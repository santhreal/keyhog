use super::limits::{MAX_HEX_INPUT_LEN, MIN_HEX_CANDIDATE_LEN};
use super::pipeline::{with_extracted_value_spans, DecodedReplacementBatcher, ExtractedValue};
use super::{DecodeAdmissionSketch, DecodeOutputSink, Decoder, EncodedString};
use keyhog_core::Chunk;
use zeroize::Zeroizing;
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

/// Fast-path trial decode and UTF-8 validation for hex candidate strings.
///
/// Decodes into a stack buffer for inputs up to 256 bytes (covering standard 16-byte
/// MD5 and 32-byte SHA256 hex string candidates) to validate UTF-8 without heap
/// allocations for binary hash tokens.
fn try_decode_hex_candidate_to_utf8(value: &str) -> Option<String> {
    if value.len() <= 256 {
        let mut stack_dst = Zeroizing::new([0u8; 128]);
        let decoded_len = if !value.as_bytes().contains(&b'_') {
            if !value.len().is_multiple_of(2) || value.len() > MAX_HEX_INPUT_LEN {
                return None;
            }
            let len = value.len() / 2;
            if len > 128 {
                return None;
            }
            hex_simd::decode(
                value.as_bytes(),
                hex_simd::Out::from_slice(&mut stack_dst[..len]),
            )
            .ok()?;
            len
        } else {
            let mut cleaned = Zeroizing::new([0u8; 256]);
            let mut len = 0usize;
            for &b in value.as_bytes() {
                if b != b'_' {
                    cleaned[len] = b;
                    len += 1;
                }
            }
            if !len.is_multiple_of(2) || len > MAX_HEX_INPUT_LEN {
                return None;
            }
            let decoded_len = len / 2;
            if decoded_len > 128 {
                return None;
            }
            hex_simd::decode(
                &cleaned[..len],
                hex_simd::Out::from_slice(&mut stack_dst[..decoded_len]),
            )
            .ok()?;
            decoded_len
        };

        // Validate UTF-8 on the stack buffer. Binary hashes return None immediately
        // without heap-allocating intermediate byte buffers or Strings.
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

/// Validate and decode a fixed `N`-byte hex hash candidate into a stack buffer.
/// Intermediate and destination buffers are zeroized on drop or validation error.
#[allow(clippy::result_unit_err)]
pub fn hex_decode_fixed<const N: usize>(input: &str) -> Result<[u8; N], ()> {
    let expected_hex_len = N.checked_mul(2).ok_or(())?;
    let mut out = Zeroizing::new([0u8; N]);
    if !input.as_bytes().contains(&b'_') {
        if input.len() != expected_hex_len {
            return Err(());
        }
        hex_simd::decode(input.as_bytes(), hex_simd::Out::from_slice(&mut *out)).map_err(|_| ())?;
        Ok(*out)
    } else if input.len() <= 256 {
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
        if len != expected_hex_len {
            return Err(());
        }
        hex_simd::decode(&cleaned[..len], hex_simd::Out::from_slice(&mut *out)).map_err(|_| ())?;
        Ok(*out)
    } else {
        let mut cleaned = Zeroizing::new(Vec::with_capacity(input.len()));
        for &b in input.as_bytes() {
            if b != b'_' {
                cleaned.push(b);
            }
        }
        if cleaned.len() != expected_hex_len {
            return Err(());
        }
        hex_simd::decode(&cleaned, hex_simd::Out::from_slice(&mut *out)).map_err(|_| ())?;
        Ok(*out)
    }
}

/// Validate and decode a 16-byte hex hash candidate (e.g. 32-hex-digit MD5 digest) into a stack buffer.
#[allow(clippy::result_unit_err)]
pub fn validate_hex_hash_16(input: &str) -> Result<[u8; 16], ()> {
    hex_decode_fixed::<16>(input)
}

/// Validate and decode a 32-byte hex hash candidate (e.g. 64-hex-digit SHA-256 digest) into a stack buffer.
#[allow(clippy::result_unit_err)]
pub fn validate_hex_hash_32(input: &str) -> Result<[u8; 32], ()> {
    hex_decode_fixed::<32>(input)
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
        if input.len() <= 256 {
            let decoded_len = input.len() / 2;
            let mut stack_dst = Zeroizing::new([0u8; 128]);
            hex_simd::decode(
                input.as_bytes(),
                hex_simd::Out::from_slice(&mut stack_dst[..decoded_len]),
            )
            .map_err(|_| ())?;
            return Ok(stack_dst[..decoded_len].to_vec());
        }

        let decoded_len = input.len() / 2;
        let mut out = Zeroizing::new(vec![0u8; decoded_len]);
        hex_simd::decode(input.as_bytes(), hex_simd::Out::from_slice(&mut out)).map_err(|_| ())?;
        return Ok((*out).clone());
    }

    if input.len() <= 256 {
        let mut cleaned = Zeroizing::new([0u8; 256]);
        let mut len = 0usize;
        for &b in input.as_bytes() {
            if b != b'_' {
                cleaned[len] = b;
                len += 1;
            }
        }
        if !len.is_multiple_of(2) || len > MAX_HEX_INPUT_LEN {
            return Err(());
        }
        let decoded_len = len / 2;
        let mut stack_dst = Zeroizing::new([0u8; 128]);
        hex_simd::decode(
            &cleaned[..len],
            hex_simd::Out::from_slice(&mut stack_dst[..decoded_len]),
        )
        .map_err(|_| ())?;
        return Ok(stack_dst[..decoded_len].to_vec());
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
    let mut out = Zeroizing::new(vec![0u8; decoded_len]);
    hex_simd::decode(&cleaned, hex_simd::Out::from_slice(&mut out)).map_err(|_| ())?;
    Ok((*out).clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_decode_empty_and_valid_cases() {
        assert_eq!(hex_decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(hex_decode("48656c6c6f").unwrap(), b"Hello");
        assert_eq!(hex_decode("48656C6C6F").unwrap(), b"Hello");
        assert_eq!(
            hex_decode("deadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(
            hex_decode("de_ad_be_ef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn hex_decode_rejects_malformed_and_odd_sequences() {
        assert!(hex_decode("a").is_err());
        assert!(hex_decode("abc").is_err());
        assert!(hex_decode("12345").is_err());
        assert!(hex_decode("gg41").is_err());
        assert!(hex_decode("41gg").is_err());
        assert!(hex_decode("48é6").is_err());
        assert!(hex_decode("41_4").is_err());
        assert!(hex_decode("41_zz").is_err());
    }

    #[test]
    fn hex_decode_fixed_validates_16_byte_hashes() {
        let md5_hex = "d41d8cd98f00b204e9800998ecf8427e";
        let decoded = validate_hex_hash_16(md5_hex).expect("valid 16-byte hash must decode");
        assert_eq!(
            decoded,
            [
                0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8,
                0x42, 0x7e
            ]
        );

        let md5_with_underscores = "d4_1d_8c_d9_8f_00_b2_04_e9_80_09_98_ec_f8_42_7e";
        let decoded_underscores = validate_hex_hash_16(md5_with_underscores)
            .expect("underscore-separated 16-byte hash must decode");
        assert_eq!(decoded_underscores, decoded);

        // Rejections: wrong length or non-hex
        assert!(validate_hex_hash_16("d41d8cd98f00b204e9800998ecf8427").is_err());
        assert!(validate_hex_hash_16("d41d8cd98f00b204e9800998ecf8427ea").is_err());
        assert!(validate_hex_hash_16("d41d8cd98f00b204e9800998ecf842zz").is_err());
    }

    #[test]
    fn hex_decode_fixed_validates_32_byte_hashes() {
        let sha256_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let decoded = validate_hex_hash_32(sha256_hex).expect("valid 32-byte hash must decode");
        assert_eq!(decoded.len(), 32);
        assert_eq!(decoded[0], 0xe3);
        assert_eq!(decoded[31], 0x55);

        let sha256_underscores =
            "e3b0c442_98fc1c14_9afbf4c8_996fb924_27ae41e4_649b934c_a495991b_7852b855";
        let decoded_underscores = validate_hex_hash_32(sha256_underscores)
            .expect("underscore-separated 32-byte hash must decode");
        assert_eq!(decoded_underscores, decoded);

        // Rejections: wrong length or non-hex
        assert!(validate_hex_hash_32(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85"
        )
        .is_err());
        assert!(validate_hex_hash_32(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855a"
        )
        .is_err());
        assert!(validate_hex_hash_32(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8zz"
        )
        .is_err());
    }

    #[test]
    fn try_decode_hex_candidate_utf8_fast_path() {
        // Text hex decodes to valid UTF-8 string
        assert_eq!(
            try_decode_hex_candidate_to_utf8("48656c6c6f").as_deref(),
            Some("Hello")
        );
        assert_eq!(
            try_decode_hex_candidate_to_utf8("73_6b_2d_70_72_6f_6a").as_deref(),
            Some("sk-proj")
        );

        // Binary hashes (random cryptographic digests) fail UTF-8 check and return None
        // without allocating heap Strings.
        let md5_hex = "d41d8cd98f00b204e9800998ecf8427e";
        assert_eq!(try_decode_hex_candidate_to_utf8(md5_hex), None);

        let sha256_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(try_decode_hex_candidate_to_utf8(sha256_hex), None);

        // Malformed inputs return None
        assert_eq!(try_decode_hex_candidate_to_utf8("abc"), None);
        assert_eq!(try_decode_hex_candidate_to_utf8("zz41"), None);
    }
}
