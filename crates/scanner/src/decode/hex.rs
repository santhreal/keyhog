use super::pipeline::{extract_encoded_values, push_decoded_text_chunk};
use super::{Decoder, EncodedString};
use keyhog_core::Chunk;

pub(super) struct HexDecoder;

impl Decoder for HexDecoder {
    fn name(&self) -> &'static str {
        "hex"
    }

    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        let mut decoded_chunks = Vec::new();
        for hex_match in find_hex_strings(&chunk.data, 32) {
            if let Ok(decoded) = hex_decode(&hex_match.value) {
                if let Ok(text) = String::from_utf8(decoded) {
                    push_decoded_text_chunk(&mut decoded_chunks, chunk, text, self.name());
                }
            }
        }
        decoded_chunks
    }
}

fn find_hex_strings(text: &str, min_length: usize) -> Vec<EncodedString> {
    let mut results = Vec::new();
    for candidate in extract_encoded_values(text) {
        // Hex literals in firmware dumps and config files commonly use `_`
        // every 2/4/8 chars for readability (`A1_B2_C3_...`). Strip those
        // before validating — audit class #5 (release-2026-04-26) noted
        // the previous all-hex check missed this evasion entirely.
        let cleaned: String = candidate.chars().filter(|c| *c != '_').collect();
        if cleaned.len() >= min_length
            && cleaned.len().is_multiple_of(2)
            && cleaned.chars().all(|ch| ch.is_ascii_hexdigit())
        {
            results.push(EncodedString { value: cleaned });
        }
    }
    results
}

/// Maximum hex input length we'll decode (prevents OOM from malicious input).
const MAX_HEX_INPUT_LEN: usize = 32 * 1024 * 1024; // 32 MB -> 16 MB decoded

#[allow(clippy::result_unit_err)]
pub fn hex_decode(input: &str) -> Result<Vec<u8>, ()> {
    if !input.len().is_multiple_of(2) || input.len() > MAX_HEX_INPUT_LEN {
        return Err(());
    }
    hex_simd::decode_to_vec(input).map_err(|_| ())
}

pub(super) fn hex_val(byte: u8) -> Result<u8, ()> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn underscored_hex_is_recognized() {
        // 64 hex chars (32 bytes) split into 2-char groups by `_`.
        // Wrapped in quotes so `extract_encoded_values` picks it up.
        let body = "\"41_42_43_44_45_46_47_48_49_4a_4b_4c_4d_4e_4f_50\
                    _51_52_53_54_55_56_57_58_59_5a_61_62_63_64_65_66\"";
        let found = find_hex_strings(body, 32);
        assert_eq!(found.len(), 1);
        // Underscores stripped; only hex remains.
        assert!(found[0].value.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(found[0].value.len(), 64);
        let decoded = hex_decode(&found[0].value).expect("decodes");
        assert_eq!(&decoded[..16], b"ABCDEFGHIJKLMNOP");
    }

    #[test]
    fn underscores_alone_dont_create_phantom_matches() {
        // Underscore-only string strips to empty, must not match.
        let found = find_hex_strings("\"_____________________________\"", 32);
        assert!(found.is_empty());
    }
}
