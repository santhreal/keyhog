use super::pipeline::{extract_encoded_values, push_decoded_text_chunk_spliced};
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
        for hex_match in find_hex_strings(&chunk.data, 16) {
            let cleaned: String = hex_match.value.chars().filter(|c| *c != '_').collect();
            if let Ok(decoded) = hex_decode(&cleaned) {
                if let Ok(text) = String::from_utf8(decoded) {
                    // Splice over the *original* encoded blob (with `_` if present)
                    // so companion context survives - passing the cleaned form
                    // misses the parent substring and drops the anchor.
                    push_decoded_text_chunk_spliced(
                        &mut decoded_chunks,
                        chunk,
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

fn find_hex_strings(text: &str, min_length: usize) -> Vec<EncodedString> {
    let mut results = Vec::new();
    for candidate in extract_encoded_values(text) {
        // Hex literals in firmware dumps and config files commonly use `_`
        // every 2/4/8 chars for readability (`A1_B2_C3_...`). Strip those
        // before validating - audit class #5 (release-2026-04-26) noted
        // the previous all-hex check missed this evasion entirely.
        let cleaned: String = candidate.chars().filter(|c| *c != '_').collect();
        if cleaned.len() >= min_length
            && cleaned.len().is_multiple_of(2)
            && cleaned.chars().all(|ch| ch.is_ascii_hexdigit())
        {
            results.push(EncodedString { value: candidate });
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

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_CREDENTIAL: &str = "TESTKEY_aK7xP9mQ2wE5rT8yU1iO";

    #[test]
    fn underscored_hex_is_recognized() {
        // 64 hex chars (32 bytes) split into 2-char groups by `_`.
        // Wrapped in quotes so `extract_encoded_values` picks it up.
        let body = "\"41_42_43_44_45_46_47_48_49_4a_4b_4c_4d_4e_4f_50\
                    _51_52_53_54_55_56_57_58_59_5a_61_62_63_64_65_66\"";
        let found = find_hex_strings(body, 32);
        assert_eq!(found.len(), 1);
        let cleaned: String = found[0].value.chars().filter(|c| *c != '_').collect();
        assert!(cleaned.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(cleaned.len(), 64);
        let decoded = hex_decode(&found[0].value).expect("decodes");
        assert_eq!(&decoded[..16], b"ABCDEFGHIJKLMNOP");
    }

    #[test]
    fn underscored_testkey_hex_decodes_to_credential() {
        let hex: String = VALID_CREDENTIAL
            .bytes()
            .map(|b| format!("{b:02x}"))
            .collect();
        let underscored = hex
            .as_bytes()
            .chunks(4)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join("_");
        let body = format!("const token_hex = \"{underscored}\";");
        let found = find_hex_strings(&body, 32);
        assert_eq!(found.len(), 1, "underscored TESTKEY hex must be found");
        let decoded = String::from_utf8(hex_decode(&found[0].value).unwrap()).unwrap();
        assert_eq!(decoded, VALID_CREDENTIAL);
    }

    #[test]
    fn hex_decode_strips_underscore_separators() {
        let hex: String = VALID_CREDENTIAL
            .bytes()
            .map(|b| format!("{b:02x}"))
            .collect();
        let underscored = hex
            .as_bytes()
            .chunks(4)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join("_");
        let decoded = String::from_utf8(hex_decode(&underscored).unwrap()).unwrap();
        assert_eq!(decoded, VALID_CREDENTIAL);
    }

    #[test]
    fn underscores_alone_dont_create_phantom_matches() {
        // Underscore-only string strips to empty, must not match.
        let found = find_hex_strings("\"_____________________________\"", 32);
        assert!(found.is_empty());
    }
}
