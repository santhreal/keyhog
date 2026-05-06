use super::pipeline::{extract_encoded_values, push_decoded_text_chunk};
use super::Decoder;
use keyhog_core::Chunk;

/// Caesar/ROT13/ROT-N decoder. A handful of malware-config dumps and CTF
/// fixtures store their tokens ROT13'd (`AKIA...` → `NXVN...`). For every
/// candidate ≥ 16 chars, emit decoded variants for the 25 non-trivial Caesar
/// shifts that produce a *plausibly credential-shaped* string.
///
/// "Plausibly shaped" gates the explosion: a 100-char chunk would otherwise
/// produce 25 sibling chunks per candidate. We require:
///   1. The decoded variant contains ≥1 ASCII digit (most modern API key
///      formats include digits — pure-letter Caesar output rarely indicates
///      a real secret).
///   2. The decoded variant has at least 8 ASCII alphanumeric chars in a
///      contiguous run (matches AWS / GitHub / Slack token shapes).
///
/// Both checks together keep the chunk count flat on prose-heavy inputs.
pub(super) struct CaesarDecoder;

const MIN_CAESAR_LEN: usize = 16;
const MIN_ALNUM_RUN: usize = 8;

impl Decoder for CaesarDecoder {
    fn name(&self) -> &'static str {
        "caesar"
    }

    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        // Refuse to recurse on our own output: shifting all 25 non-trivial
        // shifts on a previous output's would re-shift back to the original
        // (one of those 25 covers it) and trip evasion-aware downstream
        // logic. One pass per input is enough.
        if chunk.metadata.source_type.contains("/caesar") {
            return Vec::new();
        }
        let mut out = Vec::new();
        for candidate in extract_encoded_values(&chunk.data) {
            if candidate.len() < MIN_CAESAR_LEN {
                continue;
            }
            for shift in 1..=25u8 {
                let decoded = caesar_shift(&candidate, shift);
                if !looks_credential_shaped(&decoded) {
                    continue;
                }
                push_decoded_text_chunk(&mut out, chunk, decoded, self.name());
            }
        }
        out
    }
}

fn caesar_shift(input: &str, shift: u8) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        let shifted = match ch {
            'A'..='Z' => {
                let base = b'A';
                let off = (ch as u8 - base + shift) % 26;
                (base + off) as char
            }
            'a'..='z' => {
                let base = b'a';
                let off = (ch as u8 - base + shift) % 26;
                (base + off) as char
            }
            _ => ch,
        };
        out.push(shifted);
    }
    out
}

fn looks_credential_shaped(s: &str) -> bool {
    let bytes = s.as_bytes();
    if !bytes.iter().any(|b| b.is_ascii_digit()) {
        return false;
    }
    let mut run = 0usize;
    for &b in bytes {
        if b.is_ascii_alphanumeric() {
            run += 1;
            if run >= MIN_ALNUM_RUN {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rot13_round_trip() {
        let s = "AKIA64ABDEFSEWKRUMSEK1NR";
        let r13 = caesar_shift(s, 13);
        assert_eq!(caesar_shift(&r13, 13), s);
    }

    #[test]
    fn shift_preserves_non_letters() {
        assert_eq!(caesar_shift("AB-CD_12", 1), "BC-DE_12");
    }

    #[test]
    fn looks_credential_shaped_requires_digit_and_run() {
        assert!(looks_credential_shaped("AKIA64ABDEFSEWKR"));
        assert!(!looks_credential_shaped("HELLOWORLDFOOBAR")); // no digit
        assert!(!looks_credential_shaped("12-34-56-78-")); // no 8-alnum run
    }

    #[test]
    fn decode_chunk_round_trips_aws_shaped_token() {
        use keyhog_core::{Chunk, ChunkMetadata};

        // Plaintext: AKIAQR4DEFGHIJKL2345. Caesar +1 (letters only) →
        // BLJBRS4EFGHIJKLM2345. Decoder runs all 25 non-trivial shifts;
        // shift 25 (== inverse +1) recovers the original.
        let chunk = Chunk {
            data: "k = \"BLJBRS4EFGHIJKLM2345\";".into(),
            metadata: ChunkMetadata {
                base_offset: 0,
                source_type: "test".into(),
                ..Default::default()
            },
        };
        let decoded = CaesarDecoder.decode_chunk(&chunk);
        assert!(
            decoded
                .iter()
                .any(|c| c.data.as_str() == "AKIAQR4DEFGHIJKL2345"),
            "Caesar decoder did not surface the round-trip plaintext among {} variants. \
             Got: {:?}",
            decoded.len(),
            decoded.iter().map(|c| c.data.clone()).collect::<Vec<_>>(),
        );
    }
}
