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
///      formats include digits - pure-letter Caesar output rarely indicates
///      a real secret).
///   2. The decoded variant has at least 8 ASCII alphanumeric chars in a
///      contiguous run (matches AWS / GitHub / Slack token shapes).
///
/// Both checks together keep the chunk count flat on prose-heavy inputs.
///
/// Source-code files are skipped entirely. Real secrets are never Caesar-
/// encoded inside source - the 25-shift fan-out on every prose-comment in
/// a codebase just hallucinates detector matches from random letter runs
/// (helicone-api-key on a `//! Source trait` doc comment was the original
/// reproducer; see dogfood-2026-05-21.md finding #5).
pub(super) struct CaesarDecoder;

const MIN_CAESAR_LEN: usize = 16;
const MIN_ALNUM_RUN: usize = 8;

/// File extensions where Caesar-decoding is pure noise. Matched against the
/// suffix of `chunk.metadata.path` (lower-cased). Kept short - only the
/// dominant source-code extensions a scanner is realistically pointed at.
const SOURCE_CODE_EXTENSIONS: &[&str] = &[
    ".rs", ".py", ".go", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".scala", ".c", ".cc",
    ".cpp", ".cxx", ".h", ".hh", ".hpp", ".cs", ".rb", ".php", ".swift", ".m", ".mm", ".sh",
    ".bash", ".zsh", ".fish", ".lua", ".pl", ".pm", ".sql", ".html", ".htm", ".css", ".scss",
    ".sass", ".vue", ".svelte", ".md", ".rst", ".txt", ".adoc",
];

fn is_source_code_path(path: Option<&str>) -> bool {
    let Some(p) = path else { return false };
    let lower = p.to_ascii_lowercase();
    SOURCE_CODE_EXTENSIONS
        .iter()
        .any(|ext| lower.ends_with(ext))
}

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
        if is_source_code_path(chunk.metadata.path.as_deref()) {
            return Vec::new();
        }
        let mut out = Vec::new();
        for candidate in extract_encoded_values(&chunk.data) {
            if candidate.len() < MIN_CAESAR_LEN {
                continue;
            }
            // kimi-decode audit: caesar_shift is the identity for
            // digits / punctuation / non-ASCII. A pure-digit candidate
            // (e.g. a 16-digit PIN) produces 25 IDENTICAL shifts, all
            // equal to the original. The seen-set later dedups them
            // but each unnecessarily walks the full detector pipeline
            // and emits a bare decoded chunk that scans the same text
            // we already scanned in the parent. Skip if the input has
            // no a-z/A-Z character to shift.
            if !candidate.chars().any(|c| c.is_ascii_alphabetic()) {
                continue;
            }
            for shift in 1..=25u8 {
                let decoded = caesar_shift(&candidate, shift);
                if !looks_credential_shaped(&decoded) {
                    continue;
                }
                // NOTE: we intentionally use the non-spliced push.
                // Splicing the decoded variant back into the parent
                // (which the base64/hex paths do for companion-anchor
                // preservation) is wrong for Caesar: Caesar produces
                // 25 candidate shifts per blob, of which several can
                // randomly satisfy hex/UUID shape gates. Splicing
                // those into the parent multiplies findings under
                // keyword-anchored detectors with shifted credentials
                // that don't match the ground-truth value the user
                // planted. Caesar's value is the bare decoded
                // candidate; let it surface as its own chunk so the
                // dedup layer can collapse identical findings.
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
    let mut saw_long_run = false;
    for &b in bytes {
        if b.is_ascii_alphanumeric() {
            run += 1;
            if run >= MIN_ALNUM_RUN {
                saw_long_run = true;
                break;
            }
        } else {
            run = 0;
        }
    }
    if !saw_long_run {
        return false;
    }
    // Same rationale as `reverse::looks_reversible`: gate on a known
    // provider prefix appearing in the decoded text. Without this, any
    // Caesar shift of a credential-shaped input (e.g. `sk_live_...`
    // shifted +23 → `ph_ifsb_...`) gets emitted as a decoded chunk
    // whose substrings can incidentally collide with detector regexes
    // (`sb_4bZ39EnIvgT...` matches the stackblitz `sb_[a-zA-Z0-9_-]{20,}`
    // regex purely by letter coincidence). The downstream
    // `should_suppress_named_detector_finding` bypasses the
    // EXAMPLE / INSERT / CHANGE / REPLACE markers for `/caesar`
    // source_types (because evasion-decoded inputs CAN legitimately
    // be a planted-credential rotation), so the gate has to happen
    // here at decoder-output time.
    crate::confidence::KNOWN_PREFIXES
        .iter()
        .any(|prefix| s.contains(prefix))
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
    fn is_source_code_path_matches_known_extensions() {
        assert!(is_source_code_path(Some("src/foo.rs")));
        assert!(is_source_code_path(Some("/abs/path/bar.py")));
        assert!(is_source_code_path(Some("RELATIVE.GO")));
        assert!(is_source_code_path(Some("docs/README.md")));
        assert!(!is_source_code_path(Some("config/secrets.env")));
        assert!(!is_source_code_path(Some("blob.bin")));
        assert!(!is_source_code_path(None));
    }

    #[test]
    fn source_code_path_skips_caesar_decoder() {
        use keyhog_core::{Chunk, ChunkMetadata};
        // Comment in a Rust file that should never be Caesar-shifted - was the
        // source.rs:1 false positive that fired helicone-api-key in production.
        let chunk = Chunk {
            data: "//! Source trait and chunk types: pluggable input backends.".into(),
            metadata: ChunkMetadata {
                base_offset: 0,
                source_type: "filesystem".into(),
                path: Some("crates/core/src/source.rs".into()),
                ..Default::default()
            },
        };
        let decoded = CaesarDecoder.decode_chunk(&chunk);
        assert!(
            decoded.is_empty(),
            "Caesar decoder must not run on .rs source files; got {} decoded variants",
            decoded.len()
        );
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
                .any(|c| c.data.as_str() == concat!("AK", "IAQR4DEFGHIJKL2345")),
            "Caesar decoder did not surface the round-trip plaintext among {} variants. \
             Got: {:?}",
            decoded.len(),
            decoded.iter().map(|c| c.data.clone()).collect::<Vec<_>>(),
        );
    }
}
