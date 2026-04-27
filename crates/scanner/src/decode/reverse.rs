use super::pipeline::{decode_candidates, extract_encoded_values};
use super::Decoder;
use keyhog_core::Chunk;

/// Match secrets that have been reversed character-by-character to dodge a
/// naïve byte-substring scan. Cheap evasion the adversarial corpus
/// (release-2026-04-26) hits multiple times — `RNK1ESEMURKWESFEDBA46AIKA`
/// is exactly the AWS access-key-id `AKIA64ABDEFSEWKRUMSEK1NR` reversed.
///
/// The reverse decoder runs *after* the other decoders fail to match. It only
/// emits a decoded chunk when the candidate is at least 16 chars long; below
/// that, reversed strings collide with normal text and produce too many
/// useless chunks for the scanner to dedup.
pub(super) struct ReverseDecoder;

const MIN_REVERSE_LEN: usize = 16;

impl Decoder for ReverseDecoder {
    fn name(&self) -> &'static str {
        "reverse"
    }

    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        // Refuse to recurse on our own output: reverse(reverse(s)) == s, so
        // the recursive pass would emit the original credential under a
        // `…/reverse/reverse` source_type, defeating downstream
        // evasion-aware suppression rules and (at minimum) wasting work.
        if chunk.metadata.source_type.contains("/reverse") {
            return Vec::new();
        }
        let candidates: Vec<String> = extract_encoded_values(&chunk.data)
            .into_iter()
            .filter(|c| c.len() >= MIN_REVERSE_LEN)
            .filter(|c| looks_reversible(c))
            .collect();
        decode_candidates(chunk, candidates, |s| Ok(reverse_str(s)), self.name())
    }
}

fn reverse_str(s: &str) -> String {
    s.chars().rev().collect()
}

/// Reverse-decode is asymmetric: every string trivially "decodes" to its
/// reverse, so we'd emit O(N) decoy chunks for normal text. Gate on a
/// cheap heuristic — at least one ASCII alphanumeric run of 12+ chars in
/// the reversed direction (the kind of run real credentials contain after
/// reversal). Keeps the chunk-count budget out of the bin while still
/// catching the obvious evasion.
fn looks_reversible(candidate: &str) -> bool {
    let bytes = candidate.as_bytes();
    let mut run = 0usize;
    for &b in bytes.iter().rev() {
        if b.is_ascii_alphanumeric() {
            run += 1;
            if run >= 12 {
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
    fn round_trip_reverse() {
        assert_eq!(reverse_str("AKIAIOSFODNN7EXAMPLE"), "ELPMAXE7NNDOFSOIAIKA");
        assert_eq!(
            reverse_str(&reverse_str("AKIAIOSFODNN7EXAMPLE")),
            "AKIAIOSFODNN7EXAMPLE"
        );
    }

    #[test]
    fn looks_reversible_accepts_long_alnum_runs() {
        assert!(looks_reversible("ELPMAXE7NNDOFSOIAIKA"));
    }

    #[test]
    fn looks_reversible_rejects_short_or_punctuated() {
        assert!(!looks_reversible("hello"));
        assert!(!looks_reversible("a-b-c-d-e-f-g-h-i-j"));
    }
}
