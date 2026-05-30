use super::pipeline::{decode_candidates, extract_encoded_values};
use super::Decoder;
use keyhog_core::Chunk;

/// Match secrets that have been reversed character-by-character to dodge a
/// naïve byte-substring scan. Cheap evasion the adversarial corpus
/// (release-2026-04-26) hits multiple times - `RNK1ESEMURKWESFEDBA-46AIKA`
/// is exactly the AWS access-key-id `AKIA-64ABDEFSEWKRUMSEK1NR` reversed.
///
/// The reverse decoder runs *after* the other decoders fail to match. It only
/// emits a decoded chunk when the candidate is at least 16 chars long; below
/// that, reversed strings collide with normal text and produce too many
/// useless chunks for the scanner to dedup.
pub struct ReverseDecoder;

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

pub fn reverse_str(s: &str) -> String {
    s.chars().rev().collect()
}

/// Reverse-decode is asymmetric: every string trivially "decodes" to its
/// reverse, so we'd emit O(N) decoy chunks for normal text. Two cheap gates:
///
/// 1. A 12+ ASCII alphanumeric run in the reversed direction (filters out
///    `a-b-c-d-...` and other punctuated text).
/// 2. The reversed text must contain at least one known credential prefix
///    from `confidence::KNOWN_PREFIXES`. Without this, plain prose like
///    `ABCDEFGHIJKLMNOPQRSTUVWXYZ` reverses to `ZYXWVUTSRQPONMLKJIHGFEDCBA`,
///    passes the alphanumeric-run gate, and gets emitted as a decoy chunk
///    on every chunk that contains a long alphanumeric word - pure noise
///    that hammers the dedup layer. Kimi-decode audit finding #4.
pub fn looks_reversible(candidate: &str) -> bool {
    let bytes = candidate.as_bytes();
    let mut run = 0usize;
    let mut saw_long_run = false;
    for &b in bytes.iter().rev() {
        if b.is_ascii_alphanumeric() {
            run += 1;
            if run >= 12 {
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
    // Only emit a reverse-decoded chunk when the reversed string would
    // contain a known provider prefix. Stops `ZYXWVUTSRQPONMLKJIHGFEDCBA`
    // from looking like a candidate just because it has a long alnum run.
    //
    // Skip 2-char prefixes - the only entry that short is the Ethereum
    // `0x` literal. `0x` shows up by random chance in ~1.6% of 80-char
    // base64 strings, which routed every such reversed blob through the
    // decoder and emitted spurious findings on the base64-protobuf
    // decoy class. Investigator empirically attributed 4 FPs to this
    // exact path. An Ethereum address embedded inside an obfuscated
    // reversed string is exotic enough that the recall loss is near zero;
    // every 3+ char vendor prefix (`hf_`, `SG.`, `eyJ`, `sk-`, `ghp_`,
    // ...) still gates as before.
    let reversed = reverse_str(candidate);
    crate::confidence::KNOWN_PREFIXES
        .iter()
        .filter(|prefix| prefix.len() >= 3)
        .any(|prefix| reversed.contains(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Positive truth case: a reversed AKIA access key still admits the
    /// reverse decoder. AKIA is 4 chars, well above the 3-char floor.
    #[test]
    fn reversible_admits_genuine_akia_reverse() {
        // "AKIA_64ABDEFSEWKRUMSEK1NR" reversed -> "RN1KESMURKWESFEDBA46_AIKA"
        let reversed = "RN1KESMURKWESFEDBA46_AIKA";
        assert!(
            looks_reversible(reversed),
            "AKIA reversal must be admitted as reverse-decodable"
        );
    }

    /// Adversarial negative twin: a 60-char base64 blob whose reverse
    /// happens to contain `0x` (the Ethereum-address 2-char prefix) MUST
    /// NOT pass the gate. Before the fix the 2-char `0x` literal in
    /// KNOWN_PREFIXES gated random base64 through the reverse decoder.
    /// `0x` appears by random chance in ~1.6% of 80-char base64 strings.
    #[test]
    fn reversible_rejects_random_base64_with_0x() {
        // Build a 32+ char alphanumeric candidate whose REVERSE contains
        // `0x` but no 3+ char vendor prefix. The literal `x0` placed in
        // the original becomes `0x` in the reverse. The body is otherwise
        // arbitrary base64 chars that include enough digits and letters
        // to clear the 12-char alphanumeric run-length gate.
        let candidate = "x0YeAhsbifEWGqJxAefViNbZ2yJI1ZpgVqlSiZ7BcMK4LR3zU8m";
        let reversed: String = candidate.chars().rev().collect();
        assert!(
            reversed.contains("0x"),
            "reversed text must contain the 0x literal by construction; reversed={}",
            reversed
        );
        assert!(
            !looks_reversible(candidate),
            "random base64 whose only known-prefix hit is 2-char `0x` must NOT be reverse-decoded; reversed={}",
            reversed
        );
    }

    /// Defensive coverage: a reversal containing the 3-char `hf_`
    /// HuggingFace prefix still admits the candidate. Proves the 3-char
    /// floor is the cut, not 4.
    #[test]
    fn reversible_admits_hf_prefix_in_reversal() {
        // Build a candidate whose reverse contains `hf_AB...` shape with
        // a 12+ alnum run for the run-length gate.
        let reversed_text = "hf_ABCDEFGHIJKLM"; // hf_ + 13 alnum
        let candidate: String = reversed_text.chars().rev().collect();
        assert!(
            looks_reversible(&candidate),
            "3-char hf_ prefix in reversed text must keep the candidate admissible; reversed={}",
            reversed_text
        );
    }
}
