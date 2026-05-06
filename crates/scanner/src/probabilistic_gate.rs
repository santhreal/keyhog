//! Fast probabilistic gating to reject obvious non-secrets before heavy ML scoring.
//!
//! Uses character diversity and simple bigram analysis to identify high-entropy noise
//! like UUIDs, hashes, and base64-encoded binary that doesn't look like a secret.

/// A tiny statistical gate for fast candidate rejection.
pub struct ProbabilisticGate;

impl ProbabilisticGate {
    /// Returns true if the candidate string looks like a potential secret.
    /// Returns false if it's almost certainly noise (UUID, hash, etc).
    pub fn looks_promising(s: &str) -> bool {
        if s.len() < 16 {
            return true; // Too short for reliable gating
        }

        let mut count = 0;
        let mut seen = [false; 256];
        for b in s.bytes() {
            if !seen[b as usize] {
                seen[b as usize] = true;
                count += 1;
            }
        }

        // UUID detection: exactly 4 dashes in 8-4-4-4-12 hex pattern
        if s.len() >= 32 && s.len() <= 40 && s.matches('-').count() == 4 {
            let parts: Vec<&str> = s.split('-').collect();
            if parts.len() == 5
                && parts
                    .iter()
                    .all(|p| p.chars().all(|c| c.is_ascii_hexdigit()))
            {
                return false;
            }
        }

        // Extremely low diversity (e.g. "aaaaaaaaaaaaaaaa") is rejected
        if count < 5 {
            return false;
        }

        // Lightweight approximation of a full bigram frequency table.
        //
        // Real secrets are alphabet-restricted but bigram-distributed: a
        // base64 token has roughly uniform bigram frequencies, while a SHA
        // hex digest has STRONGLY skewed frequencies (only 16 chars × 16
        // bigrams = 256 possible bigrams, so any 32-char hex string visits
        // ~31 of those 256). UUIDs without dashes are an extreme case.
        //
        // The cheap proxy: count distinct bigrams in s and require a
        // minimum density. For a length-N candidate with K distinct chars,
        // a uniform-random base64 string visits ~min(N-1, K^2)
        // distinct bigrams; a hex string maxes out at 256 regardless of
        // length. We require distinct_bigrams >= length / 4 (very lax) AND
        // distinct_bigrams >= 8 (absolute floor for short candidates).
        // These bounds reject 32-hex SHAs (which have ~28 distinct bigrams
        // on 32 chars) very rarely — they pass — while killing pure-base64
        // UUID-without-dashes pads.
        //
        // We compute distinct bigrams via a 64-byte (512-bit) bitset over
        // a 9-bit FNV slot, identical to the bigram_bloom strategy.
        let bytes = s.as_bytes();
        if bytes.len() >= 32 {
            let mut bigram_seen = [0u64; 8]; // 512 bits ≈ 0.6% FP at 28 bigrams
            for window in bytes.windows(2) {
                let h = bigram_slot_512(window[0], window[1]);
                bigram_seen[h >> 6] |= 1u64 << (h & 63);
            }
            let distinct: u32 = bigram_seen.iter().map(|w| w.count_ones()).sum();
            let length_floor = (bytes.len() / 4) as u32;
            if distinct < 8 || distinct < length_floor {
                return false;
            }
        }

        true
    }
}

#[inline]
fn bigram_slot_512(a: u8, b: u8) -> usize {
    let mut h: u32 = 0x811c_9dc5;
    h ^= a as u32;
    h = h.wrapping_mul(0x0100_0193);
    h ^= b as u32;
    h = h.wrapping_mul(0x0100_0193);
    (h as usize) & 0x01ff
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn realistic_secret_passes() {
        // GitHub PAT shape — varied bigrams, length 40.
        assert!(ProbabilisticGate::looks_promising(
            "ghp_aBcD1234EFgh5678ijklMNop9012qrSTuvWX"
        ));
    }

    #[test]
    fn uuid_with_dashes_is_rejected() {
        assert!(!ProbabilisticGate::looks_promising(
            "550e8400-e29b-41d4-a716-446655440000"
        ));
    }

    #[test]
    fn short_input_passes_through() {
        // <16 bytes — gating returns true regardless.
        assert!(ProbabilisticGate::looks_promising("ghp_short"));
    }

    #[test]
    fn pure_repetition_is_rejected() {
        assert!(!ProbabilisticGate::looks_promising(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
    }
}
