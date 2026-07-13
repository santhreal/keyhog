//! Cache-soundness + invariant truth for the random-token discriminator
//! (`suppression::token_randomness`, KH-L-0413/0414), the recall/precision-
//! critical gate that LIFTS identifier-shape suppression on real random
//! passwords. Closes backlog 6485 (previously blocked on missing facades).
//!
//! `TokenRandomness::for_candidate(c)` precomputes `c`'s evidence once, then
//! `evidence_for(v)` returns that cached evidence via a `ptr+len` fast path when
//! `v` aliases `c`, else recomputes. That cache is a HOT-PATH perf optimization
//! that MUST be observationally identical to the no-cache `is_random_token(v)`
//!, a stale/mismatched hit would corrupt the verdict (drop a real password or
//! flood an FP). The jewel here is the differential:
//!   * cache HIT  (self):  `for_candidate(v).is_random_token(v)  == is_random_token(v)`
//!   * cache MISS (cross): `for_candidate(c).is_random_token(v)  == is_random_token(v)`
//! The candidate never leaks into another value's verdict.
//!
//! Plus the model-independent invariants that make the gate sound regardless of
//! the bigram model's tuning:
//!   * mutual exclusivity, a value is never BOTH a random token AND a confident
//!     dictionary word (both split on the SAME log-prob threshold);
//!   * diversity implication: `has_low_letter_diversity ⇒ !is_random_token`;
//!   * MIN_ALPHA fail-safe, fewer than MIN_ALPHA alphabetic chars ⇒ NOT random;
//!   * total (never panics on arbitrary/empty/unicode input).

use keyhog_scanner::testing::entropy_isolated::{
    has_low_letter_diversity, is_confident_dictionary_word, is_random_token,
    token_randomness_cross_is_random, token_randomness_self_is_random, MIN_ALPHA,
    MIN_DISTINCT_LETTERS,
};
use proptest::prelude::*;

fn alpha_count(s: &str) -> usize {
    s.bytes().filter(u8::is_ascii_alphabetic).count()
}

fn distinct_letters(s: &str) -> usize {
    let mut seen = 0u32;
    for b in s.bytes() {
        if b.is_ascii_alphabetic() {
            seen |= 1u32 << (b.to_ascii_lowercase() - b'a');
        }
    }
    seen.count_ones() as usize
}

// ── fixed anchors: the discriminator actually separates the two pools ─────────

#[test]
fn known_random_passwords_and_dictionary_words_classify_as_documented() {
    // Real CredData random passwords (all-lowercase, improbable adjacencies).
    for pw in ["ufnlbbavawsdeecn", "pxidztpvqk", "gjbubxsuqz"] {
        assert!(is_random_token(pw), "{pw} should read as a random token");
        assert!(
            !is_confident_dictionary_word(pw),
            "{pw} must NOT be a confident dictionary word"
        );
    }
    // Pronounceable dictionary identifiers / words.
    for w in ["getUserName", "configValue", "passwordmanager"] {
        assert!(
            !is_random_token(w),
            "{w} is pronounceable, not a random token"
        );
    }
    // Low-diversity masks are never random regardless of bigram score.
    for mask in ["xxxxxxxx", "abababab", "aaaaaaaa"] {
        assert!(!is_random_token(mask), "{mask} is a mask, not random");
        assert!(has_low_letter_diversity(mask) || distinct_letters(mask) >= MIN_DISTINCT_LETTERS);
    }
}

proptest! {
    // Testing Contract: 8k cases; per case = a few O(n) analyses over a <=24-byte
    // token, cheap. Lowercase strategy exercises the real random/word split;
    // the arbitrary-unicode tier proves totality.
    #![proptest_config(ProptestConfig::with_cases(8_000))]

    /// CACHE-HIT soundness: the aliasing fast path equals the no-cache verdict.
    #[test]
    fn cache_hit_equals_no_cache(v in "[a-z]{0,24}") {
        prop_assert_eq!(
            token_randomness_self_is_random(&v),
            is_random_token(&v),
            "cache-hit verdict diverged from no-cache for {:?}", v
        );
    }

    /// CACHE-MISS soundness: a handle built over `c` gives the SAME verdict for a
    /// different `v` as the standalone path (the candidate never leaks).
    #[test]
    fn cache_miss_equals_no_cache(c in "[a-z]{0,24}", v in "[a-z]{0,24}") {
        prop_assert_eq!(
            token_randomness_cross_is_random(&c, &v),
            is_random_token(&v),
            "cache-miss verdict (candidate {:?}) diverged from no-cache for {:?}", c, v
        );
    }

    /// A value is NEVER both a random token and a confident dictionary word 
    /// they split on the SAME log-prob threshold.
    #[test]
    fn random_and_dictionary_are_mutually_exclusive(v in "[a-zA-Z0-9_-]{0,24}") {
        prop_assert!(
            !(is_random_token(&v) && is_confident_dictionary_word(&v)),
            "{:?} classified as BOTH random and confident-dictionary", v
        );
    }

    /// `has_low_letter_diversity ⇒ !is_random_token`.
    #[test]
    fn low_diversity_implies_not_random(v in "[a-z]{0,24}") {
        if has_low_letter_diversity(&v) {
            prop_assert!(!is_random_token(&v), "{:?} is low-diversity yet random", v);
        }
    }

    /// MIN_ALPHA fail-safe: fewer than MIN_ALPHA alphabetic chars ⇒ NOT random.
    #[test]
    fn below_min_alpha_is_never_random(v in "[a-zA-Z0-9!@#_.-]{0,24}") {
        if alpha_count(&v) < MIN_ALPHA {
            prop_assert!(
                !is_random_token(&v),
                "{:?} has {} alpha (< MIN_ALPHA {}) yet was random",
                v, alpha_count(&v), MIN_ALPHA
            );
        }
    }

    /// Totality: all predicates + both cache paths never panic on arbitrary
    /// (incl. multibyte / empty) input.
    #[test]
    fn predicates_are_total_on_arbitrary_input(v in r"\PC{0,48}", c in r"\PC{0,16}") {
        let _ = is_random_token(&v);
        let _ = is_confident_dictionary_word(&v);
        let _ = has_low_letter_diversity(&v);
        let _ = token_randomness_self_is_random(&v);
        let _ = token_randomness_cross_is_random(&c, &v);
    }
}
