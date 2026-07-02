//! Truth-pinned regression coverage for the entropy primitive and the
//! heuristic confidence scorer (`crates/scanner/src/entropy`,
//! `crates/scanner/src/confidence`).
//!
//! Every assertion here is an EXACT expected value, derived by hand from the
//! source math, not a shape check:
//!
//!   * `shannon_entropy` on strings with a controlled symbol distribution has a
//!     closed-form bits/byte value (`log2(k)` for `k` equiprobable symbols); we
//!     pin `0.0` (all one char), `1.0` (two symbols), `2.0`, `4.0`, `5.0`,
//!     `6.0`, and the `8.0` ceiling.
//!   * `compute_confidence` sums fixed per-signal weights over a fixed
//!     `max_possible == 1.0` and applies a `0.6` low-entropy penalty. Each case
//!     reproduces the documented arithmetic exactly (0.35 literal prefix, 0.20
//!     context anchor, the 0.20 / 0.12 / 0.05 entropy tiers at the 5.8 / 4.5 /
//!     3.0 cutoffs, the `<2.0`-entropy `&&` `len>10` penalty, etc.).
//!   * The published entropy thresholds keep their tuned values and ordering.
//!
//! Positive, negative-twin, boundary, and adversarial cases are all present so a
//! drift in either the weights, the tier cutoffs, or the penalty gate fails here.

use keyhog_scanner::entropy::{
    normalized_entropy, shannon_entropy, HIGH_ENTROPY_THRESHOLD, LOW_ENTROPY_THRESHOLD,
    SENSITIVE_FILE_VERY_HIGH_ENTROPY_THRESHOLD, VERY_HIGH_ENTROPY_THRESHOLD,
};
use keyhog_scanner::testing::confidence::{
    compute_confidence, unique_byte_count, ConfidenceSignals,
};
use keyhog_scanner::testing::entropy_fast::shannon_entropy_simd;

/// Tolerance for entropy values that are exact in theory but pass through an
/// `f64::log2` reduction; every asserted value below is an integer or a
/// power-of-two log that is representable exactly, so this margin is generous.
const EPS: f64 = 1e-9;

/// All-zero-signal `ConfidenceSignals` builder so each test overrides only the
/// fields it exercises. `max_possible` in the scorer is a fixed `1.0`, so the
/// normalized score equals the raw weighted sum (times any penalty).
fn signals() -> ConfidenceSignals {
    ConfidenceSignals {
        has_literal_prefix: false,
        has_context_anchor: false,
        entropy: 0.0,
        keyword_nearby: false,
        sensitive_file: false,
        match_length: 0,
        has_companion: false,
    }
}

// ─────────────────────────── shannon_entropy: exact bits/byte ──────────────

#[test]
fn shannon_all_same_char_is_exactly_zero() {
    // A single distinct symbol carries 0 information: -1*log2(1) = 0.
    let e = shannon_entropy(b"aaaaaaaaaaaaaaaa");
    assert!(e.abs() < EPS, "all-same-char entropy must be 0.0, got {e}");
    // The cached public entry and the raw SIMD primitive agree bit-for-bit.
    assert!((e - shannon_entropy_simd(b"aaaaaaaaaaaaaaaa")).abs() < EPS);
}

#[test]
fn shannon_two_equiprobable_symbols_is_one_bit() {
    // 8×'a' + 8×'b' interleaved: log2(2) = 1.0 bit/byte.
    let e = shannon_entropy(b"abababababababab");
    assert!(
        (e - 1.0).abs() < EPS,
        "two-symbol entropy must be 1.0, got {e}"
    );
}

#[test]
fn shannon_four_equiprobable_symbols_is_two_bits() {
    // 4× each of a,b,c,d: log2(4) = 2.0 bits/byte.
    let e = shannon_entropy(b"abcdabcdabcdabcd");
    assert!(
        (e - 2.0).abs() < EPS,
        "four-symbol entropy must be 2.0, got {e}"
    );
}

#[test]
fn shannon_sixteen_distinct_bytes_is_four_bits() {
    // 16 distinct chars, each once: log2(16) = 4.0 bits/byte.
    let e = shannon_entropy(b"0123456789abcdef");
    assert!(
        (e - 4.0).abs() < EPS,
        "16-distinct entropy must be 4.0, got {e}"
    );
}

#[test]
fn shannon_thirtytwo_distinct_base64_is_five_bits() {
    // 32 distinct base64-alphabet chars, each once: log2(32) = 5.0. This clears
    // the 4.5 HIGH tier but stays under the 5.8 VERY-HIGH tier.
    let s = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";
    assert_eq!(s.len(), 32);
    let e = shannon_entropy(s);
    assert!(
        (e - 5.0).abs() < EPS,
        "32-distinct entropy must be 5.0, got {e}"
    );
    assert!(e > HIGH_ENTROPY_THRESHOLD);
    assert!(e < VERY_HIGH_ENTROPY_THRESHOLD);
}

#[test]
fn shannon_sixtyfour_distinct_base64_is_six_bits() {
    // The full 64-char base64 alphabet, each once: log2(64) = 6.0, above the
    // 5.8 VERY-HIGH tier.
    let s = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    assert_eq!(s.len(), 64);
    let e = shannon_entropy(s);
    assert!(
        (e - 6.0).abs() < EPS,
        "64-distinct entropy must be 6.0, got {e}"
    );
    assert!(e > VERY_HIGH_ENTROPY_THRESHOLD);
}

#[test]
fn shannon_full_byte_range_hits_the_eight_bit_ceiling() {
    // Every one of the 256 byte values exactly once is the maximum: 8.0 bits/byte.
    let all: Vec<u8> = (0u8..=255).collect();
    let e = shannon_entropy(&all);
    assert!(
        (e - 8.0).abs() < EPS,
        "full-byte-range entropy must be 8.0, got {e}"
    );
}

#[test]
fn shannon_empty_input_is_zero() {
    let e = shannon_entropy(b"");
    assert!(e.abs() < EPS, "empty entropy must be 0.0, got {e}");
    assert!(shannon_entropy_simd(b"").abs() < EPS);
}

#[test]
fn shannon_large_uncached_all_same_is_zero() {
    // >1024 bytes bypasses the thread-local cache and hits the uncached path;
    // a constant buffer is still exactly 0.0 through the direct reduction.
    let big = vec![b'a'; 2048];
    let e = shannon_entropy(&big);
    assert!(
        e.abs() < EPS,
        "2048-byte all-same entropy must be 0.0, got {e}"
    );
}

#[test]
fn shannon_cached_entry_matches_simd_primitive_and_repeats() {
    // The public cached wrapper must return the SIMD primitive's value, and a
    // second (cache-hit) call must return the identical bits.
    let v = b"s3cr3t_Tok3n_9aZ+/Qw==";
    let first = shannon_entropy(v);
    let second = shannon_entropy(v);
    assert_eq!(
        first.to_bits(),
        second.to_bits(),
        "cache must be deterministic"
    );
    assert!((first - shannon_entropy_simd(v)).abs() < EPS);
}

// ─────────────────────────── normalized_entropy: [0,1] rescale ─────────────

#[test]
fn normalized_all_same_char_is_zero() {
    // <=1 distinct symbol short-circuits to 0.0 (no log2(1) division).
    let e = normalized_entropy(b"aaaa");
    assert!(
        e.abs() < EPS,
        "all-same normalized entropy must be 0.0, got {e}"
    );
}

#[test]
fn normalized_full_alphabet_saturates_to_one() {
    // 16 distinct bytes: shannon 4.0 / log2(16)=4.0 => exactly 1.0.
    let e = normalized_entropy(b"0123456789abcdef");
    assert!(
        (e - 1.0).abs() < EPS,
        "full-alphabet normalized entropy must be 1.0, got {e}"
    );
}

#[test]
fn normalized_skewed_two_symbol_value() {
    // "aaab": 3×'a' + 1×'b'. shannon = log2(4) - (3*log2 3)/4
    //       = 2 - (3*1.5849625007)/4 = 0.8112781245 bits/byte.
    // max_entropy = log2(2) = 1.0, so normalized == shannon here.
    let raw = shannon_entropy(b"aaab");
    assert!(
        (raw - 0.811_278_124_5).abs() < 1e-6,
        "skewed shannon must be ~0.8112781, got {raw}"
    );
    let norm = normalized_entropy(b"aaab");
    assert!(
        (norm - 0.811_278_124_5).abs() < 1e-6,
        "skewed normalized must be ~0.8112781, got {norm}"
    );
}

#[test]
fn normalized_empty_input_is_zero() {
    let e = normalized_entropy(b"");
    assert!(
        e.abs() < EPS,
        "empty normalized entropy must be 0.0, got {e}"
    );
}

// ─────────────────────────── unique_byte_count: distinct symbols ───────────

#[test]
fn unique_byte_count_exact_distinct_totals() {
    assert_eq!(unique_byte_count(b"aaaa"), 1);
    assert_eq!(unique_byte_count(b"abc"), 3);
    assert_eq!(unique_byte_count(b"0123456789abcdef"), 16);
    assert_eq!(unique_byte_count(b""), 0);
    // Repeats do not inflate the count; only the distinct set matters.
    assert_eq!(unique_byte_count(b"aabbccdd"), 4);
}

// ─────────────────────────── compute_confidence: exact weighted score ──────

#[test]
fn confidence_all_signals_absent_scores_zero() {
    // No signal, zero entropy, zero-length match: nothing added, no penalty
    // (penalty needs match_length > 10), so the score is exactly 0.0.
    let s = compute_confidence(&signals());
    assert!(
        s.abs() < EPS,
        "empty-signal confidence must be 0.0, got {s}"
    );
}

#[test]
fn confidence_literal_prefix_alone_is_035() {
    // Only the 0.35 literal-prefix weight fires; entropy 0.0 with len 0 draws no
    // penalty (penalty requires match_length > 10).
    let mut sig = signals();
    sig.has_literal_prefix = true;
    let s = compute_confidence(&sig);
    assert!(
        (s - 0.35).abs() < EPS,
        "literal-prefix-only confidence must be 0.35, got {s}"
    );
}

#[test]
fn confidence_very_high_entropy_tier_adds_full_020() {
    // literal prefix (0.35) + VERY-HIGH entropy tier (0.20) = 0.55.
    let mut sig = signals();
    sig.has_literal_prefix = true;
    sig.entropy = 5.9; // >= 5.8 very-high tier
    sig.match_length = 40;
    let s = compute_confidence(&sig);
    assert!(
        (s - 0.55).abs() < EPS,
        "prefix + very-high-entropy must be 0.55, got {s}"
    );
}

#[test]
fn confidence_high_entropy_partial_tier_at_45_cutoff() {
    // entropy EXACTLY 4.5 lands the partial 0.12 tier, not the full 0.20.
    let mut sig = signals();
    sig.entropy = HIGH_ENTROPY_THRESHOLD; // 4.5
    let s = compute_confidence(&sig);
    assert!(
        (s - 0.12).abs() < EPS,
        "entropy 4.5 must give the 0.12 partial tier, got {s}"
    );
}

#[test]
fn confidence_just_below_high_tier_drops_to_moderate() {
    // 4.4999 < 4.5 but >= 3.0 => the 0.05 moderate tier (negative twin of the
    // 4.5 boundary case).
    let mut sig = signals();
    sig.entropy = 4.4999;
    let s = compute_confidence(&sig);
    assert!(
        (s - 0.05).abs() < EPS,
        "entropy just below 4.5 must give 0.05 moderate, got {s}"
    );
}

#[test]
fn confidence_moderate_tier_at_30_cutoff() {
    // entropy EXACTLY 3.0 is the moderate cutoff => 0.05.
    let mut sig = signals();
    sig.entropy = 3.0;
    let s = compute_confidence(&sig);
    assert!(
        (s - 0.05).abs() < EPS,
        "entropy 3.0 must give the 0.05 moderate tier, got {s}"
    );
}

#[test]
fn confidence_just_below_moderate_adds_no_entropy_weight() {
    // 2.9999 < 3.0 => no entropy weight; no other signal => 0.0. len 0 avoids the
    // low-entropy penalty branch (which needs match_length > 10).
    let mut sig = signals();
    sig.entropy = 2.9999;
    let s = compute_confidence(&sig);
    assert!(
        s.abs() < EPS,
        "entropy just below 3.0 must add nothing, got {s}"
    );
}

#[test]
fn confidence_very_high_tier_boundary_at_58() {
    // entropy EXACTLY 5.8 is the very-high cutoff => full 0.20; a hair below
    // falls to the 0.12 partial tier.
    let mut at = signals();
    at.entropy = VERY_HIGH_ENTROPY_THRESHOLD; // 5.8
    let s_at = compute_confidence(&at);
    assert!(
        (s_at - 0.20).abs() < EPS,
        "entropy 5.8 must give the full 0.20 tier, got {s_at}"
    );

    let mut below = signals();
    below.entropy = 5.7999;
    let s_below = compute_confidence(&below);
    assert!(
        (s_below - 0.12).abs() < EPS,
        "entropy just below 5.8 must give 0.12, got {s_below}"
    );
}

#[test]
fn confidence_low_entropy_penalty_multiplies_by_06() {
    // entropy 1.5 (< 2.0) with match_length 11 (> 10) triggers the 0.6 penalty
    // on the whole normalized score: 0.35 * 0.6 = 0.21.
    let mut sig = signals();
    sig.has_literal_prefix = true;
    sig.entropy = 1.5;
    sig.match_length = 11;
    let s = compute_confidence(&sig);
    assert!(
        (s - 0.21).abs() < EPS,
        "low-entropy penalty must give 0.35*0.6=0.21, got {s}"
    );
}

#[test]
fn confidence_low_entropy_penalty_requires_length_over_10() {
    // Same low entropy but match_length EXACTLY 10 (not > 10) => no penalty, so
    // the score stays 0.35 (negative twin of the penalty case).
    let mut sig = signals();
    sig.has_literal_prefix = true;
    sig.entropy = 1.5;
    sig.match_length = 10;
    let s = compute_confidence(&sig);
    assert!(
        (s - 0.35).abs() < EPS,
        "match_length 10 must not penalize, got {s}"
    );
}

#[test]
fn confidence_low_entropy_penalty_floor_is_strict_less_than_2() {
    // entropy EXACTLY 2.0 is NOT below the 2.0 penalty floor, so even a long
    // match is unpenalized: 0.35 stays 0.35.
    let mut sig = signals();
    sig.has_literal_prefix = true;
    sig.entropy = 2.0;
    sig.match_length = 50;
    let s = compute_confidence(&sig);
    assert!(
        (s - 0.35).abs() < EPS,
        "entropy exactly 2.0 must not penalize, got {s}"
    );
}

#[test]
fn confidence_all_signals_true_reaches_full_one() {
    // Every weight fires (0.35+0.20+0.20+0.10+0.10+0.05 = 1.00) with a very-high
    // entropy that is above the 2.0 penalty floor, so the score is exactly 1.0.
    let sig = ConfidenceSignals {
        has_literal_prefix: true,
        has_context_anchor: true,
        entropy: 6.0,
        keyword_nearby: true,
        sensitive_file: true,
        match_length: 40,
        has_companion: true,
    };
    let s = compute_confidence(&sig);
    assert!(
        (s - 1.0).abs() < EPS,
        "all-signals confidence must be 1.0, got {s}"
    );
}

#[test]
fn confidence_penalty_composes_with_multiple_signals() {
    // Prefix (0.35) + context anchor (0.20) = 0.55 weighted sum; entropy 1.0
    // (< 2.0) with len 20 (> 10) applies the 0.6 penalty: 0.55 * 0.6 = 0.33.
    let mut sig = signals();
    sig.has_literal_prefix = true;
    sig.has_context_anchor = true;
    sig.entropy = 1.0;
    sig.match_length = 20;
    let s = compute_confidence(&sig);
    assert!(
        (s - 0.33).abs() < EPS,
        "0.55 weighted * 0.6 penalty must be 0.33, got {s}"
    );
}

#[test]
fn confidence_moderate_entropy_between_penalty_and_tier() {
    // entropy 2.5 sits above the 2.0 penalty floor (no penalty) but below the
    // 3.0 moderate tier (no entropy weight); only the 0.35 prefix survives.
    let mut sig = signals();
    sig.has_literal_prefix = true;
    sig.entropy = 2.5;
    sig.match_length = 50;
    let s = compute_confidence(&sig);
    assert!(
        (s - 0.35).abs() < EPS,
        "entropy 2.5 must yield 0.35 (no tier, no penalty), got {s}"
    );
}

// ─────────────────────────── published thresholds: values + ordering ───────

#[test]
fn entropy_thresholds_keep_their_tuned_values() {
    assert_eq!(LOW_ENTROPY_THRESHOLD, 3.0);
    assert_eq!(HIGH_ENTROPY_THRESHOLD, 4.5);
    assert_eq!(SENSITIVE_FILE_VERY_HIGH_ENTROPY_THRESHOLD, 5.5);
    assert_eq!(VERY_HIGH_ENTROPY_THRESHOLD, 5.8);
}

#[test]
fn entropy_thresholds_are_strictly_ordered() {
    // The detection ladder must climb: low keyword floor < high floor <
    // sensitive-file very-high < keyword-independent very-high.
    assert!(LOW_ENTROPY_THRESHOLD < HIGH_ENTROPY_THRESHOLD);
    assert!(HIGH_ENTROPY_THRESHOLD < SENSITIVE_FILE_VERY_HIGH_ENTROPY_THRESHOLD);
    assert!(SENSITIVE_FILE_VERY_HIGH_ENTROPY_THRESHOLD < VERY_HIGH_ENTROPY_THRESHOLD);
    // The very-high margin the confidence scorer derives (5.8 - 4.5 = 1.3) is
    // positive, so the very-high confidence tier always sits above the high tier.
    assert!((VERY_HIGH_ENTROPY_THRESHOLD - HIGH_ENTROPY_THRESHOLD - 1.3).abs() < EPS);
}
