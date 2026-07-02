//! Regression contract for the Shannon-entropy histogram reduction
//! (`crate::entropy::fast`: `histogram_8way` + `entropy_from_histogram`).
//!
//! Every assertion pins a CONCRETE bits/byte value, computed by hand from the
//! closed-form Shannon entropy `H = -Σ p·log2(p)` (base-2, so the unit is
//! bits/byte). The reduction has two internal branches keyed on `active_len`
//! (the count-·-log2-count table for `active_len <= 255`, the direct `p·log2 p`
//! form above that); the cases below deliberately straddle that boundary so
//! both branches are exercised and shown to agree on the same distribution.
//!
//! It also pins KeyHog's null-byte histogram contract: a *fully*-null 8-byte
//! chunk is dropped as binary padding (it leaves `active_len`), but a null that
//! merely lives *inside* an otherwise-non-null chunk is counted as a real
//! symbol, and a lone trailing null in the sub-8 remainder drops out.
//!
//! Driven through the public `keyhog_scanner::testing` facade:
//!   - `testing::entropy_fast::shannon_entropy_simd` — the arch-dispatched
//!     entropy entry point (all ISA paths share the one exact reduction).
//!   - `testing::match_entropy` — the pipeline entry (cache → same reduction),
//!     used to prove the cached path agrees bit-for-bit with the direct one.
//!   - `testing::confidence::unique_byte_count` — the distinct-symbol primitive
//!     that caps entropy at `log2(unique)`.

use keyhog_scanner::testing::confidence::unique_byte_count;
use keyhog_scanner::testing::entropy_fast::shannon_entropy_simd as shannon;
use keyhog_scanner::testing::match_entropy;

/// Absolute f64 tolerance for entropy comparisons (few-ULP cross-branch drift).
const EPS: f64 = 1e-6;

#[track_caller]
fn assert_close(actual: f64, expected: f64) {
    assert!(
        (actual - expected).abs() < EPS,
        "entropy mismatch: actual={actual:.15}, expected={expected:.15}, |Δ|={:.3e}",
        (actual - expected).abs()
    );
}

// ------------------------------------------------------------------ boundaries

#[test]
fn empty_input_is_exactly_zero() {
    // Early `data.is_empty()` return: a literal 0.0, so assert exact equality
    // (not just within epsilon).
    let v: &[u8] = b"";
    assert_eq!(shannon(v), 0.0);
}

#[test]
fn single_byte_is_zero() {
    // active_len == 1: table branch gives log2(1) - table[1]/1 = 0 - 0 = 0.
    assert_close(shannon(b"A"), 0.0);
}

#[test]
fn all_same_byte_is_zero() {
    // 100 identical non-null bytes: one bin holds the whole mass, so H = 0.
    let all_a = vec![b'A'; 100];
    assert_close(shannon(&all_a), 0.0);
}

// ------------------------------------------------------------ canonical values

#[test]
fn uniform_256_distinct_is_eight_bits() {
    // Every byte value 0..=255 exactly once. active_len = 256 (> 255 → direct
    // branch). H = -Σ (1/256)·log2(1/256) = log2(256) = 8.0 bits/byte — the
    // maximum for a byte alphabet. The leading 0x00 is COUNTED (its 8-byte
    // chunk [0,1,2,3,4,5,6,7] is not all-null), which is exactly why
    // active_len stays 256 and the result is exactly 8.0.
    let all_bytes: Vec<u8> = (0u8..=255).collect();
    assert_eq!(all_bytes.len(), 256);
    assert_close(shannon(&all_bytes), 8.0);
}

#[test]
fn two_symbol_fifty_fifty_short_is_one_bit() {
    // "ABABABAB": counts A=4, B=4, active_len=8 (<=255 → table branch).
    // H = log2(8) - (4·log2 4 + 4·log2 4)/8 = 3 - 16/8 = 1.0 bit/byte.
    assert_close(shannon(b"ABABABAB"), 1.0);
}

#[test]
fn two_symbol_fifty_fifty_long_is_one_bit() {
    // Same 50/50 distribution but 300 bytes so active_len > 255 selects the
    // DIRECT reduction branch. It must land on the identical 1.0 bit/byte,
    // proving the two internal branches agree on one distribution.
    let mut data = vec![b'A'; 150];
    data.extend(std::iter::repeat(b'B').take(150));
    assert_eq!(data.len(), 300);
    assert_close(shannon(&data), 1.0);
}

#[test]
fn hello_known_bit_value() {
    // "hello": h=1,e=1,l=2,o=1 over 5 bytes.
    // H = log2(5) - (2·log2 2)/5 = 2.321928094887362 - 0.4
    //   = 1.9219280948873623 bits/byte.
    assert_close(shannon(b"hello"), 1.921_928_094_887_362_3);
}

#[test]
fn three_to_one_split_known_value() {
    // "aaab": a=3, b=1 over 4 bytes.
    // H = log2(4) - (3·log2 3)/4 = 2 - 4.754887502163468/4
    //   = 0.8112781244591327 bits/byte (the classic 3:1 Shannon value).
    assert_close(shannon(b"aaab"), 0.811_278_124_459_132_7);
}

// -------------------------------------------------- null-byte histogram contract

#[test]
fn trailing_null_chunk_is_dropped_as_padding() {
    // "ABCDEFGH" + eight 0x00. The second 8-byte chunk is fully null → dropped,
    // so active_len = 8 over 8 distinct symbols. H = log2(8) = 3.0 bits/byte.
    let data = b"ABCDEFGH\0\0\0\0\0\0\0\0";
    assert_close(shannon(data), 3.0);
}

#[test]
fn all_null_input_is_zero() {
    // Every 8-byte chunk is fully null → all dropped → active_len == 0 →
    // the reduction's `active_len == 0` guard returns a literal 0.0.
    let nulls = vec![0u8; 16];
    assert_eq!(shannon(&nulls), 0.0);
}

#[test]
fn null_inside_nonnull_chunk_is_counted() {
    // "A\0AAAAAA": a single 0x00 embedded in an otherwise-non-null 8-byte chunk.
    // The chunk is NOT all-null, so the null is counted as a real symbol:
    // A=7, 0x00=1 over active_len=8.
    // H = log2(8) - (7·log2 7)/8 = 3 - 19.651484454403228/8
    //   = 0.5435644431995964 bits/byte. (If the null were wrongly dropped this
    // would collapse toward 0.)
    let data = b"A\0AAAAAA";
    assert_close(shannon(data), 0.543_564_443_199_596_4);
}

#[test]
fn trailing_null_in_remainder_drops_out() {
    // "ABC\0" is entirely in the sub-8 remainder path; the lone trailing null is
    // dropped (active_len 3), so it scores identically to "ABC":
    // H = log2(3) = 1.584962500721156 bits/byte.
    let with_null = shannon(b"ABC\0");
    let without_null = shannon(b"ABC");
    assert_close(with_null, 1.584_962_500_721_156);
    assert_close(with_null, without_null);
}

// ------------------------------------------------------------------ invariance

#[test]
fn entropy_invariant_to_byte_identity() {
    // Entropy depends only on the multiset of counts, not on WHICH byte values
    // carry them. Two disjoint 3:1 alphabets must produce the identical f64.
    let a = shannon(b"aaab");
    let b = shannon(b"xxxy");
    assert_close(a, b);
    assert_close(a, 0.811_278_124_459_132_7);
}

// ------------------------------------------------------- cross-seam consistency

#[test]
fn match_entropy_seam_agrees_with_direct_reduction() {
    // The pipeline seam (`match_entropy`) routes through the ≤1KB entropy cache
    // and must return the SAME bits/byte as the direct SIMD entry point, and
    // the same hand-computed "hello" value.
    let cached = match_entropy(b"hello");
    let direct = shannon(b"hello");
    assert_close(cached, direct);
    assert_close(cached, 1.921_928_094_887_362_3);
}

// --------------------------------------------------- distinct-symbol primitive

#[test]
fn unique_byte_count_pins_alphabet_size() {
    // The distinct-byte count caps entropy at log2(unique). Pin its exact
    // integer output on empty, a small string, and the full byte range, then
    // tie it to the entropy ceiling for the uniform-256 case (log2(256) == 8).
    let empty: &[u8] = b"";
    assert_eq!(unique_byte_count(empty), 0);
    assert_eq!(unique_byte_count(b"hello"), 4); // {h,e,l,o}
    assert_eq!(unique_byte_count(b"aaab"), 2); // {a,b}

    let all_bytes: Vec<u8> = (0u8..=255).collect();
    assert_eq!(unique_byte_count(&all_bytes), 256);
    // Ceiling log2(256) == 8 is exactly reached by the uniform distribution.
    assert_close((unique_byte_count(&all_bytes) as f64).log2(), 8.0);
    assert_close(shannon(&all_bytes), 8.0);
}
