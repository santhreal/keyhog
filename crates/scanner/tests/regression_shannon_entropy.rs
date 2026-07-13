//! Truth-pinned regression coverage for the Shannon-entropy primitive
//! (`crates/scanner/src/entropy/mod.rs` `shannon_entropy` / `normalized_entropy`
//! and the SIMD dispatcher `crates/scanner/src/entropy/fast.rs`).
//!
//! Every assertion is an EXACT closed-form bits/byte value derived by hand from
//! `H = -Σ p·log2 p`, never a shape/`is_empty` check. The suite deliberately
//! drives BOTH reduction branches in `entropy_from_histogram`
//! (`active_len <= 255` log2-table path and the `> 255` direct path), the
//! `> 1024` uncached path in `shannon_entropy`, and the 8-byte null-padding
//! contract in `histogram_8way`.
//!
//! HOST-INDEPENDENCE: `shannon_entropy` (cached public entry) and
//! `shannon_entropy_simd` (raw dispatcher) reduce through the SAME exact
//! `f64::log2` reduction on every ISA, so the asserted values hold on scalar,
//! SSE2, AVX2, AVX-512 and Neon alike (no accelerator is assumed).

use keyhog_scanner::entropy::{normalized_entropy, shannon_entropy};
use keyhog_scanner::testing::entropy_fast::shannon_entropy_simd;

/// Tolerance for values that are exact in theory but pass through an
/// `f64::log2` reduction. Every expected value below is either an integer, a
/// power-of-two log (representable exactly), or a `count·log2(count)` table
/// expression evaluated identically to production; 1e-9 is generous headroom.
const EPS: f64 = 1e-9;

fn close(a: f64, b: f64) -> bool {
    (a - b).abs() < EPS
}

// ───────────────────────── degenerate / boundary distributions ─────────────

#[test]
fn all_same_char_is_exactly_zero() {
    // One distinct symbol carries 0 information: log2(8) - table[8]/8
    // = 3 - (8*log2(8))/8 = 3 - 3 = 0.
    let e = shannon_entropy(b"aaaaaaaa");
    assert!(close(e, 0.0), "all-same-char entropy must be 0.0, got {e}");
}

#[test]
fn single_byte_is_zero() {
    // active_len == 1: log2(1) - table[1]/1 = 0 - 0 = 0.
    let e = shannon_entropy(b"a");
    assert!(close(e, 0.0), "single-byte entropy must be 0.0, got {e}");
}

#[test]
fn two_equiprobable_symbols_is_one_bit() {
    // 1×'a' + 1×'b': log2(2) - 0 = 1.0 bit/byte.
    let e = shannon_entropy(b"ab");
    assert!(close(e, 1.0), "two-symbol entropy must be 1.0, got {e}");
}

#[test]
fn skewed_three_to_one_has_exact_fractional_entropy() {
    // 3×'a' + 1×'b' over len 4: H = log2(4) - (3*log2(3))/4 = 2 - 0.75*log2(3).
    // = 2 - 1.188721875540867 = 0.8112781244591328 bits/byte.
    let e = shannon_entropy(b"aaab");
    let expected = 2.0 - 3.0 * 3.0f64.log2() / 4.0;
    assert!(
        close(expected, 0.8112781244591328),
        "hand value drift: {expected}"
    );
    assert!(
        close(e, 0.8112781244591328),
        "3:1 skew entropy must be 0.8112781244591328, got {e}"
    );
}

// ─────────────────────── equiprobable → log2(k) exact ceilings ──────────────

#[test]
fn eight_distinct_bytes_is_three_bits() {
    // 8 distinct chars, each once: log2(8) = 3.0.
    let e = shannon_entropy(b"ABCDEFGH");
    assert!(close(e, 3.0), "8-distinct entropy must be 3.0, got {e}");
}

#[test]
fn sixteen_hex_distinct_is_four_bits() {
    // A 16-char hex string with every nibble once: log2(16) = 4.0.
    let e = shannon_entropy(b"0123456789abcdef");
    assert!(close(e, 4.0), "16-hex entropy must be 4.0, got {e}");
}

#[test]
fn monotonic_with_distinct_equiprobable_symbol_count() {
    // Widening the equiprobable alphabet strictly raises entropy by exactly one
    // bit per doubling of distinct symbols: 0 < 1 < 2 < 4 with exact values.
    let e1 = shannon_entropy(b"aaaa"); // 1 symbol  -> 0.0
    let e2 = shannon_entropy(b"abab"); // 2 symbols -> 1.0
    let e4 = shannon_entropy(b"abcd"); // 4 symbols -> 2.0
    let e16 = shannon_entropy(b"0123456789abcdef"); // 16 symbols -> 4.0
    assert!(close(e1, 0.0), "got {e1}");
    assert!(close(e2, 1.0), "got {e2}");
    assert!(close(e4, 2.0), "got {e4}");
    assert!(close(e16, 4.0), "got {e16}");
    assert!(
        e1 < e2 && e2 < e4 && e4 < e16,
        "entropy must be strictly monotone"
    );
}

// ─────────── reduction-branch coverage: table (<=255) vs direct (>255) ───────

#[test]
fn table_and_direct_branches_agree_at_two_bits() {
    // Same uniform 4-symbol distribution on both sides of the active_len==255
    // branch boundary in entropy_from_histogram. Both must yield exactly 2.0.
    let table_side = "abcd".repeat(63); // 252 bytes  -> <=255 table branch
    let direct_side = "abcd".repeat(64); // 256 bytes -> >255 direct branch
    assert_eq!(table_side.len(), 252);
    assert_eq!(direct_side.len(), 256);
    let et = shannon_entropy(table_side.as_bytes());
    let ed = shannon_entropy(direct_side.as_bytes());
    assert!(close(et, 2.0), "table-branch entropy must be 2.0, got {et}");
    assert!(
        close(ed, 2.0),
        "direct-branch entropy must be 2.0, got {ed}"
    );
}

#[test]
fn large_uniform_input_uses_uncached_direct_path_and_stays_four_bits() {
    // 1600 bytes > 1024 bypasses the thread-local cache (uncached path) AND
    // active_len 1600 > 255 takes the direct -Σ p·log2 p reduction. A uniform
    // 16-symbol alphabet is still exactly log2(16) = 4.0.
    let big = "0123456789abcdef".repeat(100);
    assert_eq!(big.len(), 1600);
    let e = shannon_entropy(big.as_bytes());
    assert!(
        close(e, 4.0),
        "1600-byte uniform-16 entropy must be 4.0, got {e}"
    );
}

// ───────────────────────────── null-padding contract ───────────────────────

#[test]
fn fully_null_eight_byte_chunk_is_skipped_as_padding() {
    // "aaaaaaaa" + eight NULs: the all-null chunk drops from active_len, leaving
    // 8 'a' -> entropy 0.0. If nulls were counted it would be 1.0, so this pins
    // the histogram_8way padding contract.
    let e = shannon_entropy(b"aaaaaaaa\0\0\0\0\0\0\0\0");
    assert!(
        close(e, 0.0),
        "null-padded all-same entropy must be 0.0, got {e}"
    );
}

#[test]
fn null_inside_a_mixed_chunk_is_counted_not_dropped() {
    // A single NUL inside an otherwise non-null 8-byte chunk is counted in full
    // (only whole all-null chunks / lone trailing nulls drop). 7×'a' + 1×NUL:
    // H = log2(8) - (7*log2(7))/8 = 0.5435644431995966 bits/byte.
    let e = shannon_entropy(b"aaa\0aaaa");
    let expected = 3.0 - 7.0 * 7.0f64.log2() / 8.0;
    assert!(
        close(expected, 0.5435644431995966),
        "hand value drift: {expected}"
    );
    assert!(
        close(e, 0.5435644431995966),
        "in-chunk-null entropy must be 0.5435644431995966, got {e}"
    );
}

// ─────────────────── cached public entry ≡ raw SIMD dispatcher ──────────────

#[test]
fn cached_public_entry_matches_simd_dispatcher_bit_for_bit() {
    // The cached wrapper must return exactly what the raw dispatcher computes,
    // and a mixed credential-shaped token must not perturb that equality.
    let v = b"s3cr3t_Tok3n/9aZ+Qw==Xy07";
    let cached = shannon_entropy(v);
    let raw = shannon_entropy_simd(v);
    assert_eq!(
        cached.to_bits(),
        raw.to_bits(),
        "cached public entry and SIMD dispatcher must agree bit-for-bit"
    );
    // Repeat call (cache hit) is identical bits.
    assert_eq!(shannon_entropy(v).to_bits(), cached.to_bits());
}

#[test]
fn empty_input_is_zero_on_both_entry_points() {
    assert!(close(shannon_entropy(b""), 0.0));
    assert!(close(shannon_entropy_simd(b""), 0.0));
}

// ───────────────────────────── normalized_entropy ──────────────────────────

#[test]
fn normalized_entropy_of_equiprobable_alphabet_is_one() {
    // shannon / log2(unique) = log2(4)/log2(4) = 1.0 for a uniform alphabet.
    let e = normalized_entropy(b"abcd");
    assert!(
        close(e, 1.0),
        "normalized uniform entropy must be 1.0, got {e}"
    );
}

#[test]
fn normalized_entropy_all_same_and_empty_are_zero() {
    // unique <= 1 short-circuits to 0.0; empty short-circuits to 0.0.
    let same = normalized_entropy(b"aaaa");
    let empty = normalized_entropy(b"");
    assert!(
        close(same, 0.0),
        "all-same normalized entropy must be 0.0, got {same}"
    );
    assert!(
        close(empty, 0.0),
        "empty normalized entropy must be 0.0, got {empty}"
    );
}

#[test]
fn normalized_entropy_skewed_equals_shannon_over_log2_unique() {
    // 3×'a' + 1×'b': unique = 2, log2(2) = 1, so normalized == raw shannon
    // = 0.8112781244591328.
    let raw = shannon_entropy(b"aaab");
    let norm = normalized_entropy(b"aaab");
    assert!(close(raw, 0.8112781244591328), "raw drift: {raw}");
    assert!(
        close(norm, raw),
        "normalized (÷log2(2)=÷1) must equal raw shannon, got {norm} vs {raw}"
    );
}
