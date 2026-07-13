/// Extended unit tests for `keyhog_scanner::testing::entropy_fast::shannon_entropy_scalar`.
///
/// Covers: empty slice, single byte, two bytes, exactly-2-byte all-same,
/// uniform-256 distribution (max entropy = 8.0), power-of-2 distributions, and
/// remainder/large-slice histogram correctness. The scalar↔simd differential
/// parity invariant lives in `sub_facade::sub_entropy` (`shannon_scalar_matches_simd_on_many_inputs`).
use keyhog_scanner::testing::entropy_fast::shannon_entropy_scalar;

// ── shannon_entropy_scalar: boundary values ────────────────────────────────────

#[test]
fn entropy_empty_slice_is_zero() {
    assert_eq!(shannon_entropy_scalar(&[]), 0.0);
}

#[test]
fn entropy_single_byte_is_zero() {
    // P(x) = 1.0 → H = -1.0 * log2(1.0) = 0
    assert_eq!(shannon_entropy_scalar(&[0x42]), 0.0);
}

#[test]
fn entropy_two_equal_bytes_is_zero() {
    assert_eq!(shannon_entropy_scalar(&[0x42, 0x42]), 0.0);
}

#[test]
fn entropy_two_distinct_bytes_is_one() {
    // Perfectly balanced binary: H = 1.0
    let data = vec![0xAAu8, 0xBBu8];
    let e = shannon_entropy_scalar(&data);
    assert!(
        (e - 1.0).abs() < 1e-9,
        "two distinct bytes → H=1.0, got {e}"
    );
}

#[test]
fn entropy_uniform_256_distribution_is_eight() {
    // One occurrence of each of 256 symbols → H = log2(256) = 8.0
    let data: Vec<u8> = (0..=255u8).collect();
    let e = shannon_entropy_scalar(&data);
    assert!((e - 8.0).abs() < 0.01, "uniform-256 → H≈8.0, got {e}");
}

#[test]
fn entropy_all_same_byte_repeated_1000_is_zero() {
    let data = vec![0x41u8; 1000];
    assert_eq!(shannon_entropy_scalar(&data), 0.0);
}

#[test]
fn entropy_power_of_two_alphabet_matches_log2() {
    // 4 distinct equally-likely symbols → H = log2(4) = 2.0
    let data: Vec<u8> = [0u8, 1, 2, 3].iter().cycle().take(1000).copied().collect();
    let e = shannon_entropy_scalar(&data);
    assert!((e - 2.0).abs() < 0.001, "4-symbol uniform → H≈2.0, got {e}");
}

#[test]
fn entropy_increases_with_symbol_diversity() {
    let low: Vec<u8> = vec![0u8; 100]; // single symbol
    let medium: Vec<u8> = [0u8, 1].iter().cycle().take(100).copied().collect(); // 2 symbols
    let high: Vec<u8> = (0..100u8).collect(); // 100 distinct symbols
    assert!(
        shannon_entropy_scalar(&low) < shannon_entropy_scalar(&medium),
        "more symbols → higher entropy"
    );
    assert!(
        shannon_entropy_scalar(&medium) < shannon_entropy_scalar(&high),
        "even more symbols → even higher entropy"
    );
}

#[test]
fn entropy_remainder_bytes_counted_correctly() {
    // chunks_exact(4) has remainder (test that remainder bytes aren't missed).
    // Data: 5 bytes where the 5th is unique (breaks a pure-AB pattern).
    let data = vec![0xAAu8, 0xBB, 0xAA, 0xBB, 0xCC];
    let e = shannon_entropy_scalar(&data);
    // 3 symbols, not uniform → should be > 1.0 but < 8.0
    assert!(e > 1.0 && e < 8.0, "3-symbol non-uniform: {e}");
}

#[test]
fn entropy_large_slice_does_not_overflow() {
    // 256 * 1024 = 262144 bytes, each value appearing 1024 times
    let data: Vec<u8> = (0..=255u8).cycle().take(256 * 1024).collect();
    let e = shannon_entropy_scalar(&data);
    assert!((e - 8.0).abs() < 0.01, "large uniform-256 → H≈8.0, got {e}");
}
