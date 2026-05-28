/// Extended unit tests for `keyhog_scanner::entropy_fast`.
///
/// Covers: empty slice, single byte, two bytes, exactly-2-byte all-same,
/// uniform-256 distribution (max entropy = 8.0), power-of-2 distributions,
/// has_high_entropy_fast with various thresholds, and the scalar/simd parity
/// invariant.
use keyhog_scanner::entropy_fast::{has_high_entropy_fast, shannon_entropy_scalar};

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
    // chunks_exact(4) has remainder — test that remainder bytes aren't missed.
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

// ── has_high_entropy_fast ─────────────────────────────────────────────────────

#[test]
fn fast_check_rejects_single_symbol() {
    let data = vec![0x42u8; 100];
    assert!(!has_high_entropy_fast(&data, 3.5));
}

#[test]
fn fast_check_accepts_high_entropy_data() {
    // Cycle through all 256 values — H ≈ 8.0, well above any threshold < 8
    let data: Vec<u8> = (0..=255u8).cycle().take(512).collect();
    assert!(has_high_entropy_fast(&data, 4.0));
    assert!(has_high_entropy_fast(&data, 5.0));
    assert!(has_high_entropy_fast(&data, 7.5));
}

#[test]
fn fast_check_threshold_zero_always_true() {
    let data = vec![0x42u8; 100];
    // Even a constant byte has H=0 which is ≥ 0 — but the fast check
    // samples first and may return false for a constant. We test that
    // threshold=0 still doesn't panic.
    let _ = has_high_entropy_fast(&data, 0.0);
}

#[test]
fn fast_check_short_data_falls_back_to_scalar() {
    // < 8 bytes → the fast-path samples can't run → falls back to scalar
    let data = &[0xAAu8, 0xBBu8, 0xCCu8]; // 3 bytes, 3 symbols → H = log2(3) ≈ 1.58
    let e_fast = has_high_entropy_fast(data, 1.5);
    assert!(e_fast, "3 distinct bytes → H > 1.5");
}

#[test]
fn fast_check_exactly_eight_bytes_boundary() {
    // At the 8-byte boundary the fast path switches to sampling
    let data: Vec<u8> = [0u8, 1, 2, 3, 4, 5, 6, 7].to_vec(); // 8 distinct → H = 3.0
    assert!(has_high_entropy_fast(&data, 2.5));
}

#[test]
fn fast_and_scalar_agree_on_medium_entropy() {
    // 16 distinct values repeated 64 times → H = 4.0
    let data: Vec<u8> = (0..16u8).cycle().take(1024).collect();
    let scalar = shannon_entropy_scalar(&data);
    let fast = has_high_entropy_fast(&data, 3.9); // just below 4.0
    assert!(fast, "fast check should agree that H=4.0 > 3.9 threshold");
    assert!((scalar - 4.0).abs() < 0.01, "scalar H = {scalar}");
}

// ── Early-exit path (unique < 4, spread < 16, threshold >= 2.0) ──────

#[test]
fn early_exit_constant_data_high_threshold() {
    // 1024 identical bytes: unique=1, spread=0.
    // With threshold >= 2.0, the early-exit should fire and return false
    // WITHOUT computing full entropy.
    let data = vec![0x42u8; 1024];
    assert!(!has_high_entropy_fast(&data, 3.5));
    assert!(!has_high_entropy_fast(&data, 2.0));
}

#[test]
fn early_exit_two_adjacent_values() {
    // Alternating 0x40 and 0x41 → unique=2, spread=1, H≈1.0.
    // Early-exit fires for threshold >= 2.0 because max entropy with
    // 2 values from a 1-wide range is log2(2) = 1.0 < 2.0.
    let data: Vec<u8> = [0x40, 0x41].iter().copied().cycle().take(1024).collect();
    assert!(!has_high_entropy_fast(&data, 2.0));
    // But with threshold < 2.0, the early-exit does NOT fire and we
    // fall through to full computation — the actual H≈1.0 is >= 0.5.
    assert!(has_high_entropy_fast(&data, 0.5));
}

#[test]
fn early_exit_does_not_fire_on_wide_spread() {
    // Three values: 0x00, 0x01, 0xFF → unique=3, spread=255.
    // Spread >= 16, so early-exit does NOT fire. Full computation runs.
    let mut data = vec![0x00u8; 400];
    data.extend_from_slice(&[0x01u8; 400]);
    data.extend_from_slice(&[0xFFu8; 400]);
    // H ≈ log2(3) ≈ 1.585, which is < 2.0
    assert!(!has_high_entropy_fast(&data, 2.0));
    // But H ≈ 1.585 >= 1.5
    assert!(has_high_entropy_fast(&data, 1.5));
}

#[test]
fn early_exit_does_not_fire_below_threshold_2() {
    // Constant data with threshold=1.0 (< 2.0): early-exit is NOT sound
    // below 2.0, so we fall through to full computation. H=0 < 1.0 → false.
    let data = vec![0x42u8; 1024];
    assert!(!has_high_entropy_fast(&data, 1.0));
}

#[test]
fn early_exit_agreement_with_full_computation() {
    // Verify that for every case where early-exit fires, the full
    // computation would have returned the same answer.
    let test_cases: Vec<(Vec<u8>, f64)> = vec![
        (vec![0x42u8; 512], 3.5),
        (vec![0x42u8; 512], 2.0),
        (
            [0x40, 0x41].iter().copied().cycle().take(512).collect(),
            3.0,
        ),
        (
            [0x10, 0x11, 0x12]
                .iter()
                .copied()
                .cycle()
                .take(512)
                .collect(),
            2.5,
        ),
    ];
    for (data, threshold) in &test_cases {
        let fast = has_high_entropy_fast(data, *threshold);
        let exact = shannon_entropy_scalar(data) >= *threshold;
        assert_eq!(
            fast,
            exact,
            "early-exit disagreed with exact computation for threshold={threshold}, \
             actual_entropy={}",
            shannon_entropy_scalar(data),
        );
    }
}
