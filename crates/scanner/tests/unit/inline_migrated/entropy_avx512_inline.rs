//! Migrated from src/entropy_avx512.rs

use keyhog_scanner::entropy_fast::shannon_entropy_scalar;
use keyhog_scanner::testing::calculate_shannon_entropy;

/// Reference Shannon entropy for test validation.
fn reference_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

#[test]
fn empty_input() {
    assert_eq!(shannon_entropy_scalar(&[]), 0.0);
}

#[test]
fn single_byte() {
    let data = [42u8];
    let expected = reference_entropy(&data);
    let actual = shannon_entropy_scalar(&data);
    assert!(
        (actual - expected).abs() < 1e-9,
        "expected {expected}, got {actual}"
    );
}

#[test]
fn uniform_distribution() {
    // 256 unique bytes: entropy should be exactly 8.0
    let data: Vec<u8> = (0..=255).collect();
    let expected = reference_entropy(&data);
    let actual = shannon_entropy_scalar(&data);
    assert!(
        (actual - expected).abs() < 1e-6,
        "expected {expected}, got {actual}"
    );
}

#[test]
fn repeated_single_byte() {
    // All same byte: entropy should be 0.0
    let data = vec![0xAA; 1024];
    let expected = reference_entropy(&data);
    let actual = shannon_entropy_scalar(&data);
    assert!(
        (actual - expected).abs() < 1e-9,
        "expected {expected}, got {actual}"
    );
}

#[test]
fn realistic_base64_secret() {
    let secret = b"ghp_R0FGZk5qTXhPcUxaWDR0U1ByT2xKM0ZhRGVTYkVwOFJwNndsZXhF";
    let expected = reference_entropy(secret);
    let actual = shannon_entropy_scalar(secret);
    assert!(
        (actual - expected).abs() < 1e-9,
        "expected {expected}, got {actual}"
    );
}

#[test]
#[cfg(target_arch = "x86_64")]
fn avx512_matches_reference() {
    if !(is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512bw")) {
        return; // skip on hardware without AVX-512
    }
    // Test various sizes including non-aligned
    for size in [
        0, 1, 15, 16, 17, 31, 32, 63, 64, 100, 255, 256, 512, 1024, 4096,
    ] {
        let data: Vec<u8> = (0..size).map(|i| (i * 37 + 13) as u8).collect();
        let expected = reference_entropy(&data);
        let actual = unsafe { calculate_shannon_entropy(&data) };
        // The 5-term polynomial log2 approximation has ~1% relative error.
        // 0.05 tolerance validates correctness while accommodating the
        // approximation (keyhog only needs threshold comparison, not exact math).
        assert!(
            (actual - expected).abs() < 0.05,
            "size={size}: expected {expected}, got {actual}, delta={}",
            (actual - expected).abs()
        );
    }
}
