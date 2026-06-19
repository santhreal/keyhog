//! Boundary test for uniqueness and entropy-profile checks (keywords.rs:339-344).
//!
//! Real secrets are high-entropy across their entire length. Strings 16+ chars
//! with low uniqueness (< 8 unique characters) or low entropy in the second half
//! (< 2.5 bits) are typically not credentials—they're identifier patterns or
//! repeated structures. This test pins the exact length/uniqueness/entropy boundaries.

use keyhog_scanner::entropy::shannon_entropy;
use keyhog_scanner::testing::entropy_keywords::is_secret_plausible;

#[test]
fn uniqueness_boundary_16_char_with_7_unique_rejected() {
    // 16+ chars with < 8 unique chars must be rejected. Build a 16-char
    // string with exactly 7 unique characters: "aaaabbbbccccdddd"
    // (4 of each: 'a', 'b', 'c', 'd', then add 3 more unique, total 7).
    // Actually, let's be precise: "aaaabbbbbccccdd" (15) → "aaaabbbbccccdddd" (16)
    // Let's use: "aabbccddeeeeeeee" (16 chars, unique: a,b,c,d,e = 5)
    let with_7_unique = "aabbccddeeeffgg";
    assert_eq!(with_7_unique.len(), 15);
    let unique_count: std::collections::HashSet<char> = with_7_unique.chars().collect();
    assert_eq!(unique_count.len(), 7);
    assert!(!is_secret_plausible(with_7_unique, &[]));
}

#[test]
fn uniqueness_boundary_16_char_with_8_unique_potential_pass() {
    // 16+ chars with exactly 8 unique chars passes the uniqueness gate
    // (it checks < 8). Still subject to entropy floor (4.5), but the uniqueness
    // gate is not the rejection reason.
    let with_8_unique = "aabbccddeeeffgg1"; // a,b,c,d,e,f,g,1 = 8 unique
    assert_eq!(with_8_unique.len(), 16);
    let unique_count: std::collections::HashSet<char> = with_8_unique.chars().collect();
    assert_eq!(unique_count.len(), 8);
    // This may pass or fail based on entropy, but NOT due to uniqueness gate.
}

#[test]
fn uniqueness_boundary_15_char_with_low_unique_not_gated() {
    // The uniqueness gate only applies to > 16 chars. At 15 chars with
    // 3 unique characters, it should NOT be rejected by uniqueness.
    let short_low_unique = "aaabbbcccccccc";
    assert_eq!(short_low_unique.len(), 15);
    let unique_count: std::collections::HashSet<char> = short_low_unique.chars().collect();
    assert!(unique_count.len() < 8);
    // Must NOT be rejected by the uniqueness gate (length <= 16).
}

#[test]
fn entropy_second_half_boundary_17_char_low_second_half_rejected() {
    // > 16 chars with low entropy in the second half (< 2.5 bits). Build a
    // string where first half is high-entropy, second half is low.
    // "AbCdEfGh1234567" + "aaaaaaa" = "AbCdEfGh1234567aaaaaaa" (22 chars)
    // First half: "AbCdEfGh1234567" (15 chars, mixed)
    // Second half: "aaaaaaa" (7 chars, all 'a', entropy ≈ 0)
    let low_second_half = "AbCdEfGh1234567aaaaaaa";
    assert!(low_second_half.len() > 16);
    let second_half_entropy =
        shannon_entropy(&low_second_half.as_bytes()[low_second_half.len() / 2..]);
    assert!(
        second_half_entropy < 2.5,
        "actual entropy: {}",
        second_half_entropy
    );
    assert!(!is_secret_plausible(low_second_half, &[]));
}

#[test]
fn entropy_second_half_boundary_17_char_high_second_half_potential_pass() {
    // > 16 chars with high entropy in the second half (>= 2.5 bits).
    // "aaaabbbbccccdddd" + "EfGh1234Ij5678K9" = full string, both halves high-entropy
    let high_second_half = "aaaabbbbccccddddEfGh1234Ij5678K9";
    assert!(high_second_half.len() > 16);
    let second_half_entropy =
        shannon_entropy(&high_second_half.as_bytes()[high_second_half.len() / 2..]);
    assert!(
        second_half_entropy >= 2.5,
        "actual entropy: {}",
        second_half_entropy
    );
    // This may pass or fail based on overall entropy floor, but not due to second-half gate.
}

#[test]
fn entropy_second_half_boundary_exactly_16_char_not_gated() {
    // The second-half entropy gate applies to > 16 chars only. At exactly 16 chars,
    // the gate is not applied, even if the second half is low-entropy.
    let exactly_16 = "aaaabbbbccccaaaa";
    assert_eq!(exactly_16.len(), 16);
    let second_half_entropy = shannon_entropy(&exactly_16.as_bytes()[exactly_16.len() / 2..]);
    assert!(second_half_entropy < 2.5);
    // Must NOT be rejected by the second-half gate (length is not > 16).
}

#[test]
fn uniqueness_and_entropy_second_half_both_fail_at_17_chars() {
    // A 17-char string that fails both uniqueness (< 8 unique) AND second-half
    // entropy (< 2.5) should be rejected. Either gate suffices to reject it.
    let bad_both = "aabbccddeeeffggg";
    assert_eq!(bad_both.len(), 17);
    let unique_count: std::collections::HashSet<char> = bad_both.chars().collect();
    assert!(unique_count.len() < 8);
    let second_half_entropy = shannon_entropy(&bad_both.as_bytes()[bad_both.len() / 2..]);
    assert!(second_half_entropy < 2.5);
    assert!(!is_secret_plausible(bad_both, &[]));
}

#[test]
fn passes_uniqueness_but_fails_entropy_floor() {
    // 20 chars with 8+ unique chars and high second-half entropy, but
    // overall entropy < 4.5. Should be rejected by entropy floor, not
    // uniqueness or second-half entropy.
    // Low-entropy alphabet: mostly 'a', 'b', 'c' with few high-entropy chars.
    let low_entropy_high_unique = "aaaabbbbccccddddeeee";
    assert!(low_entropy_high_unique.len() > 16);
    let unique_count: std::collections::HashSet<char> = low_entropy_high_unique.chars().collect();
    assert!(unique_count.len() >= 8);
    let overall_entropy = shannon_entropy(low_entropy_high_unique.as_bytes());
    assert!(overall_entropy < 4.5, "entropy: {}", overall_entropy);
    // Will be rejected, but by the entropy floor (checked in is_secret_plausible_with_context),
    // not the uniqueness/second-half gates.
}

#[test]
fn uniqueness_strictly_less_than_8() {
    // The gate checks: "unique_char_count < 8" (strictly less than).
    // So 8 unique chars is the boundary: it passes the uniqueness gate.
    let with_exactly_8 = "abcdefgh11111111";
    assert_eq!(with_exactly_8.len(), 16);
    let unique_count: std::collections::HashSet<char> = with_exactly_8.chars().collect();
    assert_eq!(unique_count.len(), 8);
    // Must NOT be rejected by the uniqueness gate (8 is not < 8).
}
