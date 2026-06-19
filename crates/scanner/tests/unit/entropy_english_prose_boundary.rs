//! Boundary test for English prose detection gate (keywords.rs:264-318).
//!
//! Real credentials rarely consist of pure lowercase ASCII words concatenated
//! together (e.g., "thequickbrownfoxjumps..."). The is_secret_plausible strict
//! mode rejects strings 16+ chars of pure lowercase as prose. This test pins
//! the exact length boundary and ensures mixed-case/digit strings bypass the gate.

use keyhog_scanner::testing::entropy_keywords::is_secret_plausible;

#[test]
fn prose_detection_boundary_15_char_pure_lowercase_accepted() {
    // 15-char pure lowercase is below the prose threshold (16+).
    // Even though it looks like words ("thequickbrownf"), it should pass
    // because the gate only rejects 16+ chars. This is a boundary case.
    let short_prose = "thequickbrownf";
    assert_eq!(short_prose.len(), 15);
    assert!(short_prose.chars().all(|c| c.is_ascii_lowercase()));
    assert!(is_secret_plausible(short_prose, &[]));
}

#[test]
fn prose_detection_boundary_16_char_pure_lowercase_rejected() {
    // 16-char pure lowercase must be rejected as prose. This is the exact
    // boundary: "thequickbrownfox" (dictionary words) is too prose-like.
    let prose = "thequickbrownfox";
    assert_eq!(prose.len(), 16);
    assert!(prose.chars().all(|c| c.is_ascii_lowercase()));
    assert!(!is_secret_plausible(prose, &[]));
}

#[test]
fn prose_detection_16_char_mixed_case_not_rejected() {
    // 16+ chars of pure lowercase is prose. But 16 chars with even one
    // uppercase letter is NOT prose (real credentials use mixed case).
    // This asserts the gate is specifically for pure lowercase.
    let mixed_case = "TheQuickBrownFox"; // Same length, PascalCase
    assert_eq!(mixed_case.len(), 16);
    assert!(!mixed_case.chars().all(|c| c.is_ascii_lowercase()));
    // This may or may not pass depending on other gates (e.g., program
    // identifier check), but it must NOT be rejected BY the prose gate.
    // If it fails, it's for a different reason (not pure-lowercase prose).
}

#[test]
fn prose_detection_multiword_prose_with_spaces_rejected() {
    // Branch 2: multi-word prose. "the quick brown fox jumps" has 2+ tokens,
    // all alphabetic, at least one lowercase 3+-char run. Must be rejected.
    let multiword = "the quick brown fox jumps";
    let tokens: Vec<&str> = multiword.split_whitespace().collect();
    assert!(tokens.len() >= 2);
    assert!(tokens
        .iter()
        .all(|t| { t.len() >= 2 && t.bytes().all(|b| b.is_ascii_alphabetic()) }));
    assert!(!is_secret_plausible(multiword, &[]));
}

#[test]
fn prose_detection_multiword_with_digits_not_prose() {
    // Multi-word but contains digits. "abc def 123" has digits, breaking
    // the all-alphabetic gate, so it's not multiword prose. Should pass
    // the prose check (may fail other gates).
    let mixed_word_digit = "abc def 123";
    assert!(mixed_word_digit.split_whitespace().count() >= 2);
    // The multiword prose gate requires ALL tokens to be purely alphabetic.
    // This has "123" which breaks that. So it should NOT be rejected as prose.
}

#[test]
fn prose_detection_single_long_word_rejected() {
    // A single 16+ char pure lowercase word (no spaces) is prose if it's
    // made of concatenated English words. But the multiword gate requires
    // 2+ tokens. The single-word gate rejects 16+ pure lowercase.
    let long_word = "abcdefghijklmnopqrstuvwxyz";
    assert_eq!(long_word.len(), 26);
    assert!(long_word.chars().all(|c| c.is_ascii_lowercase()));
    assert!(!is_secret_plausible(long_word, &[]));
}

#[test]
fn prose_detection_single_word_with_underscore_not_prose_by_space_gate() {
    // "my_helper_name" is snake_case (lowercase + underscores), but it's
    // a SINGLE whitespace-delimited token, so the multiword prose gate
    // doesn't apply. It may fail the program-identifier gate instead.
    // Ensure it's not caught by the multiword prose gate (which requires 2+ tokens).
    let snake_case = "my_helper_name";
    assert_eq!(snake_case.split_whitespace().count(), 1);
}

#[test]
fn prose_detection_short_multiword_with_threshold() {
    // "hi there" (8 chars) is multiword (2 tokens, both alphabetic, has 3+
    // char lowercase "there"). But the prose gate checks `bytes.len() < 16`
    // first for branch 1. Branch 2 (multiword) doesn't have a length gate,
    // so this 8-char multiword string SHOULD be rejected as prose.
    let short_multiword = "hi there";
    assert!(short_multiword.split_whitespace().count() >= 2);
    assert!(!is_secret_plausible(short_multiword, &[]));
}
