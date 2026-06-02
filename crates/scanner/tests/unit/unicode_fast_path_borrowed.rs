use keyhog_scanner::unicode_hardening::*;
use std::borrow::Cow;

/// Proving test: ASCII-only input with no evasion returns borrowed Cow.
/// Contract: normalize_homoglyphs("pure_ascii_no_evasion") returns Cow::Borrowed
/// with identical bytes (same pointer/address).
#[test]
fn normalize_homoglyphs_fast_path_pure_ascii_borrowed() {
    // Pure ASCII with no control characters or evasion
    let text = "ghp_abcdefghijklmnopqrstuvwxyz1234567890AB";
    let normalized = normalize_homoglyphs(text);

    // Fast path must return Cow::Borrowed (no allocation)
    match normalized {
        Cow::Borrowed(borrowed) => {
            // Must be the exact same string
            assert_eq!(borrowed, text, "Borrowed text must match input exactly");
            // The pointer must be the same (no copy)
            assert_eq!(
                borrowed.as_ptr(),
                text.as_ptr(),
                "Cow::Borrowed must use original pointer, not copy"
            );
        }
        Cow::Owned(_) => {
            panic!("Pure ASCII no-evasion must return Cow::Borrowed, not Cow::Owned");
        }
    }
}

/// Proving test: ASCII input containing only newline/tab/CR returns borrowed.
/// Contract: Whitelisted ASCII control characters (\\n, \\r, \\t) don't trigger allocation.
#[test]
fn normalize_homoglyphs_fast_path_allows_whitespace_controls() {
    // ASCII with allowed control characters
    let text = "ghp_abc\tdef\nghi\rjkl";
    let normalized = normalize_homoglyphs(text);

    // These whitespace controls are allowed, so fast path should apply
    match normalized {
        Cow::Borrowed(borrowed) => {
            assert_eq!(borrowed, text);
            assert_eq!(borrowed.as_ptr(), text.as_ptr());
        }
        Cow::Owned(_) => {
            panic!("ASCII with only \\t/\\n/\\r must return Cow::Borrowed");
        }
    }
}

/// Proving test: ASCII with prohibited control character triggers allocation.
/// Contract: ASCII control bytes like 0x01 (SOH) trigger allocation (not borrowed).
#[test]
fn normalize_homoglyphs_owned_path_ascii_prohibited_control() {
    // ASCII with prohibited control character (SOH = 0x01)
    let text = "ghp_abc\x01def";
    let normalized = normalize_homoglyphs(text);

    // Prohibited control character must trigger owned path (allocation)
    match normalized {
        Cow::Borrowed(_) => {
            panic!("ASCII with prohibited control (0x01) must return Cow::Owned");
        }
        Cow::Owned(owned) => {
            // The owned version should have the control removed
            assert!(
                !owned.contains('\x01'),
                "Prohibited control must be removed"
            );
            assert!(owned.contains("ghp_abcdef"), "Content must be preserved");
        }
    }
}

/// Proving test: Non-ASCII clean input (no homoglyphs/evasion) returns borrowed.
/// Contract: UTF-8 text with no detectable evasion returns Cow::Borrowed.
#[test]
fn normalize_homoglyphs_fast_path_non_ascii_clean() {
    // Non-ASCII but clean (no evasion characters)
    // Using valid UTF-8 characters that are NOT homoglyphs or evasion
    let text = "ghp_café_naïve_résumé"; // French accented characters (not combining marks, not evasion)
    let normalized = normalize_homoglyphs(text);

    // Clean non-ASCII should be borrowed (fast path)
    match normalized {
        Cow::Borrowed(borrowed) => {
            assert_eq!(borrowed, text);
            assert_eq!(borrowed.as_ptr(), text.as_ptr());
        }
        Cow::Owned(_) => {
            panic!("Clean non-ASCII text must return Cow::Borrowed in fast path");
        }
    }
}

/// Proving test: Input with zero-width character triggers owned path.
/// Contract: normalize_homoglyphs with U+200B triggers Cow::Owned (allocation).
#[test]
fn normalize_homoglyphs_owned_path_zero_width_present() {
    // ASCII + zero-width character
    let text = "ghp_abc\u{200B}def"; // Zero-width space
    let normalized = normalize_homoglyphs(text);

    // Must allocate and remove the zero-width char
    match normalized {
        Cow::Borrowed(_) => {
            panic!("Text with zero-width character must return Cow::Owned");
        }
        Cow::Owned(owned) => {
            assert!(!owned.contains('\u{200B}'), "Zero-width must be removed");
            assert_eq!(owned, "ghp_abcdef");
        }
    }
}

/// Proving test: Input with Cyrillic homoglyph triggers owned path.
/// Contract: normalize_homoglyphs("ghp_а...") triggers Cow::Owned (contains Cyrillic а).
#[test]
fn normalize_homoglyphs_owned_path_cyrillic_homoglyph_present() {
    // ASCII prefix + Cyrillic 'а' (U+0430)
    let text = "ghp_\u{0430}bcdef"; // Cyrillic 'а'
    let normalized = normalize_homoglyphs(text);

    // Must allocate and convert
    match normalized {
        Cow::Borrowed(_) => {
            panic!("Text with Cyrillic homoglyph must return Cow::Owned");
        }
        Cow::Owned(owned) => {
            assert!(owned.contains("ghp_abcdef"), "Homoglyph must be converted");
            assert!(owned.is_ascii());
        }
    }
}

/// Proving test: Borrowed and owned paths produce identical normalized output.
/// Contract: Fast path (borrowed) vs slow path (owned) both produce same normalized bytes.
#[test]
fn normalize_homoglyphs_fast_and_slow_paths_produce_same_output() {
    // Fast path example: pure ASCII
    let fast_text = "ghp_abcdef";
    let fast_normalized = normalize_homoglyphs(fast_text);

    // Slow path example: same text but forced to be owned by comparing values
    let slow_text = "ghp_\u{0430}bcdef"; // Cyrillic 'а' converted to 'a'
    let slow_normalized = normalize_homoglyphs(slow_text);

    // After conversion, the slow path should produce the fast path result
    assert_eq!(
        slow_normalized.as_ref(),
        fast_normalized.as_ref(),
        "Fast and slow paths must produce identical output"
    );
}
