//! Proving test: redact never exposes the middle of a long secret.
//! Contract: For any credential >8 chars, redact() output must:
//! 1. Contain exactly "..." separator
//! 2. Reveal only the length-scaled edge windows
//! 4. Never contain the full secret as a substring

use keyhog_core::redact;

#[test]
fn redact_long_secret_never_contains_middle_chars() {
    // Secret: "ghp_AAAAAABBBBBBCCCCCC" (20 chars)
    // Output should be: "ghp_...CCCC" (never expose the middle A/B/C block)
    let secret = "ghp_AAAAAABBBBBBCCCCCC";
    let result = redact(secret);

    // Verify structure.
    assert!(result.contains("..."), "must have ellipsis");
    assert!(result.starts_with("ghp_"), "must start with first 4");
    assert!(result.ends_with("CCCC"), "must end with last 4");

    // Verify the middle is NOT exposed.
    // The middle part "AAAAAABBBBBBCCCC" should not appear.
    let middle = "AAAAAABBBBBBCCCC";
    assert!(
        !result.as_ref().contains(middle),
        "middle of secret must not appear in output"
    );
}

#[test]
fn redact_exactly_nine_chars_no_full_exposure() {
    let secret = "ABCDEFGHI";
    let result = redact(secret);

    assert_eq!(result, "AB...HI");

    // The full secret must not appear.
    assert!(
        !result.as_ref().contains(secret),
        "full 9-char secret must not appear in output"
    );

    // Individual characters are visible, but not contiguously.
    assert!(result.as_ref().contains("AB"));
    assert!(result.as_ref().contains("HI"));
    // The transition DEFG must be hidden.
    assert!(!result.as_ref().contains("DEFG"));
}

#[test]
fn redact_very_long_secret_hides_middle_portion() {
    let secret = "prefix_MIDDLE_MIDDLE_MIDDLE_MIDDLE_MIDDLE_suffix";
    let result = redact(secret);

    // Output keeps a length-scaled 4-character edge window.
    assert_eq!(result, "pref...ffix");

    // The word "MIDDLE" (and any sequence of consecutive hidden chars) must not appear.
    assert!(!result.as_ref().contains("MIDDLE"));
    assert!(!result.as_ref().contains("pref_MIDDLE"));
    assert!(!result.as_ref().contains("MIDDLE_suffix"));
}

#[test]
fn redact_api_token_hides_entropy_core() {
    // Realistic example: an API key where the middle is the entropy-rich part
    let api_key = "sk_live_51234567890ABCDEFGHIJKLMNOP";
    let result = redact(api_key);

    // First 4: "sk_l", Last 4: "MNOP"
    assert_eq!(result, "sk_l...MNOP");

    // The entropy-rich middle "1234567890ABCDEFGHIJKL" must not appear.
    assert!(!result.as_ref().contains("1234567890"));
    assert!(!result.as_ref().contains("ABCDEFGHIJKL"));

    // But the edges are visible.
    assert!(result.as_ref().contains("sk_l"));
    assert!(result.as_ref().contains("MNOP"));
}

#[test]
fn redact_utf8_long_secret_no_middle_exposure() {
    // Long UTF-8 secret: first 4 graphemes Greek, middle is emoji, last 4 Cyrillic.
    // "αβγδ🔒🔒🔒🔒абвг"
    let secret = "αβγδ🔒🔒🔒🔒абвг";
    let result = redact(secret);

    // 12 chars keeps 3 chars at each edge.
    assert!(result.starts_with("αβγ"));
    assert!(result.ends_with("бвг"));
    assert!(result.as_ref().contains("..."));

    // The emoji sequence must not appear.
    assert!(!result.as_ref().contains("🔒"));
}
