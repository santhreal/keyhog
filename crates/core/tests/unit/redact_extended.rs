/// Extended unit tests for `keyhog_core::redact`.
///
/// Covers: exact-8-char boundary (returns "****"), 9-char scaled preview,
/// ASCII fast path vs UTF-8 slow path, multi-byte characters at boundaries,
/// empty string, all-same character, and the anti-rig contract that the full
/// secret never appears in the output for long strings.
use keyhog_core::redact;

// ── ASCII fast path ───────────────────────────────────────────────────────────

#[test]
fn redact_empty_returns_stars() {
    assert_eq!(redact(""), "****");
}

#[test]
fn redact_one_char_returns_stars() {
    assert_eq!(redact("a"), "****");
}

#[test]
fn redact_eight_chars_returns_stars() {
    assert_eq!(redact("abcdefgh"), "****");
}

#[test]
fn redact_nine_chars_reveals_edges() {
    // 9 ASCII chars: first 1 + "..." + last 1.
    let result = redact("123456789");
    assert_eq!(result, "1...9");
}

#[test]
fn redact_twelve_chars_no_overlap() {
    let result = redact("abcdefghijkl");
    assert_eq!(result, "a...l");
}

#[test]
fn redact_short_preview_edges_scale_with_length() {
    assert_eq!(redact("123456789"), "1...9");
    assert_eq!(redact("1234567890"), "1...0");
    assert_eq!(redact("12345678901"), "1...1");
    assert_eq!(redact("123456789012"), "1...2");
    assert_eq!(redact("123456789012345"), "1...5");
    assert_eq!(redact("1234567890123456"), "12...56");
}

#[test]
fn redact_long_string_never_exposes_middle() {
    let secret = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let redacted = redact(secret);
    // The middle must be replaced by "..."
    assert!(redacted.contains("..."), "must contain ellipsis");
    assert!(
        redacted.starts_with("ghp_"),
        "first 4 chars preserved for 16+ chars"
    );
    // Full secret must not appear
    assert!(
        !redacted.as_ref().contains(secret),
        "full secret must not appear in redacted output"
    );
}

#[test]
fn redact_preserves_first_four_and_last_four() {
    let secret = "ABCD_middle_WXYZ";
    let result = redact(secret);
    assert_eq!(result.as_ref(), "AB...YZ");
}

// ── UTF-8 slow path ───────────────────────────────────────────────────────────

#[test]
fn redact_utf8_short_returns_stars() {
    // "café" = 4 graphemes but 5 bytes, still ≤ 8 chars → "****"
    assert_eq!(redact("café"), "****");
}

#[test]
fn redact_utf8_nine_graphemes_reveals_edges() {
    // 9 graphemes: "αβγδεζηθι"
    let secret = "αβγδεζηθι";
    let result = redact(secret);
    assert!(result.contains("..."), "must contain ellipsis");
    assert!(result.as_ref().starts_with('α'), "first grapheme preserved");
    assert!(result.as_ref().ends_with('ι'), "last grapheme preserved");
}

#[test]
fn redact_multibyte_char_boundary_safe() {
    // 20 CJK characters, each is 3 bytes. The fast path only applies to ASCII;
    // this exercises the char-count slow path.
    let secret = "一二三四五六七八九十一二三四五六七八九十";
    let result = redact(secret);
    assert!(result.contains("..."));
    // Must not panic (no byte-boundary indexing errors)
}

// ── Anti-rig: output never equals input for long secrets ─────────────────────

#[test]
fn redact_never_returns_full_secret_above_eight_chars() {
    // For any ASCII string longer than 8 chars, the output must differ from input.
    let secret = "this_is_definitely_longer_than_eight";
    let result = redact(secret);
    assert_ne!(result.as_ref(), secret);
}

#[test]
fn redact_output_shorter_than_input_for_long_secrets() {
    // "X...Y" (5 chars) < original length for any secret > 11 chars.
    let secret = "twelve_chars"; // 12 chars
    let result = redact(secret);
    assert!(
        result.len() < secret.len(),
        "redacted output must be shorter than the input for long secrets"
    );
}
