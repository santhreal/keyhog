//! Regression coverage for the core credential mask fn `keyhog_core::redact`.
//!
//! `redact` collapses a credential to a fixed short "edge...edge" form (or
//! `"****"` for anything <= 8 chars) so that display/report surfaces never
//! echo the raw secret. Expected values below are computed directly from the
//! implementation (crates/core/src/lib.rs):
//!
//! * ASCII path uses byte length; non-ASCII path uses `chars().count()`.
//! * `char_count <= 8`            -> `"****"`.
//! * else `edge = (count / 8).clamp(1, 4)` and the result is
//!   `s[..edge] + "..." + s[count-edge..]` (char-wise on the UTF-8 path).
//!
//! Every assertion pins an exact masked string; `as_ref()` yields the inner
//! `&str` from the returned `Cow<'static, str>` so equality is against a plain
//! `&str` literal (avoids any Cow/PartialEq ambiguity).

use keyhog_core::redact;

// --- boundary: everything <= 8 chars collapses to the star sentinel --------

#[test]
fn empty_string_masks_to_four_stars() {
    // Empty is `is_ascii()` == true, len 0 <= 8.
    assert_eq!(redact("").as_ref(), "****");
}

#[test]
fn short_secret_masks_to_four_stars_no_plaintext() {
    let r = redact("abc");
    assert_eq!(r.as_ref(), "****");
    // Negative-twin: none of the plaintext survives.
    assert!(!r.contains('a'));
    assert!(!r.contains('b'));
    assert!(!r.contains('c'));
}

#[test]
fn exactly_eight_chars_is_still_stars_boundary() {
    // len == 8 takes the `<= 8` branch, NOT the edge branch.
    assert_eq!(redact("12345678").as_ref(), "****");
}

// --- boundary: 9 chars is the first length that reveals edges (edge == 1) ---

#[test]
fn nine_chars_reveals_single_edge_char_each_side() {
    // len 9 > 8, edge = 9/8 = 1 -> "1" + "..." + "9".
    assert_eq!(redact("123456789").as_ref(), "1...9");
}

#[test]
fn fifteen_chars_edge_stays_one() {
    // len 15, edge = 15/8 = 1 (clamped low) -> "1...5".
    assert_eq!(redact("123456789012345").as_ref(), "1...5");
}

// --- edge growth at /8 multiples -------------------------------------------

#[test]
fn sixteen_chars_edge_grows_to_two() {
    // len 16, edge = 16/8 = 2 -> "01" + "..." + "ef".
    assert_eq!(redact("0123456789abcdef").as_ref(), "01...ef");
}

#[test]
fn twenty_char_aws_style_key_keeps_two_edges() {
    // "AKIA"(4)+"1234567890"(10)+"ABCDEF"(6) = 20, edge = 2 -> "AK...EF".
    assert_eq!(redact("AKIA1234567890ABCDEF").as_ref(), "AK...EF");
}

#[test]
fn twenty_four_chars_edge_three() {
    // 24 chars 'a'..'x', edge = 24/8 = 3 -> "abc...vwx".
    assert_eq!(redact("abcdefghijklmnopqrstuvwx").as_ref(), "abc...vwx");
}

#[test]
fn thirty_two_chars_edge_four() {
    // 32 chars, edge = 32/8 = 4 -> "0123...cdef".
    assert_eq!(
        redact("0123456789abcdef0123456789abcdef").as_ref(),
        "0123...cdef"
    );
}

// --- clamp: edge never exceeds 4 no matter how long the secret is ----------

#[test]
fn forty_chars_edge_clamped_at_four() {
    // len 40, raw 40/8 = 5 but clamp(1,4) caps at 4 -> "0123...ghij".
    let s = "0123456789abcdefghij0123456789abcdefghij";
    assert_eq!(s.len(), 40);
    assert_eq!(redact(s).as_ref(), "0123...ghij");
}

#[test]
fn hundred_char_secret_masks_and_hides_middle_no_leak() {
    // 100 chars: "0123" + 92*'m' + "6789". edge clamps to 4.
    let s = format!("0123{}6789", "m".repeat(92));
    assert_eq!(s.len(), 100);
    let r = redact(&s);
    assert_eq!(r.as_ref(), "0123...6789");
    // Length is NOT preserved: it collapses to edge*2 + 3 = 11.
    assert_eq!(r.len(), 11);
    // No-plaintext-leak: the 92-char middle run never appears in output.
    assert!(!r.contains('m'));
}

// --- adversarial: non-ASCII takes the char-count path ----------------------

#[test]
fn non_ascii_short_still_stars() {
    // 3 Greek chars, char_count 3 <= 8 -> "****".
    assert_eq!(redact("αβγ").as_ref(), "****");
}

#[test]
fn non_ascii_eight_chars_boundary_is_stars() {
    // 8 Greek chars, char_count == 8 -> "****" (byte len would be 16).
    assert_eq!(redact("αβγδεζηθ").as_ref(), "****");
}

#[test]
fn non_ascii_twelve_chars_char_wise_edges() {
    // 12 Greek chars, edge = 12/8 = 1, char-wise -> "α...μ".
    let s = "αβγδεζηθικλμ";
    assert_eq!(s.chars().count(), 12);
    assert_eq!(redact(s).as_ref(), "α...μ");
}

#[test]
fn emoji_nine_scalars_masks_char_wise_not_byte_wise() {
    // 9 key emoji (each 1 scalar / 4 bytes). char_count 9 > 8, edge 1.
    // Byte-indexing at edge=1 would slice mid-emoji and panic; char path is safe.
    let s = "🔑".repeat(9);
    assert_eq!(s.chars().count(), 9);
    assert_eq!(redact(&s).as_ref(), "🔑...🔑");
}

#[test]
fn mixed_ascii_and_non_ascii_uses_char_path() {
    // 9 'a' + 'é' = 10 chars, not is_ascii -> edge 1 -> "a...é".
    let s = "aaaaaaaaaé";
    assert_eq!(s.chars().count(), 10);
    let r = redact(s);
    assert_eq!(r.as_ref(), "a...é");
    // Only one 'a' from the prefix edge survives; the 8-char run is hidden.
    assert_eq!(r.matches('a').count(), 1);
}
