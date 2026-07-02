//! Regression: pin the exact formatting boundaries of `keyhog_core::redact`,
//! and the redaction / exposure contracts of `SensitiveString` and
//! `Credential`.
//!
//! This is a standalone integration test (external crate): it can only touch
//! the public API (`redact`, `SensitiveString`, `Credential`) plus the
//! `#[doc(hidden)]` `testing` facade — never `#[cfg(test)]` internals.
//!
//! Every assertion is a CONCRETE expected value. Boundaries verified against
//! the source: ASCII path `len<=8 -> "****"`, else
//! `edge = (len/8).clamp(1,4)` and `s[..edge] + "..." + s[len-edge..]`;
//! non-ASCII path uses `char_count` (grapheme-safe via `chars()`), not byte
//! length. `SensitiveString::Debug` redacts to a byte count while `Display`
//! *intentionally* exposes the content; `Credential` redacts BOTH.

use keyhog_core::testing::{CoreTestApi, TestApi};
use keyhog_core::{redact, Credential, SensitiveString};

// ------------------------------------------------------------------
// redact(): ASCII boundaries
// ------------------------------------------------------------------

#[test]
fn redact_empty_and_short_ascii_return_stars() {
    // Empty string is ASCII (empty slice), len 0 <= 8 -> full mask.
    let empty = redact("");
    assert_eq!(&*empty, "****");
    // Single char, well under the 8-byte floor.
    let one = redact("a");
    assert_eq!(&*one, "****");
    // Exactly 8 bytes is the INCLUSIVE upper edge of the fully-masked band.
    let eight = redact("abcdefgh");
    assert_eq!(&*eight, "****");
}

#[test]
fn redact_nine_ascii_keeps_single_char_edges() {
    // 9 bytes is the first length that reveals edges: edge = (9/8).clamp(1,4) = 1.
    // This is the 8-vs-9 boundary: 8 -> "****", 9 -> first + "..." + last.
    let r = redact("abcdefghi");
    assert_eq!(&*r, "a...i");
}

#[test]
fn redact_sixteen_ascii_uses_edge_two() {
    // 16 bytes: edge = (16/8).clamp(1,4) = 2 -> first 2 + "..." + last 2.
    let input = format!("AB{}YZ", "m".repeat(12)); // 2 + 12 + 2 = 16 bytes
    assert_eq!(input.len(), 16);
    let r = redact(&input);
    assert_eq!(&*r, "AB...YZ");
}

#[test]
fn redact_thirtytwo_ascii_uses_edge_four() {
    // 32 bytes: edge = (32/8).clamp(1,4) = 4 -> first 4 + "..." + last 4.
    let input = format!("AAAA{}ZZZZ", "m".repeat(24)); // 4 + 24 + 4 = 32
    assert_eq!(input.len(), 32);
    let r = redact(&input);
    assert_eq!(&*r, "AAAA...ZZZZ");
}

#[test]
fn redact_forty_ascii_clamps_edge_at_four() {
    // 40 bytes: raw 40/8 = 5, but .clamp(1,4) pins the edge at 4. A missing
    // clamp would leak 5 chars per side; assert exactly 4-and-4.
    let input = format!("AAAA{}ZZZZ", "m".repeat(32)); // 4 + 32 + 4 = 40
    assert_eq!(input.len(), 40);
    let r = redact(&input);
    assert_eq!(&*r, "AAAA...ZZZZ");
    // The whole redacted form is exactly 4 + 3 + 4 = 11 chars long.
    assert_eq!(r.len(), 11);
}

#[test]
fn redact_twenty_ascii_reveals_edges_and_hides_middle() {
    // 20 bytes: edge = (20/8).clamp(1,4) = 2. Assert the exact form AND that
    // no interior byte survives (no full-secret leak).
    let r = redact("0123456789abcdefghij");
    assert_eq!(&*r, "01...ij");
    assert!(
        !r.contains("23456789abcdefgh"),
        "redacted output must not contain the interior of the secret: {}",
        &*r
    );
}

// ------------------------------------------------------------------
// redact(): non-ASCII / multibyte boundaries (char_count, not byte len)
// ------------------------------------------------------------------

#[test]
fn redact_multibyte_short_uses_char_count_not_byte_len() {
    // Adversarial: "áéíóú" is 5 chars but 10 BYTES. A byte-length gate would
    // see 10 > 8 and try to slice at a mid-codepoint boundary (panic/leak).
    // redact() uses char_count = 5 <= 8 and returns the full mask.
    let s = "áéíóú";
    assert_eq!(s.len(), 10); // bytes
    assert_eq!(s.chars().count(), 5); // chars
    let r = redact(s);
    assert_eq!(&*r, "****");
}

#[test]
fn redact_multibyte_nine_cjk_keeps_grapheme_edges() {
    // 9 three-byte CJK chars (27 bytes). char_count 9 -> edge 1. A naive
    // byte slice s[..1] would split the first codepoint; redact() keeps the
    // whole first/last CHARACTER: "一...九".
    let s = "一二三四五六七八九";
    assert_eq!(s.len(), 27);
    assert_eq!(s.chars().count(), 9);
    let r = redact(s);
    assert_eq!(&*r, "一...九");
}

#[test]
fn redact_multibyte_eight_cjk_returns_stars() {
    // 8 CJK chars = char_count 8, the fully-masked boundary, despite 24 bytes.
    let s = "一二三四五六七八";
    assert_eq!(s.chars().count(), 8);
    let r = redact(s);
    assert_eq!(&*r, "****");
}

#[test]
fn redact_multibyte_sixteen_cjk_uses_edge_two() {
    // 16 CJK chars -> edge = (16/8).clamp(1,4) = 2 -> first 2 + "..." + last 2.
    let s = "一二三四五六七八九十百千万億兆京";
    assert_eq!(s.chars().count(), 16);
    let r = redact(s);
    assert_eq!(&*r, "一二...兆京");
}

// ------------------------------------------------------------------
// SensitiveString: Debug redacts, Display exposes (by design)
// ------------------------------------------------------------------

#[test]
fn sensitive_string_debug_redacts_and_hides_secret() {
    let ss = SensitiveString::from("supersecret"); // 11 bytes
    let dbg = format!("{ss:?}");
    assert_eq!(dbg, "SensitiveString(<redacted 11 bytes>)");
    assert!(
        !dbg.contains("supersecret"),
        "Debug must never contain the raw secret: {dbg}"
    );
}

#[test]
fn sensitive_string_display_exposes_content_by_design() {
    // NEGATIVE TWIN: unlike Credential, SensitiveString::Display is the
    // *auditable exposure surface* and returns the bytes verbatim (documented
    // intent in credential.rs). Pin that so a future "redact Display too"
    // change is a deliberate, reviewed decision rather than silent.
    let ss = SensitiveString::from("supersecret");
    let disp = format!("{ss}");
    assert_eq!(disp, "supersecret");
    // Empty stays empty (no "****" masking on the SensitiveString path).
    let empty = SensitiveString::from("");
    assert_eq!(format!("{empty}"), "");
}

#[test]
fn sensitive_string_deref_and_asref_return_exact_content() {
    let ss = SensitiveString::from("supersecret");
    // Deref<Target=str>
    assert_eq!(&*ss, "supersecret");
    // AsRef<str> (bind to a typed &str to avoid inference ambiguity).
    let as_ref: &str = ss.as_ref();
    assert_eq!(as_ref, "supersecret");
}

#[test]
fn sensitive_string_debug_counts_bytes_not_chars() {
    // Boundary: the redacted byte count is the UTF-8 byte length, not the
    // char count. "café" = 4 chars but 5 bytes.
    let ss = SensitiveString::from("café");
    assert_eq!(format!("{ss:?}"), "SensitiveString(<redacted 5 bytes>)");
    // Display still exposes the exact multibyte content.
    assert_eq!(format!("{ss}"), "café");
    // Empty -> zero bytes.
    let empty = SensitiveString::from("");
    assert_eq!(format!("{empty:?}"), "SensitiveString(<redacted 0 bytes>)");
}

// ------------------------------------------------------------------
// Credential: Debug AND Display both redact; expose_secret is exact
// ------------------------------------------------------------------

#[test]
fn credential_debug_and_display_both_redact() {
    let cred = Credential::from("ghp_secretvalue"); // 15 bytes
    let dbg = format!("{cred:?}");
    let disp = format!("{cred}");
    assert_eq!(dbg, "Credential(<redacted 15 bytes>)");
    assert_eq!(disp, "<redacted 15 bytes>");
    assert!(
        !dbg.contains("secretvalue") && !disp.contains("secretvalue"),
        "neither Debug nor Display may leak the secret: dbg={dbg} disp={disp}"
    );
}

#[test]
fn credential_expose_secret_returns_exact_bytes_including_non_utf8() {
    let api = TestApi;

    // UTF-8 credential: expose_secret is byte-exact; expose_str round-trips.
    let cred = Credential::from("ghp_secretvalue");
    let expected: &[u8] = b"ghp_secretvalue";
    assert_eq!(api.credential_expose_secret(&cred), expected);
    assert_eq!(api.credential_expose_str(&cred), Some("ghp_secretvalue"));

    // Non-UTF-8 credential: raw bytes preserved verbatim, but expose_str is
    // None (the loud "not valid UTF-8" surface, not a silent lossy decode).
    let bad = Credential::from(&[0xffu8, 0xfe, 0x00][..]);
    let bad_expected: &[u8] = &[0xff, 0xfe, 0x00];
    assert_eq!(api.credential_expose_secret(&bad), bad_expected);
    assert_eq!(api.credential_expose_str(&bad), None);
    // And its Debug reports the exact 3-byte length.
    assert_eq!(format!("{bad:?}"), "Credential(<redacted 3 bytes>)");
}
