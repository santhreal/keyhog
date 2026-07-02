//! Regression: core credential redaction + opaque `Credential` zeroization surface.
//!
//! Pins the EXACT observable contract of two security-load-bearing primitives:
//!
//!   * `keyhog_core::redact` — the display-time masking applied to any credential
//!     string before it reaches a terminal / report. Edge length scales as
//!     `(char_count / 8).clamp(1, 4)`; strings of <= 8 chars are fully masked
//!     (`****`); UTF-8 is sliced on CHAR boundaries, never byte boundaries.
//!   * `keyhog_core::Credential` — the opaque, zeroize-on-drop byte wrapper whose
//!     `Debug`/`Display` refuse to print the bytes (leak guard), whose equality is
//!     length-checked + constant-time, and whose serde form is a tagged
//!     `{"text":...}` / `{"b64":...}` object (never the ambiguous legacy prefix).
//!
//! Every assertion is a concrete expected value read off the real implementation
//! in `crates/core/src/lib.rs` (`redact` / `redaction_edge_len`) and
//! `crates/core/src/credential.rs`. Raw byte access is reached only through the
//! `#[doc(hidden)]` `testing` facade, never by weakening production visibility.

use std::collections::HashSet;

use keyhog_core::testing::{CoreTestApi, TestApi};
use keyhog_core::{redact, Credential, SensitiveString};

// ---------------------------------------------------------------------------
// redact() — length / masking boundaries
// ---------------------------------------------------------------------------

#[test]
fn redact_empty_and_tiny_ascii_fully_masked() {
    // The task framing claimed empty => ""; the real contract masks it to the
    // fixed sentinel so a zero-length credential still never renders as blank
    // (which could hide the presence of a finding). Pin the ACTUAL value.
    assert_eq!(redact(""), "****");
    assert_eq!(redact("a"), "****");
    assert_eq!(redact("aB3"), "****");
}

#[test]
fn redact_boundary_eight_masked_nine_partial() {
    // <= 8 chars -> fully masked; 9 chars is the first partial reveal.
    assert_eq!(redact("12345678"), "****"); // exactly 8 -> masked
    assert_eq!(redact("123456789"), "1...9"); // 9 -> edge = 9/8 = 1
                                              // A 9-char all-same string still reveals exactly one char each side.
    assert_eq!(redact("AAAAAAAAA"), "A...A");
}

#[test]
fn redact_edge_scales_with_length() {
    // 16 chars -> edge = 16/8 = 2.
    assert_eq!(redact("0123456789abcdef"), "01...ef");
    // 20 chars (ghp_ token shape) -> edge = 20/8 = 2.
    assert_eq!(redact("ghp_0123456789abcdef"), "gh...ef");
    // 32 chars -> edge = 32/8 = 4.
    assert_eq!(redact("0123456789abcdef0123456789abcdef"), "0123...cdef");
}

#[test]
fn redact_forty_char_token_edge_clamped_to_four() {
    // 40 chars -> raw edge = 40/8 = 5, clamped to the max of 4.
    let token = "0123456789abcdef0123456789abcdef01234567";
    assert_eq!(token.len(), 40);
    assert_eq!(redact(token), "0123...4567");
    // The redacted form is exactly prefix(4) + "..." + suffix(4) = 11 bytes.
    assert_eq!(redact(token).len(), 11);
}

#[test]
fn redact_very_long_stays_clamped_at_four() {
    // 80 chars -> raw edge = 10, still clamped to 4 (upper bound holds).
    let token: String = "0123456789".repeat(8);
    assert_eq!(token.len(), 80);
    assert_eq!(redact(&token), "0123...6789");
}

#[test]
fn redact_never_contains_full_secret() {
    // Leak guard: the middle is elided, so the original never appears whole.
    let secret = "supersecretpassword123"; // 22 chars -> edge = 22/8 = 2
    let masked = redact(secret);
    assert_eq!(masked, "su...23");
    assert!(!masked.contains("secret"));
    assert!(!masked.contains(secret));
}

// ---------------------------------------------------------------------------
// redact() — UTF-8 char-boundary correctness (byte slicing would panic/corrupt)
// ---------------------------------------------------------------------------

#[test]
fn redact_short_unicode_masked_despite_byte_len() {
    // 8 multibyte chars: byte length is 16 but char count drives masking.
    let s = "αβγδεζηθ";
    assert_eq!(s.chars().count(), 8);
    assert!(s.len() > 8);
    assert_eq!(redact(s), "****");
}

#[test]
fn redact_unicode_prefix_multibyte_char_boundary() {
    // Leading multibyte char: a BYTE slice of `s[..1]` would split Ω (2 bytes)
    // and panic. Getting "Ω...i" proves char-boundary handling.
    let s = "Ωbcdefghi"; // Ω + 8 ascii = 9 chars
    assert_eq!(s.chars().count(), 9);
    assert_eq!(redact(s), "Ω...i");
}

#[test]
fn redact_unicode_suffix_multibyte_char_boundary() {
    // Trailing multibyte char: a BYTE slice of `s[len-1..]` would split Ω.
    // "a...Ω" proves the suffix is taken on a char boundary.
    let s = "abcdefghΩ"; // 8 ascii + Ω = 9 chars
    assert_eq!(s.chars().count(), 9);
    assert_eq!(redact(s), "a...Ω");
}

#[test]
fn redact_unicode_edge_two_distinct_ends() {
    // 16 Greek chars -> edge = 2; distinct prefix/suffix pairs.
    let s = "αβγδεζηθικλμνξοπ";
    assert_eq!(s.chars().count(), 16);
    assert_eq!(redact(s), "αβ...οπ");
}

// ---------------------------------------------------------------------------
// Credential — leak-guarded Debug/Display + facade byte access
// ---------------------------------------------------------------------------

#[test]
fn credential_debug_and_display_redact_without_leaking() {
    let cred: Credential = "supersecret".into(); // 11 bytes
    assert_eq!(format!("{cred:?}"), "Credential(<redacted 11 bytes>)");
    assert_eq!(format!("{cred}"), "<redacted 11 bytes>");
    // The raw secret must appear in NEITHER rendering.
    assert!(!format!("{cred:?}").contains("supersecret"));
    assert!(!format!("{cred}").contains("supersecret"));
}

#[test]
fn credential_expose_secret_and_str_via_facade() {
    let cred: Credential = "ghp_ABC123".into();
    assert_eq!(TestApi.credential_expose_secret(&cred), &b"ghp_ABC123"[..]);
    assert_eq!(TestApi.credential_expose_str(&cred), Some("ghp_ABC123"));
}

#[test]
fn credential_non_utf8_bytes_expose_str_is_none() {
    let raw: &[u8] = &[0xff, 0xfe, 0x00, 0x80];
    let cred: Credential = raw.into();
    // Non-UTF-8 stays fully accessible as bytes but yields None as &str — the
    // loud surface every caller must branch on (Law 10).
    assert_eq!(TestApi.credential_expose_secret(&cred), raw);
    assert_eq!(TestApi.credential_expose_str(&cred), None);
    // Debug still reports the exact byte count and leaks nothing.
    assert_eq!(format!("{cred:?}"), "Credential(<redacted 4 bytes>)");
}

// ---------------------------------------------------------------------------
// Credential — equality / ordering / hashing
// ---------------------------------------------------------------------------

#[test]
fn credential_equality_is_length_and_content_exact() {
    let a: Credential = "abc".into();
    let same: Credential = "abc".into();
    let longer: Credential = "abcd".into();
    let diff: Credential = "abd".into();
    assert!(a == same); // identical content
    assert!(a != longer); // length mismatch short-circuits to not-equal
    assert!(a != diff); // same length, one byte differs
                        // Byte constructor and text constructor agree for identical bytes.
    let from_bytes: Credential = (&b"abc"[..]).into();
    assert!(a == from_bytes);
}

#[test]
fn credential_ordering_and_hash_are_content_defined() {
    let a: Credential = "abc".into();
    let b: Credential = "abd".into();
    assert!(a < b); // 'c' (0x63) < 'd' (0x64)
    assert!(b > a);

    // Equal credentials collapse to a single HashSet slot; a distinct one adds.
    let mut set: HashSet<Credential> = HashSet::new();
    set.insert("abc".into());
    set.insert("abc".into());
    assert_eq!(set.len(), 1);
    set.insert("abd".into());
    assert_eq!(set.len(), 2);
}

#[test]
fn credential_clone_shares_bytes_and_stays_equal() {
    let original: Credential = "shared-secret-value".into();
    let cloned = original.clone();
    assert!(original == cloned);
    // Clone exposes the identical byte view.
    assert_eq!(
        TestApi.credential_expose_secret(&cloned),
        &b"shared-secret-value"[..]
    );
    // Dropping the clone must not disturb the original (Arc refcount, not move).
    drop(cloned);
    assert_eq!(
        TestApi.credential_expose_secret(&original),
        &b"shared-secret-value"[..]
    );
}

// ---------------------------------------------------------------------------
// Credential — serde tagged form + legacy compatibility
// ---------------------------------------------------------------------------

#[test]
fn credential_serde_text_roundtrips_as_tagged_object() {
    let cred: Credential = "hello".into();
    let json = serde_json::to_string(&cred).unwrap();
    assert_eq!(json, r#"{"text":"hello"}"#);
    let back: Credential = serde_json::from_str(&json).unwrap();
    assert!(back == cred);
    assert_eq!(TestApi.credential_expose_str(&back), Some("hello"));
}

#[test]
fn credential_serde_non_utf8_uses_b64_tag() {
    let cred: Credential = (&[0xffu8, 0xfe][..]).into();
    let json = serde_json::to_string(&cred).unwrap();
    assert_eq!(json, r#"{"b64":"//4="}"#);
    let back: Credential = serde_json::from_str(&json).unwrap();
    assert!(back == cred);
    assert_eq!(TestApi.credential_expose_secret(&back), &[0xffu8, 0xfe][..]);
}

#[test]
fn credential_deserialize_legacy_forms_still_load() {
    // Legacy bare string -> treated as literal text.
    let plain: Credential = serde_json::from_str(r#""plainsecret""#).unwrap();
    assert_eq!(TestApi.credential_expose_str(&plain), Some("plainsecret"));

    // Legacy `b64:` prefix -> decoded bytes ("aGVsbG8=" == "hello").
    let legacy_b64: Credential = serde_json::from_str(r#""b64:aGVsbG8=""#).unwrap();
    assert_eq!(TestApi.credential_expose_str(&legacy_b64), Some("hello"));
}

#[test]
fn credential_deserialize_ambiguous_tagged_forms_rejected() {
    // Both text AND b64 set -> hard error naming the fix.
    let both = serde_json::from_str::<Credential>(r#"{"text":"a","b64":"AA=="}"#);
    assert!(both.is_err());
    assert!(both.unwrap_err().to_string().contains("exactly one"));

    // Neither field set -> same rejection (empty tagged object).
    let neither = serde_json::from_str::<Credential>(r#"{}"#);
    assert!(neither.is_err());
    assert!(neither.unwrap_err().to_string().contains("exactly one"));
}

// ---------------------------------------------------------------------------
// SensitiveString — Debug redacts, Display intentionally exposes
// ---------------------------------------------------------------------------

#[test]
fn sensitive_string_debug_redacts_but_display_exposes() {
    let s: SensitiveString = "mypassword".into(); // 10 bytes
                                                  // `{:?}` is the compile-time leak guard: never the bytes.
    assert_eq!(format!("{s:?}"), "SensitiveString(<redacted 10 bytes>)");
    assert!(!format!("{s:?}").contains("mypassword"));
    // `{}` is the audited surface that deliberately yields the content.
    assert_eq!(format!("{s}"), "mypassword");
    assert_eq!(s.as_ref(), "mypassword");
}
