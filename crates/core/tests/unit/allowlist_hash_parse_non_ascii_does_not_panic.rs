//! Regression: the `.keyhogignore` SHA-256 hex parser must never panic on a
//! 64-*byte* input that contains a multibyte UTF-8 char at an odd byte offset.
//!
//! The previous implementation length-checked `input.len() == 64` and then
//! sliced `&input[idx*2..idx*2+2]`. A 64-byte string whose bytes don't all
//! land on char boundaries (e.g. a stray `é`, which is 2 bytes) would make
//! that `&str` slice panic with "byte index is not a char boundary" - a
//! `.keyhogignore` line can trivially contain such a value. The byte-wise
//! decoder rejects any non-hex byte cleanly instead.

use keyhog_core::allowlist::Allowlist;

#[test]
fn raw_hash_lookup_with_non_ascii_64_bytes_returns_false_not_panic() {
    // 62 ASCII hex chars + one 2-byte UTF-8 char 'é' = 64 bytes, 63 chars.
    // Odd-offset multibyte boundary is exactly the panic trigger.
    let needle = format!("{}{}", "a".repeat(61), "é"); // 61 + 2 bytes = 63... extend.
                                                       // Build a value that is exactly 64 bytes long and not pure-ASCII.
    let value = format!("{}é", "b".repeat(62)); // 62 + 2 = 64 bytes.
    assert_eq!(value.len(), 64, "test fixture must be 64 bytes");
    assert!(
        !value.is_char_boundary(63),
        "fixture must have an odd-offset multibyte char"
    );

    let allowlist = Allowlist::parse("");
    // Must not panic and must not be considered an ignored hash.
    assert!(!allowlist.is_raw_hash_ignored(&value));
    assert!(!allowlist.is_raw_hash_ignored(&needle));
    assert!(!allowlist.is_hash_allowed(&value));
}

#[test]
fn bare_non_ascii_64_byte_line_is_treated_as_path_not_hash() {
    // A 64-byte line that fails hash parsing falls through to the bare-path
    // glob branch. The parse must complete without panicking.
    let line = format!("{}é", "c".repeat(62));
    assert_eq!(line.len(), 64);
    let allowlist = Allowlist::parse(&line);
    // Not a valid hash -> no credential hash recorded.
    assert!(
        allowlist.credential_hashes.is_empty(),
        "non-hex 64-byte line must not be parsed as a credential hash"
    );
    // It lands in ignored_paths (gitignore-style fallback).
    assert_eq!(allowlist.ignored_paths.len(), 1);
}

#[test]
fn valid_lowercase_and_uppercase_hex_still_parse() {
    // The byte-wise decoder must still accept both cases (matches_ignored_hash
    // compares the parsed bytes, so a lookup of the same hex should hit).
    let hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
    let upper = hash.to_uppercase();
    let allowlist = Allowlist::parse(&format!("hash:{hash}\n"));
    assert!(
        allowlist.is_raw_hash_ignored(hash),
        "lowercase hex hash must match"
    );
    assert!(
        allowlist.is_raw_hash_ignored(&upper),
        "uppercase spelling of the same hash must match (case-insensitive hex)"
    );
}
