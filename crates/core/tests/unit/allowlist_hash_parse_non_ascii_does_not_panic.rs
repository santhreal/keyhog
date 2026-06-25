//! Regression: the `.keyhogignore` SHA-256 hex parser must never panic on a
//! 64-*byte* input that contains a multibyte UTF-8 char at an odd byte offset.
//!
//! The previous implementation length-checked `input.len() == 64` and then
//! sliced `&input[idx*2..idx*2+2]`. A 64-byte string whose bytes don't all
//! land on char boundaries (e.g. a stray `é`, which is 2 bytes) would make
//! that `&str` slice panic with "byte index is not a char boundary" - a
//! `.keyhogignore` line can trivially contain such a value. The byte-wise
//! decoder rejects any non-hex byte cleanly instead.

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

    let allowlist =
        keyhog_core::testing::CoreTestApi::allowlist_parse(&keyhog_core::testing::TestApi, "");
    // Must not panic and must not be considered an ignored hash.
    assert!(
        !keyhog_core::testing::CoreTestApi::allowlist_is_raw_hash_ignored(
            &keyhog_core::testing::TestApi,
            &allowlist,
            &value
        )
    );
    assert!(
        !keyhog_core::testing::CoreTestApi::allowlist_is_raw_hash_ignored(
            &keyhog_core::testing::TestApi,
            &allowlist,
            &needle
        )
    );
    assert!(
        !keyhog_core::testing::CoreTestApi::allowlist_is_hash_allowed(
            &keyhog_core::testing::TestApi,
            &allowlist,
            &value
        )
    );
}

#[test]
fn bare_non_ascii_64_byte_line_is_rejected_as_ambiguous_hash_not_path() {
    // A 64-byte line that fails hash parsing is ambiguous with the bare-hash
    // shortcut. It must not fall through to the bare-path glob branch unless
    // the operator writes `path:` explicitly.
    let line = format!("{}é", "c".repeat(62));
    assert_eq!(line.len(), 64);
    let allowlist =
        keyhog_core::testing::CoreTestApi::allowlist_parse(&keyhog_core::testing::TestApi, &line);
    // Not a valid hash -> no credential hash recorded.
    assert!(
        allowlist.credential_hashes.is_empty(),
        "non-hex 64-byte line must not be parsed as a credential hash"
    );
    assert!(
        allowlist.ignored_paths.is_empty(),
        "ambiguous 64-byte non-hex line must not become an ignored path glob"
    );
}

#[test]
fn valid_lowercase_and_uppercase_hex_still_parse() {
    // The byte-wise decoder must still accept both cases (matches_ignored_hash
    // compares the parsed bytes, so a lookup of the same hex should hit).
    let hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
    let upper = hash.to_uppercase();
    let allowlist = keyhog_core::testing::CoreTestApi::allowlist_parse(
        &keyhog_core::testing::TestApi,
        &format!("hash:{hash}\n"),
    );
    assert!(
        keyhog_core::testing::CoreTestApi::allowlist_is_raw_hash_ignored(
            &keyhog_core::testing::TestApi,
            &allowlist,
            hash
        ),
        "lowercase hex hash must match"
    );
    assert!(
        keyhog_core::testing::CoreTestApi::allowlist_is_raw_hash_ignored(
            &keyhog_core::testing::TestApi,
            &allowlist,
            &upper
        ),
        "uppercase spelling of the same hash must match (case-insensitive hex)"
    );
}
