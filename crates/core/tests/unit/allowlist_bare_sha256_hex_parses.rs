//! 64-char bare hex lines register as credential hash suppressions.

use keyhog_core::Allowlist;

#[test]
fn allowlist_bare_sha256_hex_parses_as_hash_entry() {
    let hex = "9d6060e21ef8d5daec9cfe4a44b1b1bc9792246bfad28210edaaa1782a8a676a";
    let al = keyhog_core::testing::CoreTestApi::allowlist_parse(&keyhog_core::testing::TestApi, hex);
    assert_eq!(al.credential_hashes.len(), 1);
    assert!(keyhog_core::testing::CoreTestApi::allowlist_is_raw_hash_ignored(
        &keyhog_core::testing::TestApi,
        &al,
        hex
    ));
}
