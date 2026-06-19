//! MD5 of empty string is a known non-secret hash.

use keyhog_scanner::testing::context::is_known_example_credential;

#[test]
fn context_example_empty_md5_hash() {
    assert!(
        is_known_example_credential("d41d8cd98f00b204e9800998ecf8427e"),
        "MD5('') digest must be suppressed as integrity hash"
    );
}
