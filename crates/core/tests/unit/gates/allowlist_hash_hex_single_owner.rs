#[test]
fn allowlist_hash_hex_parsing_uses_merkle_digest_parser() {
    let allowlist =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/allowlist.rs"))
            .expect("allowlist source readable");

    assert!(
        allowlist.contains("use crate::merkle_spec_hash::hex_to_array;")
            && allowlist.contains("fn parse_sha256_hex(input: &str) -> Option<[u8; 32]>")
            && allowlist.contains("hex_to_array(input.trim())"),
        "allowlist SHA-256 parsing must delegate to the canonical merkle hex parser"
    );
    for forbidden in [
        "use crate::merkle_spec_hash::hex_nibble;",
        "for idx in 0..32",
        "for i in 0..32",
        "hex_nibble(bytes",
    ] {
        assert!(
            !allowlist.contains(forbidden),
            "allowlist must not reimplement 64-hex decoding with `{forbidden}`"
        );
    }
    assert!(
        allowlist.contains("fn matches_ignored_hash_hex(&self, hash_hex: &str) -> bool")
            && allowlist.matches("self.matches_ignored_hash_hex(").count() == 2,
        "is_hash_allowed and is_raw_hash_ignored must share one hex-hash membership helper"
    );
}
