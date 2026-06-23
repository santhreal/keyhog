#[test]
fn core_owns_hyperscan_cache_header_contract() {
    let lib = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
        .expect("core lib readable");
    let cache = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/hyperscan_cache.rs"
    ))
    .expect("hyperscan cache source readable");
    let hardening =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/hardening.rs"))
            .expect("hardening source readable");

    for required in [
        "pub const HYPERSCAN_CACHE_MAGIC",
        "pub const HYPERSCAN_CACHE_VERSION",
        "pub const HYPERSCAN_CACHE_HEADER_LEN",
        "pub fn hyperscan_cache_header_is_valid(",
        "pub fn write_hyperscan_cache_header(",
    ] {
        assert!(
            cache.contains(required),
            "core hyperscan cache module must own `{required}`"
        );
    }
    assert!(
        lib.contains("mod hyperscan_cache;")
            && lib.contains("pub use hyperscan_cache::{")
            && hardening.contains("crate::hyperscan_cache_header_is_valid(&header)"),
        "core hardening must consume the exported hyperscan cache header contract"
    );
    for forbidden in [
        "const HYPERSCAN_CACHE_MAGIC: &[u8; 4] = b\"KHHS\";",
        "const HYPERSCAN_CACHE_VERSION: u32 = 1;",
        "u32::from_le_bytes([header[4], header[5], header[6], header[7]])",
    ] {
        assert!(
            !hardening.contains(forbidden),
            "hardening must not restore private hyperscan header detail `{forbidden}`"
        );
    }
}
