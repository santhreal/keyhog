#[test]
fn simd_backend_uses_core_hyperscan_cache_header_contract() {
    let backend =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/simd/backend.rs"))
            .expect("simd backend source readable");

    for required in [
        "keyhog_core::HYPERSCAN_CACHE_HEADER_LEN",
        "keyhog_core::hyperscan_cache_header_is_valid(",
        "keyhog_core::write_hyperscan_cache_header(&mut data)",
    ] {
        assert!(
            backend.contains(required),
            "SIMD backend must consume core-owned hyperscan cache header `{required}`"
        );
    }
    for forbidden in [
        "const HS_CACHE_MAGIC",
        "const HS_CACHE_VERSION",
        "b\"KHHS\"",
        "u32::from_le_bytes)",
        "bytes[4..8]",
        "data.extend_from_slice(&1_u32.to_le_bytes())",
    ] {
        assert!(
            !backend.contains(forbidden),
            "SIMD backend must not restore private hyperscan header detail `{forbidden}`"
        );
    }
}
