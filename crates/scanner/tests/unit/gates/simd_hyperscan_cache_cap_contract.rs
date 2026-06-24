#[test]
fn hyperscan_cache_cap_is_shared_by_read_and_write_paths() {
    let core_cache = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../core/src/hyperscan_cache.rs"
    ))
    .expect("core hyperscan cache contract readable");
    let backend =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/simd/backend.rs"))
            .expect("simd backend source readable");

    assert!(
        core_cache.contains("pub const HYPERSCAN_CACHE_FILE_BYTES: u64 = 128 * 1024 * 1024;"),
        "core must own a bounded Hyperscan cache cap large enough for observed 69,974,208-byte dogfood shard"
    );
    assert!(
        !backend.contains("const HS_CACHE_FILE_BYTES"),
        "SIMD backend must not restore a private cache cap that can drift from persistence"
    );
    assert!(
        backend
            .matches("keyhog_core::HYPERSCAN_CACHE_FILE_BYTES")
            .count()
            >= 5,
        "SIMD backend read and write paths must consume the core-owned cache cap"
    );
    assert!(
        backend.contains(
            "HS shard cache serialization exceeds cap; not persisting oversized cache artifact"
        ),
        "write side must refuse to persist a shard the read side would reject"
    );
    assert!(
        backend.contains("HS shard cache DB deserialization failed; compiling from patterns"),
        "corrupt/incompatible shard DB deserialization must be operator-visible before recompiling"
    );
    assert!(
        backend.contains("HS shard cache serialization failed; not persisting cache artifact"),
        "cache serialization failure must be operator-visible before the next run recompiles"
    );
    assert!(
        !backend.contains("if let Ok(db) = payload.deserialize::<BlockMode>()")
            && !backend.contains("if let Ok(ser) = db.serialize()"),
        "Hyperscan cache load/save failures must not be hidden behind omitted Err arms"
    );
    assert!(
        backend.contains("HS shard cache file exceeds cap; compiling from patterns")
            && backend
                .contains("HS shard cache grew beyond cap while reading; compiling from patterns"),
        "read side must keep bounded metadata and growth checks"
    );
}
