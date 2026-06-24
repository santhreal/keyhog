//! Gate `merkle_index`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn merkle_index_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/merkle_index.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        src.trim().len() >= 20,
        "merkle_index: expected substantive source, got {} trimmed bytes",
        src.trim().len()
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "merkle_index: todo!/unimplemented! forbidden in non-test source"
    );
    assert!(
        !prod.contains("DefaultHasher"),
        "merkle_index: shard routing is a hot path and must not use SipHasher DefaultHasher"
    );
    assert!(
        prod.contains("type MerkleShardBuildHasher = ahash::RandomState")
            && prod
                .contains("type MerkleShardMap = HashMap<CacheKey, CacheEntry, MerkleShardBuildHasher>")
            && !prod.contains("MERKLE_FNV")
            && !prod.contains("impl Hasher for MerkleShardHasher"),
        "merkle_index: per-shard HashMap lookups must use a keyed fast hasher, not std RandomState or unkeyed FNV"
    );
    assert!(
        prod.contains("fn shard_index_bytes(bytes: &[u8]) -> usize")
            && prod.contains("SHARD_MIX")
            && prod.contains("hash & (MERKLE_SHARDS - 1)"),
        "merkle_index: shard routing must use the dedicated fast byte mixer"
    );
    assert!(
        prod.contains("fn shard_capacity(max_entries: usize) -> usize")
            && prod.contains("HashMap::with_capacity_and_hasher(")
            && prod.contains("MerkleShardBuildHasher::default()")
            && !prod.contains("RwLock::new(HashMap::new())")
            && !prod.contains("HashMap::with_capacity(shard_capacity)"),
        "merkle_index: shard maps must be pre-sized from the configured entry cap"
    );
}
