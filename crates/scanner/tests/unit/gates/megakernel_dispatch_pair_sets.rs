#[test]
fn megakernel_dispatch_pair_sets_are_unordered_and_capacity_seeded() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/megakernel_triggers.rs"
    ))
    .expect("megakernel_triggers.rs readable");

    assert!(
        !src.contains("BTreeSet"),
        "megakernel trigger pair dedup/membership is hot-path work and must not use ordered sets"
    );
    assert!(
        src.contains("HashSet<(usize, usize), ahash::RandomState>"),
        "megakernel trigger pair sets must use the crate's existing fast ahash state (PairSet type)"
    );
    // `PairOffsetMap` is a `HashMap` (stores offsets per pair) and
    // `PairSet` (gpu_validated) is a `HashSet` — both must be
    // capacity-seeded with ahash to avoid rehashing on hot-path inserts.
    // The candidate map (`HashMap::with_capacity_and_hasher`) and the
    // validated set (`HashSet::with_capacity_and_hasher`) count together.
    let hashset_seeded = src.matches("HashSet::with_capacity_and_hasher").count();
    let hashmap_seeded = src.matches("HashMap::with_capacity_and_hasher").count();
    assert!(
        hashset_seeded >= 1,
        "validated pair set (PairSet/gpu_validated) must use HashSet::with_capacity_and_hasher"
    );
    assert!(
        hashmap_seeded >= 1,
        "candidate offset map (PairOffsetMap/candidate_offsets) must use HashMap::with_capacity_and_hasher"
    );
    assert!(
        hashset_seeded + hashmap_seeded >= 2,
        "both candidate and validated pair data structures must reserve capacity before insertion \
         (found {} HashSet + {} HashMap with_capacity_and_hasher calls)",
        hashset_seeded,
        hashmap_seeded,
    );
}

#[test]
fn megakernel_dispatch_does_not_rebuild_lowercase_haystack_vecs() {
    let dispatch_src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/megakernel_dispatch.rs"
    ))
    .expect("megakernel_dispatch.rs readable");
    assert!(
        !dispatch_src.contains(".as_bytes().to_vec()"),
        "megakernel dispatch must not allocate a fresh haystack Vec per chunk; \
         lowercase staging belongs to MegakernelCatalog"
    );
    assert!(
        !dispatch_src.contains("make_ascii_lowercase()"),
        "megakernel dispatch must not own ASCII folding; the catalog's reusable \
         staging owner folds once per batch"
    );

    let catalog_src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/megakernel.rs"
    ))
    .expect("megakernel.rs readable");
    assert!(
        catalog_src.contains("lowercase_staging: std::sync::Mutex<Vec<Vec<u8>>>"),
        "MegakernelCatalog must retain reusable lowercase staging buffers"
    );
    assert!(
        catalog_src.contains("bytes.fill(0);"),
        "reused lowercase staging buffers must be zeroed before retaining capacity"
    );
}
