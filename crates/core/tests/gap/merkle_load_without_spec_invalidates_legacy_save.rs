//! KH-GAP-015: legacy save() cache must not satisfy load_with_spec gate.

use keyhog_core::merkle_index::MerkleIndex;
use std::path::PathBuf;

#[test]
fn merkle_load_with_spec_rejects_legacy_save_without_spec() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cache_path = dir.path().join("merkle.idx");
    let idx = MerkleIndex::empty();
    idx.record_with_metadata(
        PathBuf::from("/tmp/x"),
        1,
        1,
        MerkleIndex::hash_content(b"x"),
    );
    idx.save(&cache_path).expect("save legacy");
    let loaded = MerkleIndex::load_with_spec(&cache_path, &[1u8; 32]);
    assert!(
        loaded.is_empty(),
        "legacy save must not satisfy spec-gated load"
    );
}
