//! Adversarial: empty merkle index round-trips through save/load.

use keyhog_core::merkle_index::MerkleIndex;

#[test]
fn merkle_empty_index_save_load_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("empty.idx");
    let idx = MerkleIndex::empty();
    idx.save(&path).expect("save empty");
    let loaded = MerkleIndex::load(&path);
    assert!(loaded.is_empty());
}
