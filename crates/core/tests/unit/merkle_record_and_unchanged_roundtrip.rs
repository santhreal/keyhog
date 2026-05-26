//! Merkle index records content hash and detects changes.

use keyhog_core::merkle_index::MerkleIndex;
use std::path::PathBuf;

#[test]
fn merkle_record_and_unchanged_roundtrip() {
    let idx = MerkleIndex::empty();
    let p = PathBuf::from("/tmp/example.env");
    let h = MerkleIndex::hash_content(b"DB_PASS=secret123");
    idx.record(p.clone(), h);
    assert!(idx.unchanged(&p, &h));
    let h2 = MerkleIndex::hash_content(b"DB_PASS=changed");
    assert!(!idx.unchanged(&p, &h2));
}
