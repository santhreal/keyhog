//! Metadata fast-path matches only on exact mtime+size pair.

use keyhog_core::merkle_index::MerkleIndex;
use std::path::{Path, PathBuf};

#[test]
fn merkle_metadata_unchanged_matches_only_on_exact_pair() {
    let idx = MerkleIndex::empty();
    let p = PathBuf::from("/tmp/file");
    idx.record_with_metadata(p.clone(), 1_700_000_000_000_000_000, 4096, MerkleIndex::hash_content(b"x"));
    assert!(idx.metadata_unchanged(&p, 1_700_000_000_000_000_000, 4096));
    assert!(!idx.metadata_unchanged(&p, 1_700_000_000_000_000_001, 4096));
    assert!(!idx.metadata_unchanged(&p, 1_700_000_000_000_000_000, 4097));
    assert!(!idx.metadata_unchanged(Path::new("/never/seen"), 0, 0));
}
