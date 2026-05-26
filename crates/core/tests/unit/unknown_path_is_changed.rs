//! Migrated from `src/merkle_index.rs` inline tests.
use keyhog_core::merkle_index::{compute_spec_hash, MerkleIndex};
use keyhog_core::spec::{CompanionSpec, DetectorSpec, PatternSpec, Severity};
use std::path::{Path, PathBuf};
fn sample_hash(s: &[u8]) -> [u8; 32] { MerkleIndex::hash_content(s) }
#[test]
    fn unknown_path_is_changed() {
        let idx = MerkleIndex::empty();
        let h = sample_hash(b"x");
        assert!(!idx.unchanged(Path::new("/never/seen"), &h));
    }
