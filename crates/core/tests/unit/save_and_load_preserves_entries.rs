//! Migrated from `src/merkle_index.rs` inline tests.
use keyhog_core::merkle_index::MerkleIndex;
use keyhog_core::compute_spec_hash;
use keyhog_core::{CompanionSpec, DetectorSpec, PatternSpec, Severity};
use std::path::{Path, PathBuf};
fn sample_hash(s: &[u8]) -> [u8; 32] { MerkleIndex::hash_content(s) }
#[test]
    fn save_and_load_preserves_entries() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("merkle.idx");

        let idx = MerkleIndex::empty();
        let p = PathBuf::from("/tmp/secrets.env");
        let h = sample_hash(b"hello world");
        idx.record_with_metadata(p.clone(), 12345, 11, h);
        idx.save(&cache_path).expect("save");

        let loaded = MerkleIndex::load(&cache_path);
        assert_eq!(loaded.len(), 1);
        assert!(loaded.unchanged(&p, &h));
        assert!(loaded.metadata_unchanged(&p, 12345, 11));
    }
