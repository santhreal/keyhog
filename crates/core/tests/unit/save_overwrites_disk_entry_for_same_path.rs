//! Migrated from `src/merkle_index.rs` inline tests.
use keyhog_core::merkle_index::{compute_spec_hash, MerkleIndex};
use keyhog_core::spec::{CompanionSpec, DetectorSpec, PatternSpec, Severity};
use std::path::{Path, PathBuf};
fn sample_hash(s: &[u8]) -> [u8; 32] { MerkleIndex::hash_content(s) }
#[test]
    fn save_overwrites_disk_entry_for_same_path() {
        // The merge is "in-memory wins" — if both disk and memory
        // hold a record for the same path, the freshly-saved one
        // (memory) takes precedence. Otherwise a stale disk entry
        // could "resurrect" itself across saves and never get
        // updated.
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("merkle.idx");
        let spec = [42u8; 32];

        let idx_old = MerkleIndex::empty();
        idx_old.record_with_metadata(PathBuf::from("/x"), 100, 10, sample_hash(b"old"));
        idx_old.save_with_spec(&cache_path, &spec).unwrap();

        let idx_new = MerkleIndex::empty();
        idx_new.record_with_metadata(PathBuf::from("/x"), 200, 20, sample_hash(b"new"));
        idx_new.save_with_spec(&cache_path, &spec).unwrap();

        let loaded = MerkleIndex::load_with_spec(&cache_path, &spec);
        assert_eq!(loaded.len(), 1);
        // The mtime/size from idx_new must be the surviving copy.
        assert!(loaded.metadata_unchanged(Path::new("/x"), 200, 20));
        assert!(!loaded.metadata_unchanged(Path::new("/x"), 100, 10));
    }
