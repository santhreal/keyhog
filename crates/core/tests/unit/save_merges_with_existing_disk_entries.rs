//! Migrated from `src/merkle_index.rs` inline tests.
use keyhog_core::merkle_index::{compute_spec_hash, MerkleIndex};
use keyhog_core::spec::{CompanionSpec, DetectorSpec, PatternSpec, Severity};
use std::path::{Path, PathBuf};
fn sample_hash(s: &[u8]) -> [u8; 32] { MerkleIndex::hash_content(s) }
#[test]
    fn save_merges_with_existing_disk_entries() {
        // Simulates two concurrent `keyhog scan --incremental`
        // processes scanning different subsets. The save path now
        // does read-modify-write so process B's save doesn't blow
        // away process A's entries when their target path sets
        // don't overlap.
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("merkle.idx");
        let spec = [42u8; 32];

        // Process A scans path /a/file and saves.
        let idx_a = MerkleIndex::empty();
        idx_a.record_with_metadata(
            PathBuf::from("/a/file"),
            100,
            10,
            sample_hash(b"a contents"),
        );
        idx_a.save_with_spec(&cache_path, &spec).unwrap();

        // Process B (separate handle, fresh memory) scans /b/file and
        // saves. Without read-modify-write, /a/file's entry would be
        // gone after this save.
        let idx_b = MerkleIndex::empty();
        idx_b.record_with_metadata(
            PathBuf::from("/b/file"),
            200,
            20,
            sample_hash(b"b contents"),
        );
        idx_b.save_with_spec(&cache_path, &spec).unwrap();

        // Reload with the same spec. BOTH /a/file AND /b/file must
        // be present — process A's entry survived process B's save.
        let loaded = MerkleIndex::load_with_spec(&cache_path, &spec);
        assert_eq!(loaded.len(), 2);
        assert!(loaded.metadata_unchanged(Path::new("/a/file"), 100, 10));
        assert!(loaded.metadata_unchanged(Path::new("/b/file"), 200, 20));
    }
