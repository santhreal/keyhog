//! Migrated from `src/merkle_index.rs` inline tests.
use keyhog_core::merkle_index::MerkleIndex;
use keyhog_core::compute_spec_hash;
use keyhog_core::{CompanionSpec, DetectorSpec, PatternSpec, Severity};
use std::path::{Path, PathBuf};
fn sample_hash(s: &[u8]) -> [u8; 32] { MerkleIndex::hash_content(s) }
#[test]
    fn v1_legacy_format_treated_as_cold_start() {
        // v1 stored `entries: HashMap<String, String>` (path → hex hash).
        // Loaders must reject it cleanly so we don't conjure zero-metadata
        // fast-path skips on entries that never had real metadata.
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("merkle.idx");
        let v1 = serde_json::json!({
            "version": 1,
            "entries": { "/foo": "ab".repeat(32) }
        });
        std::fs::write(&cache_path, serde_json::to_vec(&v1).unwrap()).unwrap();
        assert!(MerkleIndex::load(&cache_path).is_empty());
    }
