//! Migrated from `src/merkle_index.rs` inline tests.
use keyhog_core::merkle_index::{compute_spec_hash, MerkleIndex};
use keyhog_core::spec::{CompanionSpec, DetectorSpec, PatternSpec, Severity};
use std::path::{Path, PathBuf};
fn sample_hash(s: &[u8]) -> [u8; 32] { MerkleIndex::hash_content(s) }
#[test]
    fn lookup_returns_full_tuple() {
        let idx = MerkleIndex::empty();
        let p = PathBuf::from("/tmp/file");
        let h = sample_hash(b"abc");
        idx.record_with_metadata(p.clone(), 42, 99, h);
        assert_eq!(idx.lookup(&p), Some((42, 99, h)));
        assert_eq!(idx.lookup(Path::new("/missing")), None);
    }
