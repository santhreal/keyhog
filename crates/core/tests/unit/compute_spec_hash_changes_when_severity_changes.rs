//! Migrated from `src/merkle_index.rs` inline tests.
use keyhog_core::merkle_index::{compute_spec_hash, MerkleIndex};
use keyhog_core::spec::{CompanionSpec, DetectorSpec, PatternSpec, Severity};
use std::path::{Path, PathBuf};
fn sample_hash(s: &[u8]) -> [u8; 32] { MerkleIndex::hash_content(s) }
#[test]
    fn compute_spec_hash_changes_when_severity_changes() {
        use keyhog_core::spec::{DetectorSpec, PatternSpec, Severity};
        let base = DetectorSpec {
            id: "sev-test".into(),
            name: "sev".into(),
            service: "sev".into(),
            severity: Severity::Medium,
            keywords: vec![],
            patterns: vec![PatternSpec {
                regex: "[A-Z]{40}".into(),
                description: None,
                group: None,
            }],
            companions: vec![],
            verify: None,
        };
        let mut bumped = base.clone();
        bumped.severity = Severity::Critical;
        assert_ne!(
            compute_spec_hash(&[base]),
            compute_spec_hash(&[bumped]),
            "bumping severity must invalidate the cache"
        );
    }
