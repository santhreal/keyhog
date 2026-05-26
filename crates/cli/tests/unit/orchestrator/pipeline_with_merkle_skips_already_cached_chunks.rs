//! Pipeline: merkle content-hash hit skips scan.

use super::support::{make_chunk, make_detector, make_orchestrator, StaticSource};
use keyhog_core::Source;
use std::sync::Arc;

#[test]
fn pipeline_with_merkle_skips_already_cached_chunks() {
    let orch = make_orchestrator(vec![make_detector()]);
    let text = "STATIC_SECRET_42424242 here";
    let chunk = make_chunk(text, "y.rs");
    let merkle = Arc::new(keyhog_core::merkle_index::MerkleIndex::empty());
    let known_hash = keyhog_core::merkle_index::MerkleIndex::hash_content(text.as_bytes());
    merkle.record(std::path::PathBuf::from("y.rs"), known_hash);
    let sources: Vec<Box<dyn Source>> = vec![Box::new(StaticSource { chunks: vec![chunk] })];
    let findings = orch.scan_sources_for_test(sources, false, Some(merkle));
    assert!(findings.is_empty(), "cached hash must skip scan");
}
