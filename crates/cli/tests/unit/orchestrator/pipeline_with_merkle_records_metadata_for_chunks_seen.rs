//! Pipeline: merkle index records chunk metadata under threaded handoff.

use super::support::{make_chunk, make_detector, make_orchestrator, StaticSource};
use keyhog_core::Source;
use std::sync::Arc;

#[test]
fn pipeline_with_merkle_records_metadata_for_chunks_seen() {
    let orch = make_orchestrator(vec![make_detector()]);
    let mut chunk = make_chunk("STATIC_SECRET_42424242 here", "x.rs");
    chunk.metadata.mtime_ns = Some(1_700_000_000_000_000_000);
    chunk.metadata.size_bytes = Some(123);
    let merkle = Arc::new(keyhog_core::merkle_index::MerkleIndex::empty());
    let sources: Vec<Box<dyn Source>> = vec![Box::new(StaticSource { chunks: vec![chunk] })];
    let findings = orch.scan_sources_for_test(sources, false, Some(merkle.clone()));
    assert_eq!(findings.len(), 1);
    assert!(merkle.metadata_unchanged(
        std::path::Path::new("x.rs"),
        1_700_000_000_000_000_000,
        123,
    ));
}
