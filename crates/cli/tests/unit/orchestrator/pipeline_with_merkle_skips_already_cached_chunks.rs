//! Pipeline: merkle content-hash hit skips scan.

use super::support::{make_chunk, make_detector, make_orchestrator, StaticSource};
use keyhog::testing::{CliTestApi as _, API};
use keyhog_core::Source;
use std::sync::Arc;

#[test]
fn pipeline_with_merkle_skips_already_cached_chunks() {
    let orch = make_orchestrator(vec![make_detector()]);
    let text = "STATIC_SECRET_42424242 here";
    let chunk = make_chunk(text, "y.rs");
    let merkle = Arc::new(keyhog_core::testing::CoreTestApi::merkle_empty(
        &keyhog_core::testing::TestApi,
    ));
    let known_hash = keyhog_core::testing::CoreTestApi::merkle_hash_content(
        &keyhog_core::testing::TestApi,
        text.as_bytes(),
    );
    keyhog_core::testing::CoreTestApi::merkle_record(
        &keyhog_core::testing::TestApi,
        &merkle,
        std::path::PathBuf::from("y.rs"),
        known_hash,
    );
    let sources: Vec<Box<dyn Source>> = vec![Box::new(StaticSource {
        chunks: vec![chunk],
    })];
    let findings = API
        .scan_orchestrator_scan_sources_for_test(&orch, sources, false, Some(merkle))
        .expect("scan sources");
    assert!(findings.is_empty(), "cached hash must skip scan");
}
