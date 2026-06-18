//! Pipeline: within-source iteration emits every chunk.

use super::support::{make_chunk, make_detector, make_orchestrator, StaticSource};
use keyhog::testing::{CliTestApi as _, API};
use keyhog_core::Source;

#[test]
fn pipeline_two_chunks_in_one_source_both_yield_findings() {
    let orch = make_orchestrator(vec![make_detector()]);
    let sources: Vec<Box<dyn Source>> = vec![Box::new(StaticSource {
        chunks: vec![
            make_chunk("first STATIC_SECRET_12345 here", "x.rs"),
            make_chunk("second STATIC_SECRET_67890 there", "y.rs"),
        ],
    })];
    let findings = API
        .scan_orchestrator_scan_sources_for_test(&orch, sources, false, None)
        .expect("scan sources");
    assert_eq!(findings.len(), 2);
}
