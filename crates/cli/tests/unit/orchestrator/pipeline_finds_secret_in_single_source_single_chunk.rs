//! Pipeline: single chunk yields one finding.

use super::support::{
    make_chunk, make_detector, make_orchestrator, scan_sources_for_test, StaticSource,
};
use keyhog_core::Source;

#[test]
fn pipeline_finds_secret_in_single_source_single_chunk() {
    let orch = make_orchestrator(vec![make_detector()]);
    let sources: Vec<Box<dyn Source>> = vec![Box::new(StaticSource {
        chunks: vec![make_chunk("let key = STATIC_SECRET_12345;", "fixture.rs")],
    })];
    let findings = scan_sources_for_test(&orch, sources, false, None).expect("scan sources");
    assert_eq!(findings.len(), 1);
    assert_eq!(&*findings[0].credential, "STATIC_SECRET_12345");
}
