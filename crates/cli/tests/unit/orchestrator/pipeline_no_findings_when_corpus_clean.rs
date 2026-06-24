//! Pipeline: clean corpus yields zero findings.

use super::support::{
    make_chunk, make_detector, make_orchestrator, scan_sources_for_test, StaticSource,
};
use keyhog_core::Source;

#[test]
fn pipeline_no_findings_when_corpus_clean() {
    let orch = make_orchestrator(vec![make_detector()]);
    let sources: Vec<Box<dyn Source>> = vec![Box::new(StaticSource {
        chunks: vec![
            make_chunk("plain text", "a.rs"),
            make_chunk("more boring content", "b.rs"),
        ],
    })];
    let findings = scan_sources_for_test(&orch, sources, false, None).expect("scan sources");
    assert!(findings.is_empty());
}
