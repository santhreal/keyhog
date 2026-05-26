//! Pipeline: empty source returns no findings without panic.

use super::support::{make_detector, make_orchestrator, StaticSource};
use keyhog_core::Source;

#[test]
fn pipeline_handles_empty_source() {
    let orch = make_orchestrator(vec![make_detector()]);
    let sources: Vec<Box<dyn Source>> = vec![Box::new(StaticSource { chunks: Vec::new() })];
    let findings = orch.scan_sources_for_test(sources, false, None);
    assert!(findings.is_empty());
}
