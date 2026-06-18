//! Pipeline: empty source returns no findings without panic.

use super::support::{make_detector, make_orchestrator, StaticSource};
use keyhog::testing::{CliTestApi as _, API};
use keyhog_core::Source;

#[test]
fn pipeline_handles_empty_source() {
    let orch = make_orchestrator(vec![make_detector()]);
    let sources: Vec<Box<dyn Source>> = vec![Box::new(StaticSource { chunks: Vec::new() })];
    let findings = API
        .scan_orchestrator_scan_sources_for_test(&orch, sources, false, None)
        .expect("scan sources");
    assert!(findings.is_empty());
}
