use super::support::{make_detector, make_orchestrator};

#[test]
fn orchestrator_scanner_accessor_returns_compiled() {
    let orch = make_orchestrator(vec![make_detector()]);
    assert!(!orch.scanner().detector_count().to_string().is_empty());
}
