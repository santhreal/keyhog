use super::support::{make_detector, make_orchestrator};
use keyhog::testing::{CliTestApi as _, API};

#[test]
fn orchestrator_scanner_accessor_returns_compiled() {
    let orch = make_orchestrator(vec![make_detector()]);
    assert!(!API
        .scan_orchestrator_scanner(&orch)
        .runtime_status()
        .detector_count
        .to_string()
        .is_empty());
}
