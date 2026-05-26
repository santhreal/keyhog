use super::support::{make_detector, make_orchestrator};

#[test]
fn orchestrator_args_accessor_returns_scan_args() {
    let orch = make_orchestrator(vec![make_detector()]);
    assert!(!orch.args().lockdown);
}
