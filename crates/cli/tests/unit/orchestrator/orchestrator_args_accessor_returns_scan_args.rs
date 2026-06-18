use super::support::{make_detector, make_orchestrator};
use keyhog::testing::{CliTestApi as _, API};

#[test]
fn orchestrator_args_accessor_returns_scan_args() {
    let orch = make_orchestrator(vec![make_detector()]);
    assert!(!API.scan_orchestrator_args(&orch).lockdown);
}
