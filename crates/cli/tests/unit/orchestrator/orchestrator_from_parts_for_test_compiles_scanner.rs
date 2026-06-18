use super::support::{make_detector, make_orchestrator};
use keyhog::testing::{CliTestApi as _, API};

#[test]
fn orchestrator_from_parts_for_test_compiles_scanner() {
    let orch = make_orchestrator(vec![make_detector()]);
    assert!(
        API.scan_orchestrator_scanner(&orch)
            .runtime_status()
            .pattern_count
            >= 1
    );
}
