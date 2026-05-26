use super::support::{make_detector, make_orchestrator};

#[test]
fn orchestrator_from_parts_for_test_compiles_scanner() {
    let orch = make_orchestrator(vec![make_detector()]);
    assert!(orch.scanner().pattern_count() >= 1);
}
