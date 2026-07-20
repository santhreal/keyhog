use keyhog_core::{Chunk, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::testing::scan_coalesced_phase2_with_admission_for_test;
use keyhog_scanner::CompiledScanner;

#[test]
fn no_hit_multiline_text_uses_the_shared_phase_two_result_path() {
    let detector = DetectorSpec {
        id: "no-hit-multiline-fixture".into(),
        name: "No-hit multiline fixture".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: r"([A-F0-9]{8}-[A-F0-9]{8})".into(),
            group: Some(1),
            required_literals: Vec::new(),
            ..Default::default()
        }],
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };
    let scanner = CompiledScanner::compile(vec![detector]).expect("compile detector");
    let credential = "A1B2C3D4-E5F60718";
    let chunks = [Chunk::from(format!("value = {credential}"))];

    let results =
        scan_coalesced_phase2_with_admission_for_test(&scanner, &chunks, vec![None], None, None);

    let found = results[0]
        .iter()
        .find(|finding| finding.detector_id.as_ref() == "no-hit-multiline-fixture")
        .expect("a no-trigger row must execute the shared phase-two path");
    assert_eq!(found.credential.as_ref(), credential);
}
