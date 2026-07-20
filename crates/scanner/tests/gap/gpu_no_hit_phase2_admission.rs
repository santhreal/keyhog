use keyhog_core::{Chunk, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::testing::scan_coalesced_phase2_with_admission_for_test;
use keyhog_scanner::{CompiledScanner, ScannerConfig};

fn prefixless_detector() -> DetectorSpec {
    DetectorSpec { id: "phase2-prefixless-fixture".into(),
    name: "Phase Two Prefixless Fixture".into(),
    service: "test".into(),
    severity: Severity::High,
    patterns: vec![PatternSpec {
        regex: r"(?:^|[^A-Za-z0-9_-])([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}:fx)(?:$|[^A-Za-z0-9_-])".into(),
        description: None,
        group: Some(1),
        required_literals: Vec::new(),
        client_safe: false,
        weak_anchor: false,
        structural_password_slot: false,
    }], ..keyhog_scanner::testing::named_detector_fixture_defaults() }
}

#[test]
fn missing_gpu_completeness_keeps_cpu_phase2_admission_authoritative() {
    let scanner = CompiledScanner::compile(vec![prefixless_detector()]).expect("compile detector");
    let credential = "01234567-89ab-cdef-0123-456789abcdef:fx";
    let chunks = [Chunk::from(format!("value = {credential}"))];
    let admitted = [false];

    let results = scan_coalesced_phase2_with_admission_for_test(
        &scanner,
        &chunks,
        vec![Some(vec![1])],
        Some(&admitted),
        None,
    );

    let found = results[0]
        .iter()
        .find(|finding| finding.detector_id.as_ref() == "phase2-prefixless-fixture")
        .expect("an incomplete triggered GPU row must consult the CPU phase-two owner");
    assert_eq!(found.credential.as_ref(), credential);
}

#[test]
fn complete_phase2_negative_does_not_bypass_generic_assignment_detection() {
    let detectors = keyhog_core::load_embedded_detectors_or_fail()
        .expect("embedded detector corpus must parse");
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    let scanner = CompiledScanner::compile(detectors)
        .expect("compile embedded detectors")
        .with_config(config);
    let credential = "ufnlbbavawsdeecn";
    let chunks = [Chunk::from(format!("password={credential}\n"))];
    let admitted = [false];
    let complete = [true];

    let results = scan_coalesced_phase2_with_admission_for_test(
        &scanner,
        &chunks,
        vec![None],
        Some(&admitted),
        Some(&complete),
    );

    let found = results[0]
        .iter()
        .find(|finding| finding.credential.as_ref() == credential)
        .expect("a complete phase-two negative may skip only duplicate phase-two admission");
    assert_eq!(found.detector_id.as_ref(), "generic-password");
}

#[test]
fn normalized_required_literal_reenters_phase_one_before_phase_two_admission() {
    let detector = DetectorSpec {
        id: "normalized-required-literal".into(),
        name: "Normalized Required Literal".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: r"([a-f0-9]{8}:fx)".into(),
            group: Some(1),
            required_literals: vec![":fx".into()],
            ..Default::default()
        }],
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };
    let scanner = CompiledScanner::compile(vec![detector]).expect("compile detector");
    let chunks = [Chunk::from("value=0123abcd:\u{ff46}\u{ff58}")];

    let results =
        scan_coalesced_phase2_with_admission_for_test(&scanner, &chunks, vec![None], None, None);

    let found = results[0]
        .iter()
        .find(|finding| finding.detector_id.as_ref() == "normalized-required-literal")
        .expect("normalized text must rerun phase-one routing before no-hit rejection");
    assert_eq!(found.credential.as_ref(), "0123abcd:fx");
}
