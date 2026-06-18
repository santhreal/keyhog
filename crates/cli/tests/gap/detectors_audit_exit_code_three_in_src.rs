//! Contract gate: detectors subcommand defines audit failure exit 3.

#[test]
fn detectors_audit_exit_code_three_in_src() {
    assert_eq!(keyhog::exit_codes::EXIT_DETECTOR_AUDIT_FAILED, 3);
}
