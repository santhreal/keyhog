use keyhog_scanner::context::{infer_context, CodeContext};
use keyhog_scanner::testing::confidence::apply_path_confidence_penalties;
use keyhog_scanner::testing::{compute_line_offsets, should_suppress_named_detector_finding};

#[test]
fn windows_form_test_path_classifies_as_test_code_on_every_host() {
    let lines = ["let api_key = \"not-a-real-value\";"];
    assert_eq!(
        infer_context(&lines, 0, Some(r"C:\repo\tests\auth_fixture.rs")),
        CodeContext::TestCode
    );
    assert_eq!(
        infer_context(&lines, 0, Some(r"Z:\repo\spec\auth_spec.rb")),
        CodeContext::TestCode
    );
}

#[test]
fn windows_form_fixture_path_halves_confidence_on_every_host() {
    let out =
        apply_path_confidence_penalties(0.8, Some(r"C:\repo\fixtures\dummy\config.env"), true);
    assert!((out - 0.4).abs() < 1e-9, "fixture path -> *0.5, got {out}");
}

#[test]
fn windows_form_base64_path_suppresses_raw_filesystem_hits() {
    let suppressed = should_suppress_named_detector_finding(
        "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0Kk",
        Some(r"C:\repo\assets\base64_string.txt"),
        CodeContext::Unknown,
        Some("filesystem"),
        "example-named-detector",
    );
    assert!(
        suppressed,
        "raw base64 filename gate must accept backslashes"
    );
}

#[test]
fn raw_base64_path_gate_is_filesystem_scoped() {
    let suppressed = should_suppress_named_detector_finding(
        "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0Kk",
        Some(r"C:\repo\assets\base64_string.txt"),
        CodeContext::Unknown,
        Some("git"),
        "example-named-detector",
    );
    assert!(
        !suppressed,
        "non-filesystem sources must not take the raw-file gate"
    );
}

#[test]
fn line_ending_handling_compute_offsets() {
    let unix_text = "line1\nline2\nline3";
    let win_text = "line1\r\nline2\r\nline3";

    let unix_offsets = compute_line_offsets(unix_text);
    let win_offsets = compute_line_offsets(win_text);

    // In current implementation, both should find the same number of lines
    assert_eq!(unix_offsets.len(), 3);
    assert_eq!(win_offsets.len(), 3);

    // For unix: [0, 6, 12]
    // For win: [0, 7, 14]
    assert_eq!(unix_offsets, vec![0, 6, 12]);
    assert_eq!(win_offsets, vec![0, 7, 14]);
}
