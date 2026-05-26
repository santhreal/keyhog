use keyhog_scanner::context::CodeContext;
use keyhog_scanner::pipeline::should_suppress_named_detector_finding;

#[test]
fn real_password_with_digits_not_suppressed_by_camelcase_filter() {
    // Adversarial twin: a real credential that's 14 chars and has
    // mixed case BUT includes digits — must NOT trip the CamelCase
    // identifier filter (presence of any digit disqualifies a value
    // from the identifier-shape suppression path).
    // If this assertion ever flips to true we've broken real-cred
    // recall.
    assert!(!should_suppress_named_detector_finding(
        "Passw0rdAbc123",
        Some("config.env"),
        CodeContext::Unknown,
        None,
        "generic-password",
    ));
}
