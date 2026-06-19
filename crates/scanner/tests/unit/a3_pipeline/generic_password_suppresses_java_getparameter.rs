use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::should_suppress_named_detector_finding;

#[test]
fn java_getparameter_camelcase_identifier_suppressed() {
    // Dogfood FP from webgoat/WebgoatContext.java:93
    //   databasePassword = getParameter(servlet, DATABASE_PASSWORD);
    // The generic-password TOML regex matches `password = X` and
    // captures `getParameter` (12 chars, pure CamelCase, no digit,
    // no underscore). Real credentials almost always include a digit
    // or special char - this filter never trips on those.
    assert!(should_suppress_named_detector_finding(
        "getParameter",
        Some("webgoat/WebgoatContext.java"),
        CodeContext::Unknown,
        None,
        "generic-password",
    ));
}
