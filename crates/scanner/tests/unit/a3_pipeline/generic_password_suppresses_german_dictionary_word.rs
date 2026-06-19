use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::should_suppress_named_detector_finding;

#[test]
fn german_dictionary_word_in_i18n_properties_suppressed() {
    // Dogfood FP from WebGoatLabels_german.properties.
    // `Benutzername` (German for "username", 12 letters, no digit)
    // gets captured by `(?i)password[=:]<word>` shapes in i18n
    // .properties files. Pure-alphabetic 8..=32 char strings
    // without digit are dictionary words, not credentials.
    assert!(should_suppress_named_detector_finding(
        "Benutzername",
        Some("WebGoatLabels_german.properties"),
        CodeContext::Unknown,
        None,
        "generic-password",
    ));
}
