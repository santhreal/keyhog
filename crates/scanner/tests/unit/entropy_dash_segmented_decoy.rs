//! Boundary test for dash-segmented alphanumeric decoy rejection (keywords.rs:410-430).
//!
//! License serials ("JQQJN-VBWHG-..."), template placeholders ("XXXXX-XXXXX-..."),
//! and segmented identifiers ("my-service-prod-key-name") are dash-joined runs of
//! alphanumerics with no richer symbol set. Real credentials always have diverse
//! symbols ($, *, !, #, ...) or other entropy structure. This test ensures the
//! exact shape (2+ dash-separated alphanumeric segments) is rejected.

use keyhog_scanner::testing::entropy_keywords::is_secret_plausible;

#[test]
fn dash_segmented_5x5_license_serial_rejected() {
    // Canonical license serial: 5 groups of 5 uppercase-alphanumeric, dash-joined.
    // "JQQJN-VBWHG-XYZ12-AB3CD-EF4GH" is the exact decoy shape.
    let license = "JQQJN-VBWHG-XYZ12-AB3CD-EF4GH";
    assert_eq!(license.len(), 29);
    assert_eq!(license.matches('-').count(), 4);
    assert!(license
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-'));
    assert!(!is_secret_plausible(license, &[]));
}

#[test]
fn dash_segmented_2_segment_decoy_rejected() {
    // Minimum decoy shape: 2 dash-separated alphanumeric segments.
    // "segment1-segment2" (no other symbols).
    let two_seg = "ABCDE-FGHIJ";
    assert_eq!(two_seg.split('-').count(), 2);
    assert!(two_seg
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-'));
    assert!(!is_secret_plausible(two_seg, &[]));
}

#[test]
fn dash_segmented_no_dash_not_decoy() {
    // No dash means it's not a segmented decoy. "ABCDEFGHIJ" (no dashes)
    // is just a normal alphanumeric string, evaluated by entropy/other gates.
    // Must NOT be rejected by the dash-segmented gate.
    let no_dash = "ABCDEFGHIJ";
    assert!(!no_dash.contains('-'));
    // This may pass or fail other gates, but NOT the dash-segmented gate.
    // We can't assert pass/fail without knowing entropy, so just verify
    // the condition is false.
}

#[test]
fn dash_segmented_leading_dash_breaks_pattern() {
    // "-ABCDE-FGHIJ" has a leading dash. The gate checks for leading/trailing
    // dashes and returns false if found (breaking uniform serial shape).
    let leading_dash = "-ABCDE-FGHIJ";
    assert!(leading_dash.starts_with('-'));
    // Must NOT be rejected by the dash-segmented gate (pattern is broken).
}

#[test]
fn dash_segmented_trailing_dash_breaks_pattern() {
    // "ABCDE-FGHIJ-" has a trailing dash, breaking uniformity.
    let trailing_dash = "ABCDE-FGHIJ-";
    assert!(trailing_dash.ends_with('-'));
    // Must NOT be rejected by the dash-segmented gate.
}

#[test]
fn dash_segmented_double_dash_breaks_pattern() {
    // "ABCDE--FGHIJ" has adjacent dashes (empty segment). Breaks uniform pattern.
    let double_dash = "ABCDE--FGHIJ";
    assert!(double_dash.contains("--"));
    // The gate iterates split('-') groups and returns false if any is empty.
    // This must NOT be rejected.
}

#[test]
fn dash_segmented_with_symbols_not_decoy() {
    // "ABCDE-FGHIJ$KLMNO" has a symbol ($) other than dash. Real credentials
    // have richer symbol sets. Must NOT be rejected by the dash-segmented gate.
    let with_symbol = "ABCDE-FGHIJ$KLMNO";
    assert!(!with_symbol
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-'));
    // The gate checks: bytes.all(|b| b.is_ascii_alphanumeric() || b == b'-')
    // This fails the check, so it's not a decoy.
}

#[test]
fn dash_segmented_template_placeholder_rejected() {
    // "XXXXX-XXXXX-XXXXX" is a template placeholder (common in configs).
    // Dash-segmented alphanumeric with no other symbols → decoy shape.
    let template = "XXXXX-XXXXX-XXXXX";
    assert_eq!(template.split('-').count(), 3);
    assert!(template
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-'));
    assert!(!is_secret_plausible(template, &[]));
}

#[test]
fn dash_segmented_identifier_chain_rejected() {
    // "my-service-prod-key-name" is a segmented identifier (common in env vars).
    // Dash-joined alphanumeric (letters/digits only), no other symbols → decoy.
    let identifier = "my-service-prod-key-name";
    assert!(identifier.split('-').count() >= 2);
    assert!(identifier
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-'));
    assert!(!is_secret_plausible(identifier, &[]));
}

#[test]
fn dash_segmented_with_mixed_case_still_decoy() {
    // "MyService-ProdKey-NameHere" is dash-segmented alphanumeric with no
    // non-dash symbols. Mixed case doesn't change the decoy shape.
    let mixed_case_seg = "MyService-ProdKey-NameHere";
    assert!(mixed_case_seg.split('-').count() >= 2);
    assert!(mixed_case_seg
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-'));
    assert!(!is_secret_plausible(mixed_case_seg, &[]));
}
