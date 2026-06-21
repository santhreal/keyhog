use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::named_detector_suppressed;

#[test]
fn powershell_verb_noun_pattern_suppressed_for_generic_detectors() {
    // Dogfood: claude-code/src/utils/powershell/parser.ts:1343 has
    //   `pwd: 'Get-Location',`
    // The generic-secret fallback regex matches the `pwd` keyword,
    // skips `: '`, and captures `Get-Location` (12 chars, 1 hyphen,
    // no digit, mixed case).  v0.5.20 emitted it as generic-secret
    // because the fallback path didn't go through
    // `looks_like_pure_identifier`; v0.5.21 wires that filter in.
    // This test exercises the named-detector path which shares the
    // same shape gate.
    assert!(named_detector_suppressed(
        "Get-Location",
        Some("powershell/parser.ts"),
        CodeContext::Unknown,
        None,
        "generic-password",
    ));
    assert!(named_detector_suppressed(
        "Set-Location",
        Some("powershell/parser.ts"),
        CodeContext::Unknown,
        None,
        "generic-password",
    ));
}
