//! Gap test: exact ScanError Display text + the "Fix:" guidance contract.
//!
//! The engineering standard is that error messages "include context and the
//! fix". The existing ScanError tests only assert weak substrings
//! (`err.to_string().contains("probe")`); this pins the EXACT Display string of
//! the fully-controlled String-carrying variants, and pins the `Fix:` guidance
//! suffix that the bundled-rules / detector-regex variants must carry.

use keyhog_scanner::ScanError;

#[test]
fn gpu_and_simd_failure_display_is_exact() {
    assert_eq!(
        ScanError::Gpu("probe failed".to_string()).to_string(),
        "GPU scanner failure: probe failed"
    );
    assert_eq!(
        ScanError::Simd("init blew up".to_string()).to_string(),
        "SIMD scanner failure: init blew up"
    );
}

#[test]
fn config_failure_display_carries_the_fix_guidance() {
    assert_eq!(
        ScanError::Config("rules file missing".to_string()).to_string(),
        "scanner configuration failure: rules file missing. Fix: correct the bundled scanner rules"
    );
}

#[test]
fn regex_compile_display_template_and_fix_suffix_are_exact() {
    let err = ScanError::RegexCompile {
        detector_id: "aws-key".to_string(),
        index: 2,
        source: regex::Error::Syntax("oops".to_string()),
    };
    let msg = err.to_string();
    // The template text on either side of the source render is source-independent
    // and exact: detector id + pattern index up front, the Fix: guidance at the end.
    assert!(
        msg.starts_with("failed to compile regex for detector aws-key pattern 2: "),
        "got: {msg}"
    );
    assert!(
        msg.ends_with(". Fix: correct the detector regex or capture group configuration"),
        "got: {msg}"
    );
}
