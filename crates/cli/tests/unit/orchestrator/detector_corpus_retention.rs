//! Detector-spec ownership after scanner construction.

use super::support::{
    make_chunk, make_detector, make_orchestrator, scan_sources_for_test, StaticSource,
};
#[cfg(feature = "verify")]
use clap::Parser;
use keyhog::testing::{CliTestApi as _, API};
use keyhog_core::Source;

/// A non-verifying scan must release the flexible detector specifications while
/// the compiled scanner retains the exact metadata needed for emitted matches.
#[test]
fn non_verifying_orchestrator_releases_detector_specs_after_compilation() {
    let orchestrator = make_orchestrator(vec![make_detector()]);
    assert_eq!(API.scan_orchestrator_detector_count(&orchestrator), 1);
    assert_eq!(
        API.scan_orchestrator_retained_detector_specs(&orchestrator),
        0,
        "non-verifying scans must not retain the detector specification graph"
    );

    let sources: Vec<Box<dyn Source>> = vec![Box::new(StaticSource {
        chunks: vec![make_chunk(
            "let key = STATIC_SECRET_12345;",
            "retention-fixture.rs",
        )],
    })];
    let findings = scan_sources_for_test(&orchestrator, sources, false, None)
        .expect("scan after detector specifications are released");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].detector_id.as_ref(), "static-test");
    assert_eq!(findings[0].detector_name.as_ref(), "Static Test");
    assert_eq!(findings[0].service.as_ref(), "test");
    assert_eq!(findings[0].credential.as_str(), "STATIC_SECRET_12345");
    assert_eq!(
        findings[0].location.file_path.as_deref(),
        Some("retention-fixture.rs")
    );
}

/// A verifying scan retains the detector specifications because verifier-plan
/// construction consumes detector-owned verification definitions after scanning.
#[cfg(feature = "verify")]
#[test]
fn verifying_orchestrator_retains_detector_specs_for_verifier_plans() {
    let args = keyhog::args::ScanArgs::try_parse_from(["scan", "--verify"])
        .expect("parse verifying scan arguments");
    let orchestrator = super::support::make_orchestrator_with_args(vec![make_detector()], args);

    assert_eq!(API.scan_orchestrator_detector_count(&orchestrator), 1);
    assert_eq!(
        API.scan_orchestrator_retained_detector_specs(&orchestrator),
        1,
        "verifying scans must retain the detector specification graph"
    );
}
