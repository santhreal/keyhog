use keyhog_scanner::context::CodeContext;
use keyhog_scanner::pipeline::should_suppress_known_example_credential_with_source;

// The CI-workflow path filter lives inside `engine::fallback_entropy`,
// not the global suppression library - it's only meaningful for the
// entropy-fallback path. This test documents the contract via a
// related public surface: a high-entropy github-actions step name
// must NOT be suppressed by the global pipeline (so the regression
// signal is "the path filter is the only thing keeping it quiet").
#[test]
fn high_entropy_workflow_step_name_not_globally_suppressed() {
    // `Upload to Codecov` is what entropy-* fires on (entropy ~3.6).
    // Global suppression has no path filter, so it returns false; the
    // entropy fallback filter is what kills it. This test exists so a
    // future change that adds blanket suppression of step-name strings
    // doesn't silently propagate to named detectors that should still
    // catch a real `${{ secrets.SOMETHING }}` value.
    assert!(!should_suppress_known_example_credential_with_source(
        "UploadtoCodecov",
        Some("/repo/.github/workflows/coverage.yml"),
        CodeContext::Unknown,
        None,
    ));
}
