//! KH-GAP-075: macOS CI lane never exercises default-features Hyperscan path.

use super::support::read_workflow;

/// Prevents macOS accelerator regressions from hiding both the default-feature
/// execution path and the panic or typed error that caused the failing test.
#[test]
fn macos_build_job_tests_default_features_with_hyperscan() {
    let text = read_workflow("ci-nightly.yml");

    let macos_block = text
        .split("macos-build:")
        .nth(1)
        .and_then(|rest| rest.split("\n  windows-build:").next())
        .expect("ci-nightly.yml must define macos-build job");

    let exercises_default = macos_block.lines().any(|line| {
        line.contains("cargo test -p keyhog-scanner --lib")
            && !line.contains("--no-default-features")
    });
    let installs_vectorscan =
        macos_block.contains("libhyperscan") || macos_block.contains("vectorscan");

    assert!(
        exercises_default && installs_vectorscan && macos_block.contains("-- --nocapture"),
        "macos-build must test the default Vectorscan path and retain failure output with \
         `-- --nocapture` (KH-GAP-075). Block excerpt:\n{macos_block}"
    );

    assert!(
        !macos_block.contains("--test-threads=1")
            && !macos_block.contains("RUST_TEST_THREADS=1")
            && !macos_block
                .lines()
                .any(|line| line.trim_start().starts_with("sleep ")),
        "macos-build must keep the scanner tests parallel and must not mask live-adapter races \
         with process serialization or fixed sleeps. Block excerpt:\n{macos_block}"
    );
}
