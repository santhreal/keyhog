//! KH-GAP-075: macOS CI lane never exercises default-features Hyperscan path.

use super::support::read_workflow;

#[test]
fn macos_build_job_tests_default_features_with_hyperscan() {
    let text = read_workflow("ci.yml");

    let macos_block = text
        .split("macos-build:")
        .nth(1)
        .and_then(|rest| rest.split("\n  feature-matrix:").next())
        .expect("ci.yml must define macos-build job");

    let exercises_default = macos_block.lines().any(|line| {
        line.contains("cargo test -p keyhog-scanner --lib")
            && !line.contains("--no-default-features")
    });
    let installs_vectorscan =
        macos_block.contains("libhyperscan") || macos_block.contains("vectorscan");

    assert!(
        exercises_default && installs_vectorscan,
        "macos-build uses --no-default-features only. Hyperscan/simd path is never \
         compiled or tested on macOS CI (KH-GAP-075). Block excerpt:\n{macos_block}"
    );
}
