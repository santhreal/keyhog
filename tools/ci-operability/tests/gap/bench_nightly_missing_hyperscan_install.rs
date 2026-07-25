//! KH-GAP-079: bench-nightly builds keyhog without Hyperscan dev libs.

use super::support::read_workflow;

/// Locks out installing only Hyperscan's runtime library, which lacks the
/// pkg-config metadata and headers required by `hyperscan-sys`, or installing
/// the development package after the selected SIMD scanner has already built.
#[test]
fn benchmark_workflows_install_hyperscan_development_files_before_build() {
    for (workflow, build_step) in [
        ("bench-nightly.yml", "name: Build keyhog release binary"),
        (
            "differential-bench.yml",
            "name: build checked-out keyhog (CPU-only release binary)",
        ),
    ] {
        let text = read_workflow(workflow);
        let install = text
            .find("libhyperscan-dev")
            .unwrap_or_else(|| panic!("{workflow} must install libhyperscan-dev"));
        let pkg_config = text
            .find("pkg-config")
            .unwrap_or_else(|| panic!("{workflow} must install pkg-config"));
        let build = text
            .find(build_step)
            .unwrap_or_else(|| panic!("{workflow} is missing its KeyHog build step"));

        assert!(
            install < build && pkg_config < build,
            "{workflow} selects ci-lean SIMD/Hyperscan and must install its development \
             files plus pkg-config before compiling"
        );
        assert!(
            !text.contains("libhyperscan5"),
            "{workflow} must not accept the runtime-only libhyperscan5 package as \
             sufficient build tooling"
        );
    }
}
