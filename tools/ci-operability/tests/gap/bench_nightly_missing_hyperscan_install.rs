//! KH-GAP-079: hosted CPU workflows require exact Hyperscan build and runtime supply.

use super::support::read_workflow;

/// Installing only runtime `libhyperscan5` once broke `hyperscan-sys`, while an
/// unversioned dev/runtime rollout could later change dynamically linked scan
/// behavior without changing the release binary. Require exact build packages
/// before compilation and an exact post-build `libhs` package/digest receipt.
#[test]
fn benchmark_workflows_pin_hyperscan_build_and_runtime_identity() {
    for (workflow, build_step) in [
        ("bench-nightly.yml", "name: Build keyhog release binary"),
        (
            "differential-bench.yml",
            "name: build checked-out keyhog (CPU-only release binary)",
        ),
    ] {
        let text = read_workflow(workflow);
        let install = text
            .find("libhyperscan-dev=5.4.2-2")
            .unwrap_or_else(|| panic!("{workflow} must pin libhyperscan-dev"));
        let runtime = text
            .find("libhyperscan5=5.4.2-2")
            .unwrap_or_else(|| panic!("{workflow} must pin the linked runtime package"));
        let pkg_config = text
            .find("pkg-config=1.8.1-2build1")
            .unwrap_or_else(|| panic!("{workflow} must pin pkg-config"));
        let build = text
            .find(build_step)
            .unwrap_or_else(|| panic!("{workflow} is missing its KeyHog build step"));
        let receipt = text
            .find("schema_version\": \"hosted-cpu-supply-v1")
            .unwrap_or_else(|| panic!("{workflow} must emit a hosted supply receipt"));

        assert!(
            install < build && runtime < build && pkg_config < build && build < receipt,
            "{workflow} must install exact build/runtime packages before compilation, then receipt the linked runtime"
        );
        assert!(
            text.contains("dpkg-query -W -f='${Version}' libhyperscan-dev)")
                && text.contains("dpkg-query -W -f='${Version}' libhyperscan5)")
                && (text.contains("ldd target/release/keyhog")
                    || text.contains("ldd \"$(command -v keyhog)\""))
                && text.contains("libhs_sha256=\"$(sha256sum")
                && text.contains("\"package\": \"libhyperscan5\"")
                && text.contains("\"package_version\": \"5.4.2-2\""),
            "{workflow} must verify package versions and bind the exact loaded libhs bytes"
        );
        assert!(
            !text.contains("--no-install-recommends libhyperscan-dev pkg-config")
                && !text.contains("--no-install-recommends libhyperscan-dev libhyperscan5 pkg-config"),
            "{workflow} must reject mutable unversioned Hyperscan/pkg-config installation"
        );
    }
}
