//! KH-GAP-079: bench-nightly builds keyhog without Hyperscan dev libs.

use super::support::read_workflow;

#[test]
fn bench_nightly_installs_hyperscan_before_release_build() {
    let text = read_workflow("bench-nightly.yml");

    let has_hyperscan = text.contains("libhyperscan-dev")
        || text.contains("libhyperscan5")
        || text.contains("vectorscan");

    assert!(
        has_hyperscan,
        "bench-nightly.yml builds `cargo build --release -p keyhog` with default \
         features (simd/Hyperscan) but never installs libhyperscan, nightly leaderboard \
         may measure portable fallback, not production Linux build (KH-GAP-079)"
    );
}
