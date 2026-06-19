//! KH-GAP-079: bench-nightly builds keyhog without Hyperscan dev libs.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[test]
fn bench_nightly_installs_hyperscan_before_release_build() {
    let text = std::fs::read_to_string(repo_root().join(".github/workflows/bench-nightly.yml"))
        .expect("read bench-nightly.yml");

    let has_hyperscan = text.contains("libhyperscan-dev")
        || text.contains("libhyperscan5")
        || text.contains("vectorscan");

    assert!(
        has_hyperscan,
        "bench-nightly.yml builds `cargo build --release -p keyhog` with default \
         features (simd/Hyperscan) but never installs libhyperscan — nightly leaderboard \
         may measure portable fallback, not production Linux build (KH-GAP-079)"
    );
}
