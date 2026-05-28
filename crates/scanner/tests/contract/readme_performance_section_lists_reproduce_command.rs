//! Contract: README performance section cites a reproducible benchmark command.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d
}

#[test]
fn readme_performance_section_lists_reproduce_command() {
    let readme = std::fs::read_to_string(repo_root().join("README.md"))
        .expect("root README.md readable");

    assert!(
        readme.contains("## Performance"),
        "README must retain a Performance section backing throughput/recall table claims"
    );
    assert!(
        readme.contains("cargo bench --bench scan_throughput")
            || readme.contains("leaderboard.py"),
        "README Performance section must cite `cargo bench --bench scan_throughput` or \
         secretbench leaderboard - table alone is not reproducible in CI"
    );
}
