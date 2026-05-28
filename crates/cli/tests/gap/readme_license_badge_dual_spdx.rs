//! KH-GAP-149: README license badge/text said MIT-only while workspace uses
//! MIT OR Apache-2.0 (KH-GAP-133 fixed Cargo.toml only).

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d
}

#[test]
fn readme_license_badge_matches_dual_spdx_workspace_contract() {
    let readme = std::fs::read_to_string(repo_root().join("README.md")).expect("README.md");
    assert!(
        readme.contains("MIT OR Apache-2.0") || readme.contains("MIT%20OR%20Apache--2.0"),
        "README must document dual SPDX license, not MIT-only"
    );
    assert!(
        !readme.contains("badge/license-MIT-blue"),
        "README must not use MIT-only shields badge"
    );
}
