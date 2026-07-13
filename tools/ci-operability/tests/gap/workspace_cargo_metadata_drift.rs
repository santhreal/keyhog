//! KH-GAP-133: STANDARD Cargo.toml contract (authors email + license SPDX).

use super::support::repo_root;

#[test]
fn workspace_package_metadata_matches_standard_contract() {
    let toml =
        std::fs::read_to_string(repo_root().join("Cargo.toml")).expect("workspace Cargo.toml");
    assert!(
        toml.contains("authors = [\"Santh Project <contact@santh.dev>\"]"),
        "STANDARD.md requires authors contact@santh.dev (not security@ personal variant)"
    );
    assert!(
        toml.contains("license = \"MIT OR Apache-2.0\""),
        "STANDARD.md requires dual SPDX license = \"MIT OR Apache-2.0\""
    );
}
