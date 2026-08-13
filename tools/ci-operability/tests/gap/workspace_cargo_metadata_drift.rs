//! KH-GAP-133: Cargo.toml contract (authors identity + license SPDX).

use super::support::repo_root;

#[test]
fn workspace_package_metadata_matches_standard_contract() {
    let toml =
        std::fs::read_to_string(repo_root().join("Cargo.toml")).expect("workspace Cargo.toml");
    assert!(
        toml.contains("authors = [\"Santh <64453045+santhreal@users.noreply.github.com>\"]"),
        "Binding identity (AGENTS.md): Santh <64453045+santhreal@users.noreply.github.com>"
    );
    assert!(
        toml.contains("license = \"MIT OR Apache-2.0\""),
        "Binding identity (AGENTS.md): dual SPDX license = \"MIT OR Apache-2.0\""
    );
}
