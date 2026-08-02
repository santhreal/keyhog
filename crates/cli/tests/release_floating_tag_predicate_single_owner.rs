//! Automatic crates.io releases do not move container tags or major-version
//! aliases. Those floating pointers belonged to the retired binary-asset
//! workflow. This test prevents either route or its duplicated newest-version
//! predicate from returning to the crates-only release transaction.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = <repo>/crates/cli
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("crates/cli has a repo root two levels up")
        .to_path_buf()
}

/// A green main push must publish versioned crates without mutating floating release pointers.
#[test]
fn automatic_crates_release_has_no_floating_pointer_routes() {
    let root = repo_root();
    let release = std::fs::read_to_string(root.join(".github/workflows/release.yml"))
        .expect("read .github/workflows/release.yml");

    for obsolete in [
        "is-newest-stable-tag.sh",
        "latest-image",
        "major-tag",
        "advance=false",
        "sort -V | tail",
    ] {
        assert!(
            !release.contains(obsolete),
            "automatic crates.io release must not restore floating-pointer route {obsolete:?}"
        );
    }
}
