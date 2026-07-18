//! `cargo binstall keyhog` is wired in crates/cli/Cargo.toml
//! (`[package.metadata.binstall]`) to fetch the exact signed release binaries
//! that .github/workflows/release.yml uploads, verified with the same minisign
//! key the install.sh / install.ps1 flow pins. Three things must never drift
//! apart, or binstall 404s or fails signature verification:
//!  1. the binstall `pkg-url` asset basenames == the release matrix `asset:`
//!     names (for the four prebuilt targets),
//!  2. the binstall signing `pubkey` == the installers' release public key,
//!  3. signatures are fetched as `.minisig` (keyhog's extension), fail-closed.
//! This test locks all three.

use std::collections::BTreeSet;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = <repo>/crates/cli
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("crates/cli has a repo root two levels up")
        .to_path_buf()
}

/// Basename after the final `/` in a binstall `pkg-url = "...<asset>"` line.
fn binstall_asset_names(cargo_toml: &str) -> BTreeSet<String> {
    cargo_toml
        .lines()
        .filter(|l| l.trim_start().starts_with("pkg-url"))
        .filter_map(|l| l.rsplit_once('/'))
        .map(|(_, tail)| tail.trim_end_matches(['"', ' ', '\t']).to_string())
        .collect()
}

/// The `asset: <name>` values from the release build matrix.
fn release_matrix_assets(release_yml: &str) -> BTreeSet<String> {
    release_yml
        .lines()
        .map(str::trim)
        .filter_map(|l| l.strip_prefix("asset:"))
        .map(|v| v.trim().to_string())
        .collect()
}

#[test]
fn binstall_targets_match_the_release_matrix_assets() {
    let root = repo_root();
    let cargo_toml = std::fs::read_to_string(root.join("crates/cli/Cargo.toml"))
        .expect("read crates/cli/Cargo.toml");
    let release = std::fs::read_to_string(root.join(".github/workflows/release.yml"))
        .expect("read .github/workflows/release.yml");

    let binstall = binstall_asset_names(&cargo_toml);
    let matrix = release_matrix_assets(&release);

    // The four prebuilt targets binstall serves.
    let expected: BTreeSet<String> = [
        "keyhog-linux-x86_64",
        "keyhog-macos-x86_64",
        "keyhog-macos-aarch64",
        "keyhog-windows-x86_64.exe",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    assert_eq!(
        binstall, expected,
        "binstall pkg-url asset basenames drifted from the four shipped targets"
    );
    assert!(
        binstall.is_subset(&matrix),
        "every binstall asset must be produced by the release matrix; \
         binstall={binstall:?} release matrix={matrix:?}"
    );
}

#[test]
fn binstall_signing_key_matches_the_installers() {
    let root = repo_root();
    let cargo_toml = std::fs::read_to_string(root.join("crates/cli/Cargo.toml"))
        .expect("read crates/cli/Cargo.toml");
    let install_sh =
        std::fs::read_to_string(root.join("install.sh")).expect("read install.sh");
    let install_ps1 =
        std::fs::read_to_string(root.join("install.ps1")).expect("read install.ps1");

    // The one release public key, as pinned in install.sh.
    let key = install_sh
        .lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("RELEASE_PUBLIC_KEY=")
                .map(|v| v.trim_matches('"').to_string())
        })
        .expect("install.sh pins RELEASE_PUBLIC_KEY");
    assert!(
        key.starts_with("RW") && key.len() > 40,
        "install.sh RELEASE_PUBLIC_KEY is not a minisign key: {key:?}"
    );

    // install.ps1 must pin the identical key.
    assert!(
        install_ps1.contains(&key),
        "install.ps1 release public key drifted from install.sh"
    );

    // The binstall signing block must pin that same key and fail closed on a
    // `.minisig` signature.
    assert!(
        cargo_toml.contains(&format!("pubkey = \"{key}\"")),
        "binstall signing pubkey must equal the installers' release key"
    );
    assert!(
        cargo_toml.contains("algorithm = \"minisign\""),
        "binstall signing must use minisign"
    );
    assert!(
        cargo_toml.contains("file = \"{ url }.minisig\""),
        "binstall must fetch the `.minisig` signature keyhog actually publishes"
    );
}
