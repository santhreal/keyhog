#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Export the pinned workspace Naga version to the crate so disk cache keys
//! invalidate cleanly when the shader frontend changes.

use std::fs;
use std::path::PathBuf;

fn main() {
    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR missing"));
    let workspace_toml = manifest_dir
        .parent()
        .expect("vyre-driver-wgpu must live under the vyre workspace root")
        .join("Cargo.toml");
    let workspace = fs::read_to_string(&workspace_toml)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", workspace_toml.display()));
    let naga_version = workspace
        .lines()
        .find_map(|line| {
            let trimmed = line.trim();
            if !trimmed.starts_with("naga = {") {
                return None;
            }
            let version_start = trimmed.find("version = \"")? + "version = \"".len();
            let rest = &trimmed[version_start..];
            let version_end = rest.find('"')?;
            Some(rest[..version_end].trim_start_matches('=').to_string())
        })
        .unwrap_or_else(|| {
            panic!(
                "failed to locate the workspace naga version in {}",
                workspace_toml.display()
            )
        });

    println!("cargo:rerun-if-changed={}", workspace_toml.display());
    println!("cargo:rustc-env=VYRE_NAGA_VERSION={naga_version}");
}
