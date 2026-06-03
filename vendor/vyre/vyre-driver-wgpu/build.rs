//! Export the resolved Naga version to the crate so disk cache keys
//! invalidate cleanly when the shader frontend changes. Reads from
//! this crate's own Cargo.toml under [package.metadata.vyre], because
//! the workspace root is not available inside the crates.io tarball.

use std::fs;
use std::path::PathBuf;

fn fail(message: impl std::fmt::Display) -> ! {
    eprintln!("Fix: {message}");
    std::process::exit(1);
}

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| {
        fail("CARGO_MANIFEST_DIR missing; restore this invariant before continuing.")
    }));
    let manifest_path = manifest_dir.join("Cargo.toml");
    let manifest = fs::read_to_string(&manifest_path).unwrap_or_else(|error| {
        fail(format!("failed to read {}: {error}", manifest_path.display()))
    });
    let naga_version = manifest
        .lines()
        .find_map(|line| {
            let trimmed = line.trim();
            let key = "naga_version = \"";
            if !trimmed.starts_with(key) {
                return None;
            }
            let rest = &trimmed[key.len()..];
            let end = rest.find('"')?;
            Some(rest[..end].to_string())
        })
        .unwrap_or_else(|| {
            fail(format!(
                "failed to locate `naga_version = \"...\"` under [package.metadata.vyre] in {}",
                manifest_path.display()
            ))
        });

    println!("cargo:rerun-if-changed={}", manifest_path.display());
    println!("cargo:rustc-env=VYRE_NAGA_VERSION={naga_version}");
}
