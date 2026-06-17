//! TARGET-SPEC - Vyre registry pin and no repository vendor tree.
//!
//! Vyre 0.6.2 is published with the megakernel APIs Keyhog imports, so Keyhog's
//! active build must resolve the Vyre runtime fleet from crates.io exact pins.
//! The old repository-level `vendor/` snapshots must not exist.

use std::path::PathBuf;
use toml::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonicalize repo root from crates/cli")
}

fn root_cargo() -> Value {
    let path = repo_root().join("Cargo.toml");
    let text = std::fs::read_to_string(&path).expect("read root Cargo.toml");
    toml::from_str::<Value>(&text).expect("parse root Cargo.toml")
}

const VYRE_DEPS: &[&str] = &[
    "vyre",
    "vyre_libs",
    "vyre-driver-wgpu",
    "vyre-driver-cuda",
    "vyre-runtime",
];

#[test]
fn vyre_runtime_fleet_is_published_0_6_2_without_path_overrides() {
    let cargo = root_cargo();
    let deps = cargo
        .get("workspace")
        .and_then(|workspace| workspace.get("dependencies"))
        .and_then(|deps| deps.as_table())
        .expect("[workspace.dependencies]");

    for dep in VYRE_DEPS {
        let spec = deps
            .get(*dep)
            .unwrap_or_else(|| panic!("missing workspace dependency {dep}"));
        let (version, path) = if let Some(version) = spec.as_str() {
            (version, None)
        } else {
            let table = spec
                .as_table()
                .unwrap_or_else(|| panic!("{dep} must be string or table"));
            (
                table
                    .get("version")
                    .and_then(|value| value.as_str())
                    .unwrap_or_else(|| panic!("{dep} missing version")),
                table.get("path").and_then(|value| value.as_str()),
            )
        };

        assert_eq!(
            version, "=0.6.2",
            "{dep} must pin the published Vyre release that carries Keyhog's megakernel APIs"
        );
        assert_eq!(
            path, None,
            "{dep} must resolve from crates.io, not from a local source path"
        );
    }
}

#[test]
fn repository_vendor_tree_is_removed_and_not_a_cargo_resolution_path() {
    let root = repo_root();
    let cargo = root_cargo();
    let excludes: Vec<String> = cargo
        .get("workspace")
        .and_then(|workspace| workspace.get("exclude"))
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    assert!(
        !root.join("vendor").exists(),
        "repository vendor/ must not exist; keyhog consumes published dependencies from crates.io"
    );
    assert!(
        !excludes.iter().any(|entry| entry.starts_with("vendor/")),
        "root [workspace] exclude must not preserve retired vendor snapshots"
    );

    let mut cargo_files = vec![root.join("Cargo.toml")];
    for entry in std::fs::read_dir(root.join("crates")).expect("read crates") {
        let path = entry.unwrap().path().join("Cargo.toml");
        if path.is_file() {
            cargo_files.push(path);
        }
    }

    let mut offenders = Vec::new();
    for path in cargo_files {
        let text = std::fs::read_to_string(&path).expect("read Cargo.toml");
        for line in text.lines() {
            let normalized = line.replace('\\', "/");
            if normalized.contains("path")
                && normalized.contains('=')
                && normalized.contains("vendor/")
            {
                offenders.push(format!(
                    "{}: {line}",
                    path.strip_prefix(&root).unwrap_or(&path).display()
                ));
            }
        }
    }

    assert_eq!(
        offenders,
        Vec::<String>::new(),
        "repository vendor/ must not be a Cargo dependency path"
    );
}
