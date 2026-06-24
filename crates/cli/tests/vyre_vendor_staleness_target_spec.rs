//! TARGET-SPEC - Vyre registry pin and no repository vendor tree.
//!
//! Vyre 0.6.3 is published with the megakernel APIs Keyhog imports, so Keyhog's
//! active build must resolve the Vyre runtime fleet from crates.io exact pins.
//! The old repository-level `vendor/` snapshots must not exist.

use std::path::{Path, PathBuf};
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

fn is_generated_path(root: &Path, path: &Path) -> bool {
    let rel = path.strip_prefix(root).unwrap_or(path);
    let text = rel.to_string_lossy().replace('\\', "/");
    [
        ".git",
        "target",
        "docs/book",
        "benchmarks/corpora",
        "benchmarks/results",
        "benchmarks/results-cross-device",
    ]
    .iter()
    .any(|part| text == *part || text.starts_with(&format!("{part}/")))
}

fn collect_cargo_manifests(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
    if is_generated_path(root, dir) {
        return;
    }
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
        let path = entry.expect("dir entry").path();
        if is_generated_path(root, &path) {
            continue;
        }
        if path.is_dir() {
            collect_cargo_manifests(root, &path, out);
        } else if path.file_name().is_some_and(|name| name == "Cargo.toml") {
            out.push(path);
        }
    }
}

fn collect_vendor_dirs(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
    if is_generated_path(root, dir) {
        return;
    }
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
        let path = entry.expect("dir entry").path();
        if is_generated_path(root, &path) {
            continue;
        }
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "vendor") {
                out.push(path);
            } else {
                collect_vendor_dirs(root, &path, out);
            }
        }
    }
}

const VYRE_DEPS: &[&str] = &[
    "vyre",
    "vyre_libs",
    "vyre-driver-wgpu",
    "vyre-driver-cuda",
    "vyre-runtime",
];

#[test]
fn vyre_runtime_fleet_is_published_0_6_3_without_path_overrides() {
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
            version, "=0.6.3",
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

    let mut vendor_dirs = Vec::new();
    collect_vendor_dirs(&root, &root, &mut vendor_dirs);
    assert_eq!(
        vendor_dirs,
        Vec::<PathBuf>::new(),
        "repository vendor/ trees must not exist; keyhog consumes published dependencies from crates.io"
    );
    assert!(
        !excludes.iter().any(|entry| entry.starts_with("vendor/")),
        "root [workspace] exclude must not preserve retired vendor snapshots"
    );

    let mut cargo_files = Vec::new();
    collect_cargo_manifests(&root, &root, &mut cargo_files);
    cargo_files.sort();

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
