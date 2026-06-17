//! Lane 3 - VYRE INTEGRATION coherence regression tests.
//!
//! Keyhog consumes Vyre from crates.io, not from a path mirror and not from any
//! retired repository `vendor/` snapshot. These tests pin the registry contract:
//! all five runtime Vyre crates are exact `=0.6.2` pins, they stay in lockstep,
//! no Vyre dependency carries `path =`, and repository `vendor/` does not exist.

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

fn workspace_deps(cargo: &Value) -> &toml::value::Table {
    cargo
        .get("workspace")
        .and_then(|w| w.get("dependencies"))
        .and_then(|d| d.as_table())
        .expect("[workspace.dependencies] table")
}

const REQUIRED_VERSION: &str = "=0.6.2";

/// (dep key in [workspace.dependencies], published package name).
const VYRE: &[(&str, &str)] = &[
    ("vyre", "vyre"),
    ("vyre_libs", "vyre-libs"),
    ("vyre-driver-wgpu", "vyre-driver-wgpu"),
    ("vyre-driver-cuda", "vyre-driver-cuda"),
    ("vyre-runtime", "vyre-runtime"),
];

fn dep_version_and_path<'a>(key: &str, spec: &'a Value) -> (&'a str, Option<&'a str>) {
    if let Some(version) = spec.as_str() {
        return (version, None);
    }
    let table = spec
        .as_table()
        .unwrap_or_else(|| panic!("vyre dep '{key}' must be a string pin or table"));
    let version = table
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("vyre dep '{key}' has no string version"));
    let path = table.get("path").and_then(|v| v.as_str());
    (version, path)
}

#[test]
fn all_five_vyre_pins_present_exact_registry_and_lockstep() {
    let cargo = root_cargo();
    let deps = workspace_deps(&cargo);

    let mut seen: Vec<(&str, String)> = Vec::new();
    for (key, _pkg) in VYRE {
        let spec = deps
            .get(*key)
            .unwrap_or_else(|| panic!("[workspace.dependencies] missing vyre dep '{key}'"));
        let (version, path) = dep_version_and_path(key, spec);
        assert_eq!(
            version, REQUIRED_VERSION,
            "vyre dep '{key}' must pin exactly {REQUIRED_VERSION}, got {version}"
        );
        assert_eq!(
            path, None,
            "vyre dep '{key}' must be a crates.io registry pin, not path override {path:?}"
        );
        seen.push((*key, version.to_string()));
    }

    assert_eq!(seen.len(), 5, "expected exactly 5 vyre deps");
    let first = seen[0].1.clone();
    for (key, version) in &seen {
        assert_eq!(
            version, &first,
            "vyre pins are not in lockstep: '{key}'={version}, expected {first}"
        );
    }
}

#[test]
fn renamed_vyre_dependencies_resolve_to_the_expected_packages() {
    let cargo = root_cargo();
    let deps = workspace_deps(&cargo);

    for (key, package) in VYRE {
        let spec = deps.get(*key).unwrap();
        let declared_package = spec
            .as_table()
            .and_then(|table| table.get("package"))
            .and_then(|value| value.as_str())
            .unwrap_or(key);
        assert_eq!(
            declared_package, *package,
            "vyre dep '{key}' resolves to package '{declared_package}', expected '{package}'"
        );
    }
}

#[test]
fn repository_vendor_tree_is_absent_and_never_a_build_dependency() {
    let root = repo_root();
    let cargo = root_cargo();
    let exclude: Vec<String> = cargo
        .get("workspace")
        .and_then(|w| w.get("exclude"))
        .and_then(|e| e.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|value| value.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        !root.join("vendor").exists(),
        "repository vendor/ must not exist; keyhog consumes published dependencies from crates.io"
    );
    assert!(
        !exclude.iter().any(|entry| entry.starts_with("vendor/")),
        "root [workspace] exclude must not preserve retired vendor snapshots; got {exclude:?}"
    );

    let mut cargos: Vec<PathBuf> = vec![root.join("Cargo.toml")];
    for entry in std::fs::read_dir(root.join("crates")).expect("read crates/") {
        let path = entry.unwrap().path().join("Cargo.toml");
        if path.is_file() {
            cargos.push(path);
        }
    }

    let mut offending: Vec<String> = Vec::new();
    for cargo_path in cargos {
        let text = std::fs::read_to_string(&cargo_path).unwrap();
        for line in text.lines() {
            let normalized = line.replace('\\', "/");
            if normalized.contains("path")
                && normalized.contains('=')
                && (normalized.contains("vendor/")
                    || normalized.contains("third_party/vyre")
                    || normalized.contains("libs/performance/matching/vyre"))
            {
                offending.push(format!(
                    "{}: {line}",
                    cargo_path
                        .strip_prefix(&root)
                        .unwrap_or(&cargo_path)
                        .display()
                ));
            }
        }
    }
    assert_eq!(
        offending,
        Vec::<String>::new(),
        "Vyre must not resolve through vendor snapshots, third_party mirrors, or the Santh live tree"
    );
}

#[test]
fn vyre_docs_match_registry_pin_contract() {
    let root = repo_root();
    let cases: &[(&str, &str)] = &[
        ("PUBLISHING.md", "third_party/vyre"),
        ("PUBLISHING.md", "path override"),
        ("docs/vyre-usage.md", "third_party/vyre"),
        ("docs/vyre-usage.md", "not in any published"),
        ("docs/CROSS_OS_STATUS.md", "third_party/vyre"),
    ];

    let mut offending: Vec<String> = Vec::new();
    for (rel, needle) in cases {
        let path = root.join(rel);
        if path.is_file() {
            let text = std::fs::read_to_string(&path).unwrap();
            if text.contains(needle) {
                offending.push(format!("{rel}: stale claim contains {needle:?}"));
            }
        }
    }

    assert_eq!(
        offending,
        Vec::<String>::new(),
        "Vyre-facing docs must describe crates.io =0.6.2 pins, not retired path mirrors"
    );
}
