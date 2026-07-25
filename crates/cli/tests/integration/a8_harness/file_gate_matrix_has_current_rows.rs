//! FILE_GATE_MATRIX ownership contract for the current production module inventory.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
#[test]
fn file_gate_matrix_has_current_rows() {
    let repo = repo_root();
    let raw = std::fs::read_to_string(repo.join("tests/FILE_GATE_MATRIX.toml"))
        .expect("FILE_GATE_MATRIX.toml readable");
    let matrix: toml::Value = toml::from_str(&raw).expect("FILE_GATE_MATRIX.toml parses");
    let rows = matrix
        .get("module")
        .and_then(toml::Value::as_array)
        .expect("matrix declares module rows");
    let listed: BTreeSet<String> = rows
        .iter()
        .map(|row| {
            row.get("path")
                .and_then(toml::Value::as_str)
                .expect("every [[module]] row declares a string path")
                .to_owned()
        })
        .collect();
    assert_eq!(
        listed.len(),
        rows.len(),
        "FILE_GATE_MATRIX module paths must be unique"
    );

    let owned: BTreeSet<String> = [
        "crates/cli/src",
        "crates/core/src",
        "crates/scanner/src",
        "crates/sources/src",
        "crates/verifier/src",
    ]
    .into_iter()
    .flat_map(|root| walk_rs(&repo.join(root), &repo))
    .collect();
    let missing: Vec<&String> = owned.difference(&listed).collect();
    let stale: Vec<&String> = listed.difference(&owned).collect();
    assert!(
        missing.is_empty() && stale.is_empty(),
        "FILE_GATE_MATRIX ownership differs from the live production filesystem; missing={missing:?}, stale={stale:?}"
    );
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn walk_rs(root: &Path, repo: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let entries = std::fs::read_dir(root)
        .unwrap_or_else(|error| panic!("read source directory {}: {error}", root.display()));
    for entry in entries {
        let entry = entry
            .unwrap_or_else(|error| panic!("read source entry under {}: {error}", root.display()));
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk_rs(&path, repo));
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(
                path.strip_prefix(repo)
                    .unwrap_or_else(|error| {
                        panic!("strip repo root from {}: {error}", path.display())
                    })
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
    out
}
