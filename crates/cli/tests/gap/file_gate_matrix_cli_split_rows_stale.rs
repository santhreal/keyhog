//! KH-GAP-134: FILE_GATE_MATRIX CLI rows stale after R3.2 args/orchestrator split.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d
}

#[test]
fn file_gate_matrix_lists_every_cli_src_module() {
    let repo = repo_root();
    let raw = std::fs::read_to_string(repo.join("tests/FILE_GATE_MATRIX.toml"))
        .expect("FILE_GATE_MATRIX.toml");
    let matrix: toml::Value = toml::from_str(&raw).expect("FILE_GATE_MATRIX.toml parses");
    let listed: BTreeSet<String> = matrix
        .get("module")
        .and_then(toml::Value::as_array)
        .expect("matrix declares module rows")
        .iter()
        .filter_map(|row| row.get("path").and_then(toml::Value::as_str))
        .filter(|path| path.starts_with("crates/cli/src/"))
        .map(str::to_owned)
        .collect();
    let owned: BTreeSet<String> = walk_rs(&repo.join("crates/cli/src"), &repo)
        .into_iter()
        .collect();

    // Regression: compare real ownership in both directions. A hardcoded count
    // or one-off stale filename check can pass while new split modules are absent.
    let missing: Vec<&String> = owned.difference(&listed).collect();
    let stale: Vec<&String> = listed.difference(&owned).collect();
    assert!(
        missing.is_empty() && stale.is_empty(),
        "FILE_GATE_MATRIX CLI ownership differs from the live filesystem; missing={missing:?}, stale={stale:?}"
    );
}

fn walk_rs(root: &Path, repo: &Path) -> Vec<String> {
    fn rec(base: &Path, repo: &Path, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(base).expect("read_dir") {
            let entry = entry.expect("entry");
            let path = entry.path();
            if path.is_dir() {
                rec(&path, repo, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let rel = path
                    .strip_prefix(repo)
                    .expect("cli src path under repo root")
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push(rel);
            }
        }
    }
    let mut out = Vec::new();
    rec(root, repo, &mut out);
    out.sort();
    out
}
