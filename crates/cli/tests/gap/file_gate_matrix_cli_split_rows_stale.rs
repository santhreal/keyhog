//! KH-GAP-134: FILE_GATE_MATRIX CLI rows stale after R3.2 args/orchestrator split.

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
    let matrix = std::fs::read_to_string(repo.join("tests/FILE_GATE_MATRIX.toml"))
        .expect("FILE_GATE_MATRIX.toml");
    let src = walk_rs(&repo.join("crates/cli/src"), &repo);
    for path in &src {
        assert!(
            matrix.contains(&format!("path = \"{path}\"")),
            "FILE_GATE_MATRIX must include {path} after R3.2 split"
        );
    }
    assert!(
        !matrix.contains("path = \"crates/cli/src/orchestrator.rs\""),
        "stale orchestrator.rs row must be removed from matrix"
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
