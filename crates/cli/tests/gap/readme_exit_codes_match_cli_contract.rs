//! KH-GAP-095: README exit-code table must match `Cli::after_help` and orchestrator constants.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d
}

#[test]
fn readme_documents_full_exit_code_contract() {
    let readme = std::fs::read_to_string(repo_root().join("README.md")).expect("README.md");
    for needle in [
        "`10` live credentials",
        "`11`",
        "scanner panic",
        "`3` system error",
        "`4` `backend --self-test`",
    ] {
        assert!(
            readme.contains(needle),
            "README exit-code section must document {needle:?}; excerpt missing from README"
        );
    }
}
