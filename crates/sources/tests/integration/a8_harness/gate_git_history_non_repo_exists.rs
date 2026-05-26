//! LR2-A8 harness integration: git history gate on disk

#[test]
fn git_history_gate_present() {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/gate/git_history_non_repo_yields_no_chunks.rs");
    assert!(p.is_file());
}
