//! KH-GAP-110: README quickstart shows `--baseline` without `--create-baseline`
//! first — first-time users hit a missing-file error with no Fix: pointer.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d
}

#[test]
fn readme_quickstart_documents_create_baseline_before_baseline_filter() {
    let readme = std::fs::read_to_string(repo_root().join("README.md")).expect("README.md");
    let filter_section = readme
        .split("Filter, format, gate:")
        .nth(1)
        .map(|s| s.as_ref())
        .unwrap_or(readme.as_str());
    assert!(
        filter_section.contains("--create-baseline"),
        "README Filter section must document --create-baseline before --baseline; section={filter_section}"
    );
}
