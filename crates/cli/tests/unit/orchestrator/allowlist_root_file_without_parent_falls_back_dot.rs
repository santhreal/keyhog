use keyhog::orchestrator::allowlist_root_for_test;
use std::path::Path;

#[test]
fn allowlist_root_file_without_parent_falls_back_dot() {
    let p = Path::new("file.rs");
    assert_eq!(allowlist_root_for_test(p), Path::new("."));
}
