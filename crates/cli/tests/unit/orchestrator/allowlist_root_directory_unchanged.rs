use keyhog::orchestrator::allowlist_root_for_test;
use std::path::Path;

#[test]
fn allowlist_root_directory_unchanged() {
    let p = Path::new("/tmp/project");
    assert_eq!(allowlist_root_for_test(p), Path::new("/tmp/project"));
}
