use super::resolve_root_for_control;
use std::path::PathBuf;

#[test]
fn deleted_absolute_path_falls_back_without_canonicalize() {
    let missing = PathBuf::from("/tmp/keyhog-guard-missing-root-does-not-exist-xyz");
    assert!(!missing.exists());
    let resolved = resolve_root_for_control(&missing).expect("resolve deleted root");
    assert_eq!(resolved, missing.to_string_lossy());
}
