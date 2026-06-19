//! Migrated from `src/safe_bin.rs` inline tests.
use keyhog_core::resolve_safe_bin;
#[test]
fn refuses_relative_path() {
    assert!(resolve_safe_bin("./malicious").is_none());
    assert!(resolve_safe_bin("../../../bin/sh").is_none());
}
