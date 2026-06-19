//! Migrated from `src/safe_bin.rs` inline tests.
use keyhog_core::resolve_safe_bin;
#[test]
fn refuses_absolute_path_outside_trusted_dirs() {
    assert!(resolve_safe_bin("/tmp/whatever").is_none());
}
