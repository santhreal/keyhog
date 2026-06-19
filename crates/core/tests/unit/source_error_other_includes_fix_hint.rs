//! Migrated from `src/source.rs` inline tests.
use keyhog_core::SourceError;
#[test]
fn source_error_other_includes_fix_hint() {
    let err = SourceError::Other("missing path".into());
    assert!(err.to_string().contains("Fix:"));
}
