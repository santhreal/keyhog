//! Migrated from `src/safe_bin.rs` inline tests.
use keyhog_core::resolve_safe_bin;
#[test]
    fn unknown_binary_is_none() {
        // A name that should never exist on any system.
        assert!(resolve_safe_bin("definitely-not-a-real-binary-xyz123").is_none());
    }
