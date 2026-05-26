//! Migrated from `src/hardening.rs` inline tests.
use keyhog_core::hardening::{apply_default_protections, HardeningReport};
#[test]
    fn default_protections_are_idempotent() {
        // Calling twice in quick succession must not error or change
        // outcomes — bits are already set on the second call.
        let first = apply_default_protections();
        let second = apply_default_protections();
        assert_eq!(first.no_core_dumps, second.no_core_dumps);
        assert_eq!(first.no_ptrace, second.no_ptrace);
    }
