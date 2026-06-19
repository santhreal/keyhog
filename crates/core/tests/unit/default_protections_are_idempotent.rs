//! Migrated from `src/hardening.rs` inline tests.
use keyhog_core::apply_protections;
#[test]
fn default_protections_are_idempotent() {
    // Calling twice in quick succession must not error or change
    // outcomes - bits are already set on the second call.
    let first = apply_protections(false);
    let second = apply_protections(false);
    assert_eq!(first.no_core_dumps, second.no_core_dumps);
    assert_eq!(first.no_ptrace, second.no_ptrace);
}
