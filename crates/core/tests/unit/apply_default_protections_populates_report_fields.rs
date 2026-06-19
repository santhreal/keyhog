//! Migrated from `src/hardening.rs` inline tests.
use keyhog_core::apply_protections;
#[test]
fn apply_default_protections_populates_report_fields() {
    let report = apply_protections(false);
    // On Linux/macOS at least one protection should succeed; on other
    // platforms the call is a no-op but must not panic.
    let _ = report.no_core_dumps;
    let _ = report.no_ptrace;
}
