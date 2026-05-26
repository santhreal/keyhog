//! Migrated from `src/hardening.rs` inline tests.
use keyhog_core::hardening::{apply_default_protections, HardeningReport};
#[test]
fn hardening_report_failures_are_collectible() {
    let mut report = HardeningReport::default();
    report.failures.push("simulated failure".into());
    assert_eq!(report.failures.len(), 1);
}
