//! Migrated from `src/spec.rs` - severity downgrade steps one tier.

use keyhog_core::Severity;

#[test]
fn severity_downgrade_walks_one_step() {
    assert_eq!(Severity::Critical.downgrade_one(), Severity::High);
    assert_eq!(Severity::High.downgrade_one(), Severity::Medium);
    assert_eq!(Severity::Medium.downgrade_one(), Severity::Low);
    assert_eq!(Severity::Low.downgrade_one(), Severity::ClientSafe);
    assert_eq!(Severity::ClientSafe.downgrade_one(), Severity::Info);
}
