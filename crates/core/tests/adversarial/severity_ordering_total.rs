//! Adversarial: Severity ordering must rank Critical above Info.

use keyhog_core::Severity;

#[test]
fn severity_ordering_critical_above_info() {
    assert!(Severity::Critical > Severity::Info);
    assert!(Severity::High > Severity::Low);
}
