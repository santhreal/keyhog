//! Migrated from `src/spec.rs` — repeated downgrade never increases severity.

use keyhog_core::Severity;

#[test]
fn severity_downgrade_is_monotonic() {
    let mut s = Severity::Critical;
    for _ in 0..10 {
        let next = s.downgrade_one();
        assert!(next <= s, "downgrade must not increase severity: {next:?} > {s:?}");
        s = next;
    }
    assert_eq!(s, Severity::Info);
}
