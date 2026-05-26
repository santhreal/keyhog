//! Migrated from `src/spec.rs` — Info severity cannot downgrade further.

use keyhog_core::Severity;

#[test]
fn severity_downgrade_floors_at_info() {
    assert_eq!(Severity::Info.downgrade_one(), Severity::Info);
}
