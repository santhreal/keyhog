//! Expired allowlist entries must not load.

use keyhog_core::Allowlist;

#[test]
fn allowlist_expired_entries_dropped() {
    let content = "detector:foo ; expires=1970-01-01";
    let al = Allowlist::parse(content);
    assert!(!al.ignored_detectors.contains("foo"), "expired detector entry must not load");
}
