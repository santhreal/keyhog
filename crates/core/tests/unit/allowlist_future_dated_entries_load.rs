//! Future-dated allowlist entries must load normally.

use keyhog_core::Allowlist;

#[test]
fn allowlist_future_dated_entries_load() {
    let content = r#"detector:bar ; expires=9999-12-31 ; reason="long-lived ack""#;
    let al = Allowlist::parse(content);
    assert!(al.ignored_detectors.contains("bar"));
}
