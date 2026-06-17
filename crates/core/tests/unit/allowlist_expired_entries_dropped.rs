//! Expired allowlist entries must not load.

use keyhog_core::Allowlist;

#[test]
fn allowlist_expired_entries_dropped() {
    let content = "detector:foo ; expires=1970-01-01";
    let al = keyhog_core::testing::allowlist_parse(content);
    assert!(
        !al.ignored_detectors.contains("foo"),
        "expired detector entry must not load"
    );
}

#[test]
fn allowlist_load_with_expired_entry_fails_loudly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(".keyhogignore");
    std::fs::write(&path, "detector:foo ; expires=1970-01-01\n").expect("write allowlist");

    let err = Allowlist::load(&path).expect_err("expired policy must fail load");
    let msg = err.to_string();
    assert!(
        msg.contains(".keyhogignore")
            && msg.contains("expired allowlist policy")
            && msg.contains("line 1")
            && msg.contains("1970-01-01")
            && msg.contains("refusing to scan"),
        "expired allowlist error must be operator-actionable; got: {msg}"
    );
}
