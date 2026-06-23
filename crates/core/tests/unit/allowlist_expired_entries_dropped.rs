//! Expired allowlist entries must not load.

use keyhog_core::Allowlist;

#[test]
fn allowlist_expired_entries_dropped() {
    let content = "detector:foo ; expires=1970-01-01";
    let al =
        keyhog_core::testing::CoreTestApi::allowlist_parse(&keyhog_core::testing::TestApi, content);
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

    let err = Allowlist::load_with_metadata_policy(&path, false, false, None)
        .expect_err("expired policy must fail load");
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

#[test]
fn allowlist_malformed_expires_is_not_loaded() {
    let content = "detector:foo ; expires=2026-6-2";
    let al =
        keyhog_core::testing::CoreTestApi::allowlist_parse(&keyhog_core::testing::TestApi, content);
    assert!(
        !al.ignored_detectors.contains("foo"),
        "malformed expires metadata must not create an active suppression"
    );
}

#[test]
fn allowlist_load_with_malformed_expires_fails_loudly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(".keyhogignore");
    std::fs::write(&path, "detector:foo ; expires=2026-6-2\n").expect("write allowlist");

    let err = Allowlist::load_with_metadata_policy(&path, false, false, None)
        .expect_err("malformed expires metadata must fail load");
    let msg = err.to_string();
    assert!(
        msg.contains(".keyhogignore")
            && msg.contains("violates allowlist governance")
            && msg.contains("line 1")
            && msg.contains("expires")
            && msg.contains("YYYY-MM-DD")
            && msg.contains("refusing to scan"),
        "malformed expires error must be operator-actionable; got: {msg}"
    );
}
