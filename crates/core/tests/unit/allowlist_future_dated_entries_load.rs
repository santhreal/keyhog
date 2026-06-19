//! Future-dated allowlist entries must load normally.

use keyhog_core::Allowlist;

#[test]
fn allowlist_future_dated_entries_load() {
    let content = r#"detector:bar ; expires=9999-12-31 ; reason="long-lived ack""#;
    let al =
        keyhog_core::testing::CoreTestApi::allowlist_parse(&keyhog_core::testing::TestApi, content);
    assert!(al.ignored_detectors.contains("bar"));
}

#[test]
fn allowlist_load_with_future_dated_entry_succeeds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(".keyhogignore");
    std::fs::write(
        &path,
        r#"detector:bar ; expires=9999-12-31 ; reason="long-lived ack""#,
    )
    .expect("write allowlist");

    let al = Allowlist::load(&path).expect("future-dated policy must load");
    assert!(al.ignored_detectors.contains("bar"));
}
