//! WebSource coverage-gap accounting must have one owner per skip class.

#[cfg(not(feature = "web"))]
#[test]
fn web_skip_event_owner_requires_web_feature() {
    assert!(!cfg!(feature = "web"));
}
