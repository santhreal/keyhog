//! WebSource coverage-gap accounting must have one owner per skip class.

#[cfg(feature = "web")]
#[test]
fn web_unreadable_and_over_max_skip_events_have_single_helpers() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/web.rs"))
        .expect("web.rs");

    assert!(
        src.contains("fn web_unreadable_error(message: String) -> SourceError")
            && src.contains("fn web_over_max_error(message: String) -> SourceError")
            && src.contains(
                "fn web_skip_error(event: crate::SourceSkipEvent, message: String) -> SourceError"
            ),
        "web.rs must keep typed skip/error helpers for web coverage gaps"
    );
    assert_eq!(
        src.matches("web_skip_error(crate::SourceSkipEvent::Unreadable, message)")
            .count(),
        1,
        "web unreadable coverage gaps must route through web_unreadable_error"
    );
    assert_eq!(
        src.matches("web_skip_error(crate::SourceSkipEvent::OverMaxSize, message)")
            .count(),
        1,
        "web over-size coverage gaps must route through web_over_max_error"
    );
    assert_eq!(
        src.matches("crate::record_skip_event(event)").count(),
        1,
        "web.rs must have one direct skip-counter call, owned by web_skip_error"
    );
    assert_eq!(
        src.matches("crate::SourceSkipEvent::Unreadable").count(),
        1,
        "web unreadable skip variants must appear only in web_unreadable_error"
    );
    assert_eq!(
        src.matches("crate::SourceSkipEvent::OverMaxSize").count(),
        1,
        "web over-size skip variants must appear only in web_over_max_error"
    );
    assert!(
        src.contains("web_skip_error(crate::SourceSkipEvent::Unreadable, message)")
            && src.contains("web_skip_error(crate::SourceSkipEvent::OverMaxSize, message)")
            && src.contains("SourceError::Other(message)"),
        "web skip helpers must preserve the typed skip counter and the returned SourceError row"
    );
}

#[cfg(not(feature = "web"))]
#[test]
fn web_skip_event_owner_requires_web_feature() {
    assert!(!cfg!(feature = "web"));
}
