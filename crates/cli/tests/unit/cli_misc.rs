use keyhog::benchmark::startup_summary;
use keyhog::config::find_config_file;
use keyhog::inline_suppression::filter_inline_suppressions;
use keyhog_core::{MatchLocation, RawMatch, Severity};
use std::sync::Arc;

#[test]
fn startup_summary_includes_detector_count() {
    let summary = startup_summary(42, "cpu");
    assert!(summary.contains("42"));
}

#[test]
fn find_config_file_returns_none_for_empty_temp_dir() {
    let dir = tempfile::tempdir().unwrap();
    assert!(find_config_file(Some(dir.path())).is_none());
}

#[test]
fn filter_inline_suppressions_keeps_non_filesystem_matches() {
    let m = RawMatch {
        detector_id: Arc::from("demo"),
        detector_name: Arc::from("Demo"),
        service: Arc::from("demo"),
        severity: Severity::Low,
        credential: Arc::from("abc"),
        credential_hash: "hash".into(),
        companions: Default::default(),
        location: MatchLocation {
            source: Arc::from("stdin"),
            file_path: None,
            line: None,
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: None,
    };
    let kept = filter_inline_suppressions(vec![m]);
    assert_eq!(kept.len(), 1);
}

#[test]
fn filter_inline_suppressions_drops_directive_marked_line() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("with_ignore.rs");
    std::fs::write(
        &path,
        "let x = 1; // keyhog:ignore\nlet token = \"secret\";\n",
    )
    .unwrap();

    let m = RawMatch {
        detector_id: Arc::from("demo"),
        detector_name: Arc::from("Demo"),
        service: Arc::from("demo"),
        severity: Severity::Low,
        credential: Arc::from("secret"),
        credential_hash: "hash".into(),
        companions: Default::default(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from(path.to_string_lossy().as_ref())),
            line: Some(2),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: None,
    };
    let kept = filter_inline_suppressions(vec![m]);
    assert!(kept.is_empty());
}
