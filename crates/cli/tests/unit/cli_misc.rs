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

#[test]
fn filter_inline_suppressions_supports_migrated_directives() {
    for directive in &["keyhog:allow", "gitleaks:allow", "betterleaks:allow"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("with_directive.rs");
        std::fs::write(
            &path,
            format!("let x = 1; // {}\nlet token = \"secret\";\n", directive),
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
        assert!(
            kept.is_empty(),
            "directive '{}' did not suppress finding",
            directive
        );
    }
}

#[test]
fn filter_inline_suppressions_with_detector_suffix() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("with_suffix.rs");
    std::fs::write(
        &path,
        "let x = 1; // keyhog:ignore detector=aws-access-key\nlet token = \"secret\";\n",
    )
    .unwrap();

    // 1. Match with matching detector_id: should be suppressed (kept is empty)
    let m_match = RawMatch {
        detector_id: Arc::from("aws-access-key"),
        detector_name: Arc::from("AWS Access Key"),
        service: Arc::from("aws"),
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
    let kept_match = filter_inline_suppressions(vec![m_match]);
    assert!(kept_match.is_empty(), "matching detector should be suppressed");

    // 2. Match with non-matching detector_id: should NOT be suppressed (kept has 1 finding)
    let m_nonmatch = RawMatch {
        detector_id: Arc::from("stripe-secret-key"),
        detector_name: Arc::from("Stripe Secret Key"),
        service: Arc::from("stripe"),
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
    let kept_nonmatch = filter_inline_suppressions(vec![m_nonmatch]);
    assert_eq!(
        kept_nonmatch.len(),
        1,
        "non-matching detector should not be suppressed"
    );
}
