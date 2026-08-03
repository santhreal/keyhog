//! Validation contracts for detector-owned positive source selectors.

use keyhog_core::{
    validate_detector, DetectorSpec, PatternSpec, QualityIssue, Severity, SourceAdmissionSpec,
};

fn detector(admission: SourceAdmissionSpec) -> DetectorSpec {
    DetectorSpec {
        id: "source-admission-validation".into(),
        name: "Source admission validation".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: r"ADM_[A-Za-z0-9]{20}".into(),
            required_literals: vec!["ADM_".into()],
            ..Default::default()
        }],
        keywords: vec!["ADM_".into()],
        source_admission: admission,
        ..Default::default()
    }
}

fn errors(admission: SourceAdmissionSpec) -> Vec<String> {
    validate_detector(&detector(admission))
        .into_iter()
        .filter_map(|issue| match issue {
            QualityIssue::Error(message) => Some(message),
            QualityIssue::Warning(_) => None,
        })
        .collect()
}

/// Empty exact source types cannot silently become wildcard selectors.
#[test]
fn empty_source_type_is_rejected() {
    let messages = errors(SourceAdmissionSpec {
        source_types: vec!["  ".into()],
        ..Default::default()
    });
    assert!(messages
        .iter()
        .any(|message| message.contains("source_admission.source_types[0] must not be empty")));
}

/// Duplicate exact source types are authoring errors rather than redundant runtime work.
#[test]
fn duplicate_source_type_is_rejected() {
    let messages = errors(SourceAdmissionSpec {
        source_types: vec!["filesystem".into(), "filesystem".into()],
        ..Default::default()
    });
    assert!(messages
        .iter()
        .any(|message| message.contains("source_admission.source_types[1] is duplicated")));
}

/// Extensions use one normalized representation so matching stays allocation-free.
#[test]
fn noncanonical_extensions_are_rejected() {
    for extension in [".json", "JSON", ""] {
        let messages = errors(SourceAdmissionSpec {
            file_extensions: vec![extension.into()],
            ..Default::default()
        });
        assert!(messages.iter().any(|message| message.contains(
            "source_admission.file_extensions[0] must be lowercase ASCII without a leading dot"
        )));
    }
}

/// Invalid positive path expressions must fail corpus validation before scanner compilation.
#[test]
fn invalid_path_pattern_is_rejected() {
    let messages = errors(SourceAdmissionSpec {
        path_patterns: vec!["(".into()],
        ..Default::default()
    });
    assert!(messages.iter().any(|message| {
        message.contains("source_admission.path_patterns[0] is not a valid regex")
    }));
}

/// Unknown selector fields must fail closed instead of becoming ignored policy text.
#[test]
fn unknown_source_selector_field_fails_toml_decoding() {
    let error = toml::from_str::<SourceAdmissionSpec>("directory = [\"secrets\"]\n")
        .expect_err("unknown source-admission fields must fail");
    assert!(error.to_string().contains("unknown field `directory`"));
}
