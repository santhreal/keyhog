use keyhog_core::{
    validate_detector, AnchorSemanticRole, AuthSpec, CaptureSemanticRole, CompanionSpec,
    DetectorFile, DetectorSpec, PatternSpec, QualityIssue, RequiredSemanticEvidence, ScriptEngine,
    SemanticSourceRole, Severity,
};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("keyhog-core-{name}-{unique}"));
    fs::create_dir_all(&path).unwrap();
    path
}

fn valid_detector() -> DetectorSpec {
    DetectorSpec {
        kind: Default::default(),
        entropy_floor: Vec::new(),
        tests: Vec::new(),
        id: "demo-token".into(),
        name: "Demo Token".into(),
        service: "demo".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "demo_[A-Z0-9]{8}".into(),
            description: Some("demo".into()),
            ..Default::default()
        }],
        companions: Vec::new(),
        verify: None,
        keywords: vec!["demo_".into()],
        min_confidence: None,
        ..keyhog_core::testing::named_detector_fixture_defaults()
    }
}

#[test]
fn detector_spec_deserialization() {
    let toml_str = r#"
        [detector]
        id = "test-id"
        name = "Test Name"
        service = "test-service"
        severity = "high"
        ml = { match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }
        keywords = ["KEY", "secret"]

        [[detector.patterns]]
        regex = 'key-[a-z0-9]{32}'
        description = "Test pattern"
    "#;

    let file: DetectorFile = toml::from_str(toml_str).unwrap();
    let spec = file.detector;
    assert_eq!(spec.id, "test-id");
    assert_eq!(spec.severity, Severity::High);
    assert_eq!(spec.patterns.len(), 1);
    assert_eq!(spec.keywords.len(), 2);
}

#[test]
fn detector_semantic_roles_are_typed_and_default_to_abstention() {
    assert_eq!(
        keyhog_core::DETECTOR_CORPUS_SCHEMA_VERSION,
        4,
        "semantic role keys require detector corpus schema 4"
    );
    let declared: DetectorFile = toml::from_str(
        r#"
        [detector]
        id = "semantic-role-test"
        name = "Semantic Role Test"
        service = "test"
        severity = "high"
        ml = { match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }
        capture_role = "assignment-value"
        anchor_role = "exact-key"
        allowed_source_roles = ["structured-assignment-value", "environment-assignment-value"]
        required_evidence = ["checksum", "required-companion"]

        [[detector.patterns]]
        regex = 'demo_[A-Z0-9]{8}'
        "#,
    )
    .expect("known semantic roles must parse");
    assert_eq!(
        declared.detector.capture_role,
        CaptureSemanticRole::AssignmentValue
    );
    assert_eq!(declared.detector.anchor_role, AnchorSemanticRole::ExactKey);
    assert_eq!(
        declared.detector.allowed_source_roles,
        [
            SemanticSourceRole::StructuredAssignmentValue,
            SemanticSourceRole::EnvironmentAssignmentValue,
        ]
    );
    assert_eq!(
        declared.detector.required_evidence,
        [
            RequiredSemanticEvidence::Checksum,
            RequiredSemanticEvidence::RequiredCompanion,
        ]
    );

    let omitted: DetectorFile = toml::from_str(
        r#"
        [detector]
        id = "semantic-role-default"
        name = "Semantic Role Default"
        service = "test"
        severity = "high"
        ml = { match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }

        [[detector.patterns]]
        regex = 'demo_[A-Z0-9]{8}'
        "#,
    )
    .expect("omitted semantic roles must use compatibility defaults");
    assert_eq!(omitted.detector.capture_role, CaptureSemanticRole::Unknown);
    assert_eq!(omitted.detector.anchor_role, AnchorSemanticRole::Unknown);
    assert!(omitted.detector.allowed_source_roles.is_empty());
    assert!(omitted.detector.required_evidence.is_empty());
    let serialized =
        toml::to_string(&omitted.detector).expect("default semantic policy must serialize");
    for field in [
        "capture_role",
        "anchor_role",
        "allowed_source_roles",
        "required_evidence",
    ] {
        assert!(
            !serialized.contains(field),
            "compatibility-default field {field} must not perturb corpus identity"
        );
    }
}

#[test]
fn unknown_detector_semantic_roles_fail_schema_parsing() {
    for declaration in [
        r#"capture_role = "not-a-capture-role""#,
        r#"anchor_role = "not-an-anchor-role""#,
        r#"allowed_source_roles = ["not-a-source-role"]"#,
        r#"required_evidence = ["not-an-evidence-kind"]"#,
    ] {
        let source = format!(
            r#"
            [detector]
            id = "semantic-role-invalid"
            name = "Semantic Role Invalid"
            service = "test"
            severity = "high"
            ml = {{ match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }}
            {declaration}

            [[detector.patterns]]
            regex = 'demo_[A-Z0-9]{{8}}'
            "#
        );
        let error = toml::from_str::<DetectorFile>(&source)
            .expect_err("unknown semantic role must fail closed");
        assert!(
            error.to_string().contains("unknown variant"),
            "unexpected error for {declaration}: {error}"
        );
    }
}

#[test]
fn detector_semantic_policy_rejects_ambiguous_or_duplicate_declarations() {
    let mut detector = valid_detector();
    detector.allowed_source_roles = vec![
        SemanticSourceRole::Unknown,
        SemanticSourceRole::StringLiteral,
        SemanticSourceRole::StringLiteral,
    ];
    detector.required_evidence = vec![
        RequiredSemanticEvidence::Checksum,
        RequiredSemanticEvidence::Checksum,
    ];

    let issues = validate_detector(&detector);
    assert!(issues.iter().any(
        |issue| matches!(issue, QualityIssue::Error(message) if message.contains("cannot combine `unknown`"))
    ));
    assert!(issues.iter().any(
        |issue| matches!(issue, QualityIssue::Error(message) if message.contains("duplicate role"))
    ));
    assert!(issues.iter().any(
        |issue| matches!(issue, QualityIssue::Error(message) if message.contains("duplicate requirement"))
    ));
}

#[test]
fn script_auth_engine_is_typed_but_toml_stays_string_compatible() {
    let toml_str = r#"
        [detector]
        id = "script-auth"
        name = "Script Auth"
        service = "demo"
        severity = "high"
        ml = { match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }
        keywords = ["demo_"]

        [[detector.patterns]]
        regex = 'demo_[A-Z0-9]{8}'

        [detector.verify]
        url = "https://example.com/verify"

        [detector.verify.auth]
        type = "script"
        engine = "python3"
        code = "print('STATUS: LIVE')"
    "#;

    let file: DetectorFile = toml::from_str(toml_str).unwrap();
    let auth = file.detector.verify.unwrap().auth.unwrap();
    assert!(matches!(
        auth,
        AuthSpec::Script {
            engine: ScriptEngine::Python3,
            ..
        }
    ));
}

#[test]
fn unknown_script_auth_engine_preserves_wire_value_for_verifier_rejection() {
    let engine = ScriptEngine::from("notreal");
    assert_eq!(engine.as_str(), "notreal");
    let value = toml::Value::try_from(&engine).unwrap();
    assert_eq!(value.as_str(), Some("notreal"));
}

#[test]
fn pattern_spec_with_group() {
    let pattern = PatternSpec {
        regex: "API_KEY=(.*)".to_string(),
        description: Some("capture group test".to_string()),
        group: Some(1),
        required_literals: Vec::new(),
        ..Default::default()
    };
    assert_eq!(pattern.group, Some(1));
}

#[test]
fn detector_spec_no_longer_derives_default() {
    let detector = valid_detector();
    assert!(validate_detector(&detector).is_empty());
}

#[test]
fn companion_regexes_are_validated() {
    // within_lines = 12 (> TIGHT_COMPANION_RADIUS = 5) - pure character
    // class with this much radius needs a textual anchor.
    let mut detector = valid_detector();
    detector.companions.push(CompanionSpec {
        name: "secondary".into(),
        regex: "[A-Za-z0-9+/=]{40,}".into(),
        within_lines: 12,
        required: false,
        ..Default::default()
    });
    let issues = validate_detector(&detector);
    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("pure character class")
    )));
}

#[test]
fn malformed_toml_files_fail_closed_instead_of_returning_partial_corpus() {
    let dir = temp_dir("detector-load");
    fs::write(
        dir.join("valid.toml"),
        r#"
        [detector]
        id = "demo-token"
        name = "Demo Token"
        service = "demo"
        severity = "high"
        ml = { match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }
        keywords = ["demo_"]

        [[detector.patterns]]
        regex = "demo_[A-Z0-9]{8}"
        "#,
    )
    .unwrap();
    fs::write(dir.join("broken.toml"), "[detector").unwrap();

    let error = keyhog_core::testing::CoreTestApi::load_detectors_with_gate(
        &keyhog_core::testing::TestApi,
        &dir,
        true,
    )
    .expect_err("enforced detector load must reject a partial corpus");
    let message = error.to_string();
    assert!(
        message.contains("pass the quality gate")
            && message.contains("complete detector corpus")
            && message.contains("broken.toml")
            && message.contains("Fix: repair the named TOML"),
        "malformed detector error must be operator-visible; got {message}"
    );
}

#[test]
fn oversized_toml_files_fail_closed_instead_of_allocating_unboundedly() {
    let dir = temp_dir("detector-load-oversized");
    let path = dir.join("oversized.toml");
    let file = std::fs::File::create(&path).expect("create oversized detector");
    file.set_len(keyhog_core::DETECTOR_TOML_FILE_BYTES + 1)
        .expect("make oversized sparse detector TOML");

    let error = keyhog_core::testing::CoreTestApi::load_detectors_with_gate(
        &keyhog_core::testing::TestApi,
        &dir,
        true,
    )
    .expect_err("oversized detector TOML must reject the corpus");
    let message = error.to_string();
    assert!(
        message.contains("exceeds")
            && message.contains("complete detector corpus")
            && message.contains(&path.display().to_string()),
        "oversized detector TOML must be an operator-visible corpus failure; got {message}"
    );
}

#[test]
fn no_detector_uses_singular_companion_table() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    // The in-crate `detectors` is a Unix symlink to `../../detectors`. On
    // Windows checkouts without core.symlinks the symlink lands as a plain
    // file holding the link target, so prefer the workspace-root path and
    // fall back to the in-crate path. Mirrors `crates/core/build.rs`.
    let manifest_path = std::path::Path::new(&manifest_dir);
    let workspace_detectors = manifest_path
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("detectors"))
        .filter(|p| p.is_dir());
    let in_crate = manifest_path.join("detectors");
    let detectors_dir = workspace_detectors
        .or_else(|| {
            if in_crate.is_dir() {
                Some(in_crate.clone())
            } else {
                None
            }
        })
        .unwrap_or(in_crate);

    let mut violations = Vec::new();
    for entry in std::fs::read_dir(&detectors_dir).expect("failed to read detectors dir") {
        let entry = entry.expect("failed to read dir entry");
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "toml") {
            let contents = std::fs::read_to_string(&path).expect("failed to read detector file");
            if contents.contains("[detector.companion]") {
                violations.push(path.file_name().unwrap().to_string_lossy().to_string());
            }
        }
    }

    assert!(
        violations.is_empty(),
        "Found {} detector(s) using deprecated singular [detector.companion] instead of [[detector.companions]]: {}. Fix: rename to [[detector.companions]] and ensure field names match the spec",
        violations.len(),
        violations.join(", ")
    );
}
