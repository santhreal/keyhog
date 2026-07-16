use keyhog_core::{
    validate_detector, AuthSpec, CompanionSpec, DetectorFile, DetectorSpec, PatternSpec,
    QualityIssue, ScriptEngine, Severity,
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
        ..Default::default()
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
fn spec_loader_and_validator_boundaries_are_explicit() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let spec_source =
        std::fs::read_to_string(manifest_dir.join("src/spec.rs")).expect("read spec root");
    let load_source =
        std::fs::read_to_string(manifest_dir.join("src/spec/load.rs")).expect("read spec loader");
    let validate_source = std::fs::read_to_string(manifest_dir.join("src/spec/validate.rs"))
        .expect("read spec validator");

    assert!(spec_source.contains("pub use load::{"));
    assert!(!spec_source.contains("pub enum SpecError"));
    assert!(!spec_source.contains("pub fn read_detector_toml_file"));
    assert!(!spec_source.contains("pub const DETECTOR_TOML_FILE_BYTES"));

    assert!(load_source.contains("pub enum SpecError"));
    assert!(load_source.contains("pub fn read_detector_toml_file"));
    assert!(load_source.contains("pub const DETECTOR_TOML_FILE_BYTES"));
    assert!(load_source.contains("fn discover_detector_tomls("));
    assert!(load_source.contains("fn parse_detector_files("));
    assert!(load_source.contains("fn assemble_detector_load("));
    assert!(load_source.contains("directory entry under"));
    assert!(load_source.contains("detector TOML {} exceeds"));

    let load_fn = load_source
        .split("pub(crate) fn load_detectors_with_gate(")
        .nth(1)
        .expect("load_detectors_with_gate exists")
        .split("fn discover_detector_tomls(")
        .next()
        .expect("load function boundary");
    assert!(!load_fn.contains("std::fs::read_dir"));
    assert!(!load_fn.contains(".par_iter()"));
    assert!(!load_fn.contains("for outcome in parsed"));

    assert!(validate_source.contains("mod regex_complexity;"));
    assert!(!validate_source.contains("#[path ="));
    assert!(spec_source.contains("pub enum ScriptEngine"));
    assert!(spec_source.contains("engine: ScriptEngine"));
    assert!(!spec_source.contains("Script {\n        engine: String"));
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
