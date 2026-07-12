//! Gap coverage: detector-spec TOML deserialization + quality-gate validation
//! (`crates/core/src/spec.rs`, `spec/validate.rs`, `spec/load.rs`) and the
//! merkle spec-hash digest (`crates/core/src/merkle_spec_hash.rs`).
//!
//! Two intertwined behaviors are exercised here:
//!
//! 1. SPEC TOML SCHEMA. `DetectorSpec` and its nested structs use
//!    `#[serde(deny_unknown_fields)]`, so an unknown / typoed field is a hard
//!    parse error (the schema's typo guard). Required fields (`id`, `name`,
//!    `service`, `severity`, `patterns`) must be present; `#[serde(default)]`
//!    fields (`companions`, `keywords`, `min_confidence`, `tests`, …) are
//!    forward-compatible omissions. `validate_detector` then runs the quality
//!    gate and returns `Vec<QualityIssue>` (Errors block load, Warnings don't).
//!
//! 2. MERKLE SPEC HASH. `compute_spec_hash(&[DetectorSpec]) -> [u8; 32]` builds
//!    a canonical sorted key set over (id, severity, patterns, companions,
//!    sorted keywords) and BLAKE3-hashes it. The digest is ORDER-INVARIANT in
//!    detector order and in keyword order, but CHANGES when any hashed field
//!    changes. Fields NOT in the key set (name, service, verify, group=None vs
//!    absent, client_safe, min_confidence, tests, pattern.description) do NOT
//!    affect the digest.
//!
//! Every expected value below is derived by reading the real source under
//! crates/core/src/spec*.rs and crates/core/src/merkle_spec_hash.rs. No blake3
//! dependency is needed: order-invariance and change-on-edit are proved by
//! comparing `compute_spec_hash` outputs to one another.

use keyhog_core::{
    compute_spec_hash, validate_detector, CompanionSpec, DetectorFile, DetectorSpec, PatternSpec,
    QualityIssue, Severity,
};

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

/// A minimal, quality-gate-CLEAN detector: a literal-prefixed pattern plus a
/// keyword. `validate_detector` should return an empty issue vec for this.
fn clean_detector(id: &str) -> DetectorSpec {
    DetectorSpec {
        kind: Default::default(),
        entropy_floor: Vec::new(),
        id: id.into(),
        name: "Demo".into(),
        service: "demo".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "demo_[A-Z0-9]{8}".into(),
            ..Default::default()
        }],
        companions: Vec::new(),
        verify: None,
        keywords: vec!["demo_".into()],
        min_confidence: None,
        tests: Vec::new(),
        ..Default::default()
    }
}

/// Count Error vs Warning issues in a quality-gate result.
fn counts(issues: &[QualityIssue]) -> (usize, usize) {
    let errors = issues
        .iter()
        .filter(|i| matches!(i, QualityIssue::Error(_)))
        .count();
    let warnings = issues
        .iter()
        .filter(|i| matches!(i, QualityIssue::Warning(_)))
        .count();
    (errors, warnings)
}

fn has_error_containing(issues: &[QualityIssue], needle: &str) -> bool {
    issues
        .iter()
        .any(|i| matches!(i, QualityIssue::Error(m) if m.contains(needle)))
}

fn has_warning_containing(issues: &[QualityIssue], needle: &str) -> bool {
    issues
        .iter()
        .any(|i| matches!(i, QualityIssue::Warning(m) if m.contains(needle)))
}

// A complete, syntactically-valid detector TOML (literal prefix + keyword =>
// clean gate). Tests mutate / append to this body to probe one axis at a time.
const VALID_TOML: &str = r#"
[detector]
id = "demo-key"
name = "Demo Key"
service = "demo"
severity = "high"
keywords = ["demo_"]

[[detector.patterns]]
regex = "demo_[A-Z0-9]{8}"
"#;

// ===========================================================================
// SECTION 1: TOML schema — required fields present, parse succeeds
// ===========================================================================

#[test]
fn valid_toml_parses_into_single_detector() {
    let dets = keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        VALID_TOML,
    )
    .expect("valid TOML must parse");
    assert_eq!(dets.len(), 1, "one [detector] table => one spec");
    let d = &dets[0];
    assert_eq!(d.id, "demo-key");
    assert_eq!(d.name, "Demo Key");
    assert_eq!(d.service, "demo");
    assert_eq!(d.severity, Severity::High);
    assert_eq!(d.patterns.len(), 1);
    assert_eq!(d.patterns[0].regex, "demo_[A-Z0-9]{8}");
    assert_eq!(d.keywords, vec!["demo_".to_string()]);
}

#[test]
fn omitted_default_fields_take_their_defaults() {
    // companions, verify, min_confidence, tests are all `#[serde(default)]` /
    // Option and absent from VALID_TOML.
    let d = &keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        VALID_TOML,
    )
    .unwrap()[0];
    assert!(d.companions.is_empty(), "companions defaults to empty Vec");
    assert!(d.verify.is_none(), "verify defaults to None");
    assert_eq!(d.min_confidence, None, "min_confidence defaults to None");
    assert!(d.tests.is_empty(), "tests defaults to empty Vec");
    // PatternSpec.group / description default to None, client_safe to false.
    assert_eq!(d.patterns[0].group, None);
    assert_eq!(d.patterns[0].description, None);
    assert!(!d.patterns[0].client_safe);
}

#[test]
fn missing_id_field_is_parse_error() {
    let toml = VALID_TOML.replace("id = \"demo-key\"\n", "");
    let err = keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        &toml,
    )
    .expect_err("missing required `id` must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("invalid TOML") || msg.to_lowercase().contains("missing"),
        "error should reference the parse failure, got: {msg}"
    );
}

#[test]
fn missing_name_field_is_parse_error() {
    let toml = VALID_TOML.replace("name = \"Demo Key\"\n", "");
    assert!(
        keyhog_core::testing::CoreTestApi::load_detectors_from_str(
            &keyhog_core::testing::TestApi,
            &toml
        )
        .is_err(),
        "missing required `name` must fail to parse"
    );
}

#[test]
fn missing_service_field_is_parse_error() {
    let toml = VALID_TOML.replace("service = \"demo\"\n", "");
    assert!(
        keyhog_core::testing::CoreTestApi::load_detectors_from_str(
            &keyhog_core::testing::TestApi,
            &toml
        )
        .is_err(),
        "missing required `service` must fail to parse"
    );
}

#[test]
fn missing_severity_field_is_parse_error() {
    let toml = VALID_TOML.replace("severity = \"high\"\n", "");
    assert!(
        keyhog_core::testing::CoreTestApi::load_detectors_from_str(
            &keyhog_core::testing::TestApi,
            &toml
        )
        .is_err(),
        "missing required `severity` must fail to parse"
    );
}

#[test]
fn missing_patterns_is_a_quality_error_not_a_parse_error() {
    // `patterns` IS `#[serde(default)]` (spec.rs), so omitting the
    // [[detector.patterns]] table PARSES cleanly — the recall-safety requirement
    // (a regex detector must carry at least one anchor, or it ships zero recall)
    // is enforced by the quality gate `validate_patterns_present`, NOT at parse
    // time. This lets `kind = "phase2-generic"` keyword detectors omit patterns
    // by design. Pin both halves so the layering can't silently regress.
    let toml = r#"
[detector]
id = "demo-key"
name = "Demo Key"
service = "demo"
severity = "high"
keywords = ["demo_"]
"#;
    let detectors = keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        toml,
    )
    .expect("omitting patterns must PARSE: patterns is #[serde(default)]");

    // Default kind is Regex; a regex detector with no patterns is a hard quality
    // Error at validation time (a dead anchor that would silently ship no recall).
    let issues = keyhog_core::validate_detector(&detectors[0]);
    assert!(
        issues.iter().any(|i| matches!(
            i,
            keyhog_core::QualityIssue::Error(m) if m.contains("no patterns defined")
        )),
        "a regex-kind detector with no patterns must be a 'no patterns defined' quality \
         Error; got {issues:?}"
    );
}

#[test]
fn phase2_generic_may_add_structured_regex_envelopes() {
    let toml = r#"
[detector]
id = "generic-demo"
name = "Generic Demo"
service = "generic"
severity = "medium"
kind = "phase2-generic"
keywords = ["secret"]
entropy_floor = [{ floor = 1.5 }]

[[detector.patterns]]
regex = '"secret"\s*:\s*"([A-Za-z0-9]{12,80})"'
group = 1
"#;
    let detectors = keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        toml,
    )
    .expect("hybrid phase2-generic detector must parse");
    let issues = keyhog_core::validate_detector(&detectors[0]);
    assert!(
        !issues
            .iter()
            .any(|issue| matches!(issue, QualityIssue::Error(_))),
        "structured regex envelopes must coexist with the phase-2 bridge: {issues:?}"
    );
}

// ===========================================================================
// SECTION 2: TOML schema — deny_unknown_fields rejects typos / extras
// ===========================================================================

#[test]
fn unknown_detector_file_top_level_field_rejected() {
    let toml = format!("schema_typo = true\n{VALID_TOML}");
    let err = toml::from_str::<DetectorFile>(&toml)
        .expect_err("unknown top-level DetectorFile field must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("schema_typo") || msg.contains("unknown field"),
        "top-level schema error should name the offending key, got: {msg}"
    );
}

#[test]
fn unknown_top_level_detector_field_rejected() {
    // DetectorSpec has #[serde(deny_unknown_fields)] — a typoed field fails.
    let toml = format!("{VALID_TOML}sevrity = \"low\"\n");
    let err = keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        &toml,
    )
    .expect_err("unknown field must be rejected");
    assert!(
        err.to_string().contains("invalid TOML"),
        "deny_unknown_fields => InvalidToml, got: {err}"
    );
}

#[test]
fn unknown_field_named_in_error_message() {
    let toml = format!("{VALID_TOML}bogus_field = 1\n");
    let err = keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        &toml,
    )
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("bogus_field") || msg.contains("unknown field"),
        "toml error should name the offending key, got: {msg}"
    );
}

#[test]
fn unknown_pattern_field_rejected() {
    // PatternSpec also has deny_unknown_fields.
    let toml = format!("{VALID_TOML}\n[[detector.patterns]]\nregex = \"x\"\nbogus = true\n");
    assert!(
        keyhog_core::testing::CoreTestApi::load_detectors_from_str(
            &keyhog_core::testing::TestApi,
            &toml
        )
        .is_err(),
        "unknown field on PatternSpec must be rejected"
    );
}

#[test]
fn unknown_companion_field_rejected() {
    let toml = format!(
        "{VALID_TOML}\n[[detector.companions]]\nname = \"c\"\nregex = \"FOO_KEY\"\nwithin_lines = 3\nbogus = 1\n"
    );
    assert!(
        keyhog_core::testing::CoreTestApi::load_detectors_from_str(
            &keyhog_core::testing::TestApi,
            &toml
        )
        .is_err(),
        "unknown field on CompanionSpec must be rejected"
    );
}

#[test]
fn unknown_verify_field_rejected() {
    let toml =
        format!("{VALID_TOML}\n[detector.verify]\nurl = \"https://api.demo.test/v1\"\nbogus = 1\n");
    assert!(
        keyhog_core::testing::CoreTestApi::load_detectors_from_str(
            &keyhog_core::testing::TestApi,
            &toml
        )
        .is_err(),
        "unknown field on VerifySpec must be rejected"
    );
}

#[test]
fn unknown_auth_spec_field_rejected() {
    let toml = format!(
        "{VALID_TOML}\n[detector.verify]\nurl = \"https://api.demo.test/v1\"\n[detector.verify.auth]\ntype = \"query\"\nparam = \"key\"\nfield = \"match\"\nschema_typo = true\n"
    );
    let err = keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        &toml,
    )
    .expect_err("unknown AuthSpec field must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("schema_typo") || msg.contains("unknown field"),
        "auth schema error should name the offending key, got: {msg}"
    );
}

#[test]
fn unknown_none_auth_spec_field_rejected() {
    let toml = format!(
        "{VALID_TOML}\n[detector.verify]\nurl = \"https://api.demo.test/v1\"\n[detector.verify.auth]\ntype = \"none\"\nschema_typo = true\n"
    );
    let err = keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        &toml,
    )
    .expect_err("unknown AuthSpec::None field must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("schema_typo") || msg.contains("unknown field"),
        "none-auth schema error should name the offending key, got: {msg}"
    );
}

#[test]
fn unknown_success_field_rejected() {
    let toml = format!(
        "{VALID_TOML}\n[detector.verify]\nurl = \"https://api.demo.test\"\n[detector.verify.success]\nstatus = 200\nbogus = 1\n"
    );
    assert!(
        keyhog_core::testing::CoreTestApi::load_detectors_from_str(
            &keyhog_core::testing::TestApi,
            &toml
        )
        .is_err(),
        "unknown field on SuccessSpec must be rejected"
    );
}

// ===========================================================================
// SECTION 3: TOML schema — type mismatches
// ===========================================================================

#[test]
fn severity_wrong_type_is_parse_error() {
    // severity must deserialize as a kebab-case enum string, not an integer.
    let toml = VALID_TOML.replace("severity = \"high\"", "severity = 3");
    assert!(
        keyhog_core::testing::CoreTestApi::load_detectors_from_str(
            &keyhog_core::testing::TestApi,
            &toml
        )
        .is_err(),
        "integer severity must fail (enum expects a string)"
    );
}

#[test]
fn severity_unknown_variant_is_parse_error() {
    let toml = VALID_TOML.replace("severity = \"high\"", "severity = \"supercritical\"");
    assert!(
        keyhog_core::testing::CoreTestApi::load_detectors_from_str(
            &keyhog_core::testing::TestApi,
            &toml
        )
        .is_err(),
        "unknown severity variant must fail to parse"
    );
}

#[test]
fn id_wrong_type_is_parse_error() {
    // id is a String; an integer literal is a type mismatch.
    let toml = VALID_TOML.replace("id = \"demo-key\"", "id = 42");
    assert!(
        keyhog_core::testing::CoreTestApi::load_detectors_from_str(
            &keyhog_core::testing::TestApi,
            &toml
        )
        .is_err(),
        "numeric id must fail (expects String)"
    );
}

#[test]
fn min_confidence_wrong_type_is_parse_error() {
    // min_confidence is Option<f64>; a string is a type mismatch.
    let toml = format!("{VALID_TOML}min_confidence = \"high\"\n");
    assert!(
        keyhog_core::testing::CoreTestApi::load_detectors_from_str(
            &keyhog_core::testing::TestApi,
            &toml
        )
        .is_err(),
        "string min_confidence must fail (expects f64)"
    );
}

#[test]
fn companion_within_lines_wrong_type_is_parse_error() {
    let toml = format!(
        "{VALID_TOML}\n[[detector.companions]]\nname = \"c\"\nregex = \"FOO_KEY\"\nwithin_lines = \"three\"\n"
    );
    assert!(
        keyhog_core::testing::CoreTestApi::load_detectors_from_str(
            &keyhog_core::testing::TestApi,
            &toml
        )
        .is_err(),
        "string within_lines must fail (expects usize)"
    );
}

#[test]
fn patterns_as_scalar_is_parse_error() {
    // patterns must be an array of tables; a scalar is a type mismatch.
    let toml = r#"
[detector]
id = "x"
name = "X"
service = "x"
severity = "low"
patterns = "demo_[A-Z]{8}"
"#;
    assert!(
        keyhog_core::testing::CoreTestApi::load_detectors_from_str(
            &keyhog_core::testing::TestApi,
            toml
        )
        .is_err(),
        "scalar patterns value must fail (expects array of tables)"
    );
}

// ===========================================================================
// SECTION 4: severity enum — every variant round-trips from its kebab form
// ===========================================================================

#[test]
fn severity_kebab_variants_deserialize() {
    let cases = [
        ("info", Severity::Info),
        ("client-safe", Severity::ClientSafe),
        ("low", Severity::Low),
        ("medium", Severity::Medium),
        ("high", Severity::High),
        ("critical", Severity::Critical),
    ];
    for (wire, expected) in cases {
        let toml = VALID_TOML.replace("severity = \"high\"", &format!("severity = \"{wire}\""));
        let d = &keyhog_core::testing::CoreTestApi::load_detectors_from_str(
            &keyhog_core::testing::TestApi,
            &toml,
        )
        .unwrap_or_else(|e| panic!("severity {wire} should parse: {e}"))[0];
        assert_eq!(d.severity, expected, "wire {wire} => {expected:?}");
    }
}

#[test]
fn severity_client_safe_alias_deserializes() {
    // Severity::ClientSafe carries #[serde(alias = "client_safe")] in addition
    // to its kebab-case rename "client-safe".
    let toml = VALID_TOML.replace("severity = \"high\"", "severity = \"client_safe\"");
    let d = &keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        &toml,
    )
    .expect("client_safe alias must parse")[0];
    assert_eq!(d.severity, Severity::ClientSafe);
}

#[test]
fn severity_as_str_matches_wire_form() {
    // as_str is the canonical wire string; ClientSafe is "client-safe".
    assert_eq!(Severity::Info.to_string(), "info");
    assert_eq!(Severity::ClientSafe.to_string(), "client-safe");
    assert_eq!(Severity::Low.to_string(), "low");
    assert_eq!(Severity::Medium.to_string(), "medium");
    assert_eq!(Severity::High.to_string(), "high");
    assert_eq!(Severity::Critical.to_string(), "critical");
}

#[test]
fn severity_display_uses_canonical_wire_names() {
    for (severity, expected) in [
        (Severity::Info, "info"),
        (Severity::ClientSafe, "client-safe"),
        (Severity::Low, "low"),
        (Severity::Medium, "medium"),
        (Severity::High, "high"),
        (Severity::Critical, "critical"),
    ] {
        assert_eq!(format!("{severity}"), expected);
    }
}

#[test]
fn severity_ordering_is_info_lt_critical() {
    // PartialOrd/Ord derived from declaration order: Info < ClientSafe < Low <
    // Medium < High < Critical.
    assert!(Severity::Info < Severity::ClientSafe);
    assert!(Severity::ClientSafe < Severity::Low);
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
    assert!(Severity::High < Severity::Critical);
}

#[test]
fn severity_downgrade_one_steps_exactly_one_tier() {
    assert_eq!(Severity::Critical.downgrade_one(), Severity::High);
    assert_eq!(Severity::High.downgrade_one(), Severity::Medium);
    assert_eq!(Severity::Medium.downgrade_one(), Severity::Low);
    assert_eq!(Severity::Low.downgrade_one(), Severity::ClientSafe);
    assert_eq!(Severity::ClientSafe.downgrade_one(), Severity::Info);
    // Info is the floor — it stays put.
    assert_eq!(Severity::Info.downgrade_one(), Severity::Info);
}

#[test]
fn severity_default_is_info() {
    assert_eq!(Severity::default(), Severity::Info);
}

// ===========================================================================
// SECTION 5: forward-compat — new optional blocks parse without schema bumps
// ===========================================================================

#[test]
fn detector_with_tests_block_parses() {
    // [[detector.tests]] is modeled (not silently dropped) so deny_unknown_fields
    // covers the whole file. Both subfields are Option<String> defaulting None.
    let toml = format!(
        "{VALID_TOML}\n[[detector.tests]]\ntest_positive = \"demo_ABCD1234\"\ntest_negative = \"nope\"\n"
    );
    let d = &keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        &toml,
    )
    .expect("tests block must parse")[0];
    assert_eq!(d.tests.len(), 1);
    assert_eq!(d.tests[0].test_positive.as_deref(), Some("demo_ABCD1234"));
    assert_eq!(d.tests[0].test_negative.as_deref(), Some("nope"));
}

#[test]
fn detector_test_block_both_fields_optional() {
    let toml = format!("{VALID_TOML}\n[[detector.tests]]\ntest_positive = \"demo_ABCD1234\"\n");
    let d = &keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        &toml,
    )
    .unwrap()[0];
    assert_eq!(d.tests.len(), 1);
    assert_eq!(d.tests[0].test_positive.as_deref(), Some("demo_ABCD1234"));
    assert_eq!(d.tests[0].test_negative, None, "omitted negative => None");
}

#[test]
fn detector_min_confidence_parses_in_unit_range() {
    // min_confidence is a DETECTOR-level field (DetectorSpec), not a per-pattern
    // field — PatternSpec has deny_unknown_fields and only allows
    // regex/description/group/client_safe. It must sit under [detector], before
    // the [[detector.patterns]] array-of-tables table so TOML still scopes it to
    // the detector table.
    let toml = r#"
[detector]
id = "demo-key"
name = "Demo Key"
service = "demo"
severity = "high"
keywords = ["demo_"]
min_confidence = 0.42

[[detector.patterns]]
regex = "demo_[A-Z0-9]{8}"
"#;
    let d = &keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        toml,
    )
    .expect("min_confidence float must parse")[0];
    assert_eq!(d.min_confidence, Some(0.42));
}

#[test]
fn pattern_client_safe_flag_parses() {
    let toml = r#"
[detector]
id = "pk"
name = "Public Key"
service = "stripe"
severity = "medium"
keywords = ["pk_live_"]

[[detector.patterns]]
regex = "pk_live_[A-Za-z0-9]{24}"
client_safe = true
"#;
    let d = &keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        toml,
    )
    .expect("client_safe must parse")[0];
    assert!(
        d.patterns[0].client_safe,
        "client_safe = true must round-trip"
    );
}

#[test]
fn pattern_group_index_parses() {
    let toml = r#"
[detector]
id = "g"
name = "G"
service = "g"
severity = "low"
keywords = ["token"]

[[detector.patterns]]
regex = "token=([A-Za-z0-9]{20})"
group = 1
"#;
    let d = &keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        toml,
    )
    .expect("group index must parse")[0];
    assert_eq!(d.patterns[0].group, Some(1));
}

// ===========================================================================
// SECTION 6: quality gate — clean detector + error/warning conditions
// ===========================================================================

#[test]
fn clean_detector_has_no_issues() {
    let issues = validate_detector(&clean_detector("demo"));
    assert!(
        issues.is_empty(),
        "literal-prefix pattern + keyword should be clean, got: {issues:?}"
    );
}

#[test]
fn no_patterns_is_error() {
    let mut d = clean_detector("nopat");
    d.patterns.clear();
    let issues = validate_detector(&d);
    assert!(
        has_error_containing(&issues, "no patterns defined"),
        "empty patterns => Error 'no patterns defined', got: {issues:?}"
    );
}

#[test]
fn no_keywords_is_warning_not_error() {
    let mut d = clean_detector("nokw");
    d.keywords.clear();
    let issues = validate_detector(&d);
    assert!(
        has_warning_containing(&issues, "no keywords defined"),
        "empty keywords => Warning, got: {issues:?}"
    );
    // The clean literal-prefix pattern itself does not add an Error here.
    let (errors, _) = counts(&issues);
    assert_eq!(errors, 0, "missing keywords is a Warning, never an Error");
}

#[test]
fn pure_character_class_pattern_without_group_is_error() {
    // is_pure_character_class("[A-Za-z0-9]{32}") == true, no capture group =>
    // hard Error "pure character class".
    let mut d = clean_detector("broad");
    d.patterns = vec![PatternSpec {
        regex: "[A-Za-z0-9]{32}".into(),
        ..Default::default()
    }];
    let issues = validate_detector(&d);
    assert!(
        has_error_containing(&issues, "pure character class"),
        "pure char-class without group => Error, got: {issues:?}"
    );
}

#[test]
fn pure_character_class_with_group_is_accepted() {
    // A capture group rescues a pure char class — no "pure character class" Error.
    let mut d = clean_detector("grouped");
    d.patterns = vec![PatternSpec {
        regex: "[A-Za-z0-9]{32}".into(),
        group: Some(0),
        ..Default::default()
    }];
    let issues = validate_detector(&d);
    assert!(
        !has_error_containing(&issues, "pure character class"),
        "group should suppress the pure-char-class Error, got: {issues:?}"
    );
}

#[test]
fn invalid_regex_pattern_is_error() {
    // An unbalanced group fails ast::parse => "does not compile".
    let mut d = clean_detector("badre");
    d.patterns = vec![PatternSpec {
        regex: "demo_(unterminated".into(),
        ..Default::default()
    }];
    let issues = validate_detector(&d);
    assert!(
        has_error_containing(&issues, "does not compile"),
        "uncompilable regex => Error, got: {issues:?}"
    );
}

#[test]
fn oversized_regex_is_error() {
    // MAX_REGEX_PATTERN_LEN = 4096. A 4097-byte literal trips the length guard
    // BEFORE the parser runs.
    let mut d = clean_detector("big");
    let big = "a".repeat(4097);
    d.patterns = vec![PatternSpec {
        regex: big,
        ..Default::default()
    }];
    let issues = validate_detector(&d);
    assert!(
        has_error_containing(&issues, "too large"),
        "regex > 4096 bytes => 'too large' Error, got: {issues:?}"
    );
}

#[test]
fn regex_at_exactly_max_len_is_not_too_large() {
    // Boundary: 4096 bytes is NOT > 4096, so no "too large" Error. (A literal
    // 'a'*4096 compiles fine and is a literal prefix, so the detector is clean.)
    let mut d = clean_detector("edge");
    let exact = "a".repeat(4096);
    d.patterns = vec![PatternSpec {
        regex: exact,
        ..Default::default()
    }];
    let issues = validate_detector(&d);
    assert!(
        !has_error_containing(&issues, "too large"),
        "exactly 4096 bytes must NOT trip the > 4096 guard, got: {issues:?}"
    );
}

#[test]
fn nested_quantifier_redos_pattern_is_error() {
    // (a+)+ — classic catastrophic-backtracking ReDoS — must be flagged.
    let mut d = clean_detector("redos");
    d.patterns = vec![PatternSpec {
        regex: "demo_(a+)+".into(),
        ..Default::default()
    }];
    let issues = validate_detector(&d);
    assert!(
        has_error_containing(&issues, "nested quantifier"),
        "(a+)+ => nested-quantifier Error, got: {issues:?}"
    );
}

#[test]
fn excessive_repeat_bound_is_error() {
    // MAX_REGEX_REPEAT_BOUND = 1000. {1001} exceeds it.
    let mut d = clean_detector("rep");
    d.patterns = vec![PatternSpec {
        regex: "demo_[A-Z]{1001}".into(),
        ..Default::default()
    }];
    let issues = validate_detector(&d);
    assert!(
        has_error_containing(&issues, "excessive counted repetition bound"),
        "{{1001}} > 1000 => Error, got: {issues:?}"
    );
}

#[test]
fn repeat_bound_at_limit_is_clean() {
    // Boundary: {1000} is NOT > 1000, so no excessive-bound Error.
    let mut d = clean_detector("rep1k");
    d.patterns = vec![PatternSpec {
        regex: "demo_[A-Z]{1000}".into(),
        ..Default::default()
    }];
    let issues = validate_detector(&d);
    assert!(
        !has_error_containing(&issues, "excessive counted repetition bound"),
        "{{1000}} == limit must not trip the > 1000 guard, got: {issues:?}"
    );
}

#[test]
fn too_many_alternation_branches_is_error() {
    // MAX_REGEX_ALTERNATION_BRANCHES = 64. 65 distinct branches exceed it.
    let mut d = clean_detector("alt");
    let branches: Vec<String> = (0..65).map(|i| format!("opt{i:03}")).collect();
    d.patterns = vec![PatternSpec {
        regex: format!("demo_(?:{})", branches.join("|")),
        ..Default::default()
    }];
    let issues = validate_detector(&d);
    assert!(
        has_error_containing(&issues, "too many alternation branches"),
        "65 alternation branches > 64 => Error, got: {issues:?}"
    );
}

#[test]
fn pattern_no_prefix_no_group_no_keywords_is_warning() {
    // !has_literal_prefix && !has_group && keywords empty, but NOT a pure char
    // class => the softer "may false-positive" Warning (not an Error).
    let mut d = clean_detector("vague");
    d.keywords.clear();
    d.patterns = vec![PatternSpec {
        regex: r"\d{4}-\d{4}".into(), // starts with \ => no literal prefix
        ..Default::default()
    }];
    let issues = validate_detector(&d);
    assert!(
        has_warning_containing(&issues, "no literal prefix and no capture group"),
        "no-prefix/no-group/no-keyword pattern => Warning, got: {issues:?}"
    );
    assert!(
        !has_error_containing(&issues, "pure character class"),
        "this regex is not a pure char class, so no pure-class Error"
    );
}

// ===========================================================================
// SECTION 7: quality gate — companions
// ===========================================================================

#[test]
fn companion_empty_name_is_error() {
    let mut d = clean_detector("cnm");
    d.companions = vec![CompanionSpec {
        name: "   ".into(),
        regex: "SECRET_KEY".into(),
        within_lines: 3,
        required: false,
    }];
    let issues = validate_detector(&d);
    assert!(
        has_error_containing(&issues, "name must not be empty"),
        "blank companion name => Error, got: {issues:?}"
    );
}

#[test]
fn companion_reserved_oob_name_is_error() {
    // __keyhog_oob_url is reserved for the OOB interpolator.
    let mut d = clean_detector("crsv");
    d.companions = vec![CompanionSpec {
        name: "__keyhog_oob_url".into(),
        regex: "SECRET_KEY_VALUE".into(),
        within_lines: 3,
        required: false,
    }];
    let issues = validate_detector(&d);
    assert!(
        has_error_containing(&issues, "reserved for the OOB interpolator"),
        "reserved companion name => Error, got: {issues:?}"
    );
}

#[test]
fn companion_pure_charclass_tight_radius_is_warning() {
    // Pure char class with within_lines <= TIGHT_COMPANION_RADIUS (5) is a
    // Warning (positional anchoring), not an Error.
    let mut d = clean_detector("ctw");
    d.companions = vec![CompanionSpec {
        name: "appid".into(),
        regex: "[A-Z0-9]{10}".into(),
        within_lines: 5,
        required: false,
    }];
    let issues = validate_detector(&d);
    assert!(
        has_warning_containing(&issues, "positional anchoring"),
        "pure-class companion within radius => Warning, got: {issues:?}"
    );
    assert!(
        !has_error_containing(&issues, "wide search radius"),
        "within_lines==5 is the inclusive boundary, no Error"
    );
}

#[test]
fn companion_pure_charclass_wide_radius_is_error() {
    // within_lines = 6 (> TIGHT_COMPANION_RADIUS 5) for a pure char class =>
    // hard Error.
    let mut d = clean_detector("cwide");
    d.companions = vec![CompanionSpec {
        name: "appid".into(),
        regex: "[A-Z0-9]{10}".into(),
        within_lines: 6,
        required: false,
    }];
    let issues = validate_detector(&d);
    assert!(
        has_error_containing(&issues, "wide search radius"),
        "pure-class companion beyond radius => Error, got: {issues:?}"
    );
}

#[test]
fn companion_broad_regex_no_literal_is_warning() {
    // Not a pure char class, but has no substantial (>=3) literal run =>
    // "too broad" Warning.
    let mut d = clean_detector("cbr");
    d.companions = vec![CompanionSpec {
        name: "c".into(),
        regex: r"\w+=\w+".into(),
        within_lines: 3,
        required: false,
    }];
    let issues = validate_detector(&d);
    assert!(
        has_warning_containing(&issues, "too broad"),
        "companion with no substantial literal => Warning, got: {issues:?}"
    );
}

#[test]
fn companion_with_substantial_literal_is_clean() {
    // "SECRET_KEY" is a >=3-char literal run and not a pure char class — no
    // companion Warning/Error from the gate.
    let mut d = clean_detector("cok");
    d.companions = vec![CompanionSpec {
        name: "sk".into(),
        regex: "SECRET_KEY=[A-Za-z0-9]{20}".into(),
        within_lines: 3,
        required: true,
    }];
    let issues = validate_detector(&d);
    assert!(
        !has_error_containing(&issues, "companion"),
        "anchored companion must not produce an Error, got: {issues:?}"
    );
    assert!(
        !has_warning_containing(&issues, "too broad"),
        "anchored companion must not be flagged 'too broad', got: {issues:?}"
    );
}

// ===========================================================================
// SECTION 8: quality gate — verify spec / URL exfil / OOB consistency
// ===========================================================================

#[test]
fn verify_with_no_url_and_no_steps_is_error() {
    let mut d = clean_detector("vnone");
    d.verify = Some(keyhog_core::VerifySpec::default());
    let issues = validate_detector(&d);
    assert!(
        has_error_containing(&issues, "no steps and no default URL"),
        "verify with neither url nor steps => Error, got: {issues:?}"
    );
}

#[test]
fn verify_http_url_is_warning() {
    // http:// (non-localhost) => "uses HTTP instead of HTTPS" Warning, not Error.
    let mut d = clean_detector("vhttp");
    d.verify = Some(keyhog_core::VerifySpec {
        url: Some("http://api.demo.test/v1".into()),
        ..Default::default()
    });
    let issues = validate_detector(&d);
    assert!(
        has_warning_containing(&issues, "HTTP instead of HTTPS"),
        "plain-http verify URL => Warning, got: {issues:?}"
    );
}

#[test]
fn verify_https_url_is_clean() {
    let mut d = clean_detector("vhttps");
    d.verify = Some(keyhog_core::VerifySpec {
        url: Some("https://api.demo.test/v1".into()),
        ..Default::default()
    });
    let issues = validate_detector(&d);
    assert!(
        !has_warning_containing(&issues, "HTTP instead of HTTPS"),
        "https verify URL must not warn, got: {issues:?}"
    );
    assert!(
        !has_error_containing(&issues, "verify URL"),
        "well-formed https verify URL must not error, got: {issues:?}"
    );
}

#[test]
fn verify_templated_host_without_allowed_domains_is_error() {
    // url host begins with {{...}} and allowed_domains empty => exfil-risk Error.
    let mut d = clean_detector("vexfil");
    d.verify = Some(keyhog_core::VerifySpec {
        url: Some("https://{{companion.host}}/v1".into()),
        ..Default::default()
    });
    let issues = validate_detector(&d);
    assert!(
        has_error_containing(&issues, "attacker-controlled interpolation could exfil"),
        "templated host without allowed_domains => exfil Error, got: {issues:?}"
    );
}

#[test]
fn verify_bare_match_url_is_exfil_error() {
    // url == "{{match}}" exactly is the canonical credential-exfil case.
    let mut d = clean_detector("vmatch");
    d.verify = Some(keyhog_core::VerifySpec {
        url: Some("{{match}}".into()),
        ..Default::default()
    });
    let issues = validate_detector(&d);
    assert!(
        has_error_containing(&issues, "could exfil credentials"),
        "url = {{match}} => exfil Error, got: {issues:?}"
    );
}

#[test]
fn verify_templated_host_with_allowed_domains_is_clean() {
    // allowed_domains set => exfil Error suppressed.
    let mut d = clean_detector("vallow");
    d.verify = Some(keyhog_core::VerifySpec {
        url: Some("https://{{companion.shop}}.myshopify.com/admin".into()),
        allowed_domains: vec!["myshopify.com".into()],
        ..Default::default()
    });
    let issues = validate_detector(&d);
    assert!(
        !has_error_containing(&issues, "could exfil"),
        "allowed_domains should suppress the exfil Error, got: {issues:?}"
    );
}

#[test]
fn verify_single_brace_template_is_error() {
    // {var} (single brace) is not honored by the interpolator => Error.
    let mut d = clean_detector("vsingle");
    d.verify = Some(keyhog_core::VerifySpec {
        url: Some("https://api.demo.test/{token}".into()),
        ..Default::default()
    });
    let issues = validate_detector(&d);
    assert!(
        has_error_containing(&issues, "single-brace"),
        "single-brace template syntax => Error, got: {issues:?}"
    );
}

#[test]
fn verify_oob_without_interactsh_token_is_error() {
    // oob block set but no {{interactsh}} token anywhere => Error.
    let mut d = clean_detector("voob1");
    d.verify = Some(keyhog_core::VerifySpec {
        url: Some("https://api.demo.test/v1".into()),
        oob: Some(keyhog_core::OobSpec {
            protocol: keyhog_core::OobProtocol::Http,
            timeout_secs: None,
            policy: keyhog_core::OobPolicy::default(),
        }),
        ..Default::default()
    });
    let issues = validate_detector(&d);
    assert!(
        has_error_containing(&issues, "verify.oob is set but no"),
        "oob set without interactsh token => Error, got: {issues:?}"
    );
}

#[test]
fn verify_interactsh_token_without_oob_is_error() {
    // interactsh token referenced but no oob block => Error.
    let mut d = clean_detector("voob2");
    d.verify = Some(keyhog_core::VerifySpec {
        url: Some("https://api.demo.test/{{interactsh.url}}".into()),
        ..Default::default()
    });
    let issues = validate_detector(&d);
    // The `\`-continued string literal collapses to a single-spaced line, so
    // the runtime message reads "...verify template but no [detector.verify.oob]
    // block is set...". Match a stable substring of that collapsed form.
    assert!(
        has_error_containing(&issues, "token is referenced in a verify template but no"),
        "interactsh token without oob => Error, got: {issues:?}"
    );
}

#[test]
fn verify_oob_with_interactsh_token_is_consistent() {
    // Both present => no oob-consistency Error (URL is https + has interactsh).
    let mut d = clean_detector("voob3");
    d.verify = Some(keyhog_core::VerifySpec {
        url: Some("https://api.demo.test/{{interactsh.url}}".into()),
        allowed_domains: vec!["demo.test".into()],
        oob: Some(keyhog_core::OobSpec {
            protocol: keyhog_core::OobProtocol::Dns,
            timeout_secs: Some(15),
            policy: keyhog_core::OobPolicy::OobOnly,
        }),
        ..Default::default()
    });
    let issues = validate_detector(&d);
    assert!(
        !has_error_containing(&issues, "verify.oob is set but no"),
        "oob + interactsh token must be consistent, got: {issues:?}"
    );
    assert!(
        !has_error_containing(&issues, "token is referenced in a verify template but no"),
        "oob + interactsh token must be consistent, got: {issues:?}"
    );
}

// ===========================================================================
// SECTION 9: merkle spec-hash — determinism, order-invariance, change-on-edit
// ===========================================================================

#[test]
fn spec_hash_is_deterministic() {
    let dets = vec![clean_detector("a"), clean_detector("b")];
    let h1 = compute_spec_hash(&dets);
    let h2 = compute_spec_hash(&dets);
    assert_eq!(h1, h2, "same input must hash identically");
}

#[test]
fn spec_hash_empty_set_is_stable() {
    // Empty detector set hashes the empty key list — stable, and equal across
    // calls. (BLAKE3 of nothing-fed is a fixed 32-byte digest.)
    let h1 = compute_spec_hash(&[]);
    let h2 = compute_spec_hash(&[]);
    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 32, "digest is always 32 bytes");
}

#[test]
fn spec_hash_invariant_to_detector_order() {
    // keys.sort() before hashing => detector order does not matter.
    let a = clean_detector("alpha");
    let b = clean_detector("bravo");
    let forward = compute_spec_hash(&[a.clone(), b.clone()]);
    let reverse = compute_spec_hash(&[b, a]);
    assert_eq!(
        forward, reverse,
        "detector order must not change the digest"
    );
}

#[test]
fn spec_hash_invariant_to_keyword_order() {
    // kws.sort() per detector => keyword order does not matter.
    let mut d1 = clean_detector("kw");
    d1.keywords = vec!["zzz".into(), "aaa".into(), "mmm".into()];
    let mut d2 = clean_detector("kw");
    d2.keywords = vec!["aaa".into(), "mmm".into(), "zzz".into()];
    assert_eq!(
        compute_spec_hash(&[d1]),
        compute_spec_hash(&[d2]),
        "keyword order must not change the digest"
    );
}

#[test]
fn spec_hash_changes_when_id_changes() {
    let a = clean_detector("id-one");
    let mut b = a.clone();
    b.id = "id-two".into();
    assert_ne!(
        compute_spec_hash(&[a]),
        compute_spec_hash(&[b]),
        "id is in the key set; changing it must change the digest"
    );
}

#[test]
fn spec_hash_changes_when_severity_changes() {
    // sev:{:?} is hashed => High vs Critical differ.
    let mut a = clean_detector("sev");
    a.severity = Severity::High;
    let mut b = a.clone();
    b.severity = Severity::Critical;
    assert_ne!(
        compute_spec_hash(&[a]),
        compute_spec_hash(&[b]),
        "severity is hashed; changing it must change the digest"
    );
}

#[test]
fn spec_hash_changes_when_pattern_regex_changes() {
    let a = clean_detector("pat");
    let mut b = a.clone();
    b.patterns[0].regex = "demo_[a-z0-9]{8}".into();
    assert_ne!(
        compute_spec_hash(&[a]),
        compute_spec_hash(&[b]),
        "pattern regex is hashed; editing it must change the digest"
    );
}

#[test]
fn spec_hash_changes_when_pattern_group_changes() {
    // p:{regex}|g:{group} — None encodes as empty, Some(1) as "1".
    let a = clean_detector("grp");
    let mut b = a.clone();
    b.patterns[0].group = Some(1);
    assert_ne!(
        compute_spec_hash(&[a]),
        compute_spec_hash(&[b]),
        "pattern group is hashed; changing None->Some(1) must change the digest"
    );
}

#[test]
fn spec_hash_changes_when_keyword_added() {
    let a = clean_detector("addkw");
    let mut b = a.clone();
    b.keywords.push("extra_".into());
    assert_ne!(
        compute_spec_hash(&[a]),
        compute_spec_hash(&[b]),
        "adding a keyword changes the hashed key set"
    );
}

#[test]
fn spec_hash_changes_when_companion_added() {
    let a = clean_detector("addc");
    let mut b = a.clone();
    b.companions.push(CompanionSpec {
        name: "sk".into(),
        regex: "SECRET_KEY".into(),
        within_lines: 3,
        required: true,
    });
    assert_ne!(
        compute_spec_hash(&[a]),
        compute_spec_hash(&[b]),
        "adding a companion changes the hashed key set"
    );
}

#[test]
fn spec_hash_changes_when_companion_required_flips() {
    // c:{name}|{regex}|w:{within_lines}|r:{required} — required is hashed.
    let mut a = clean_detector("creq");
    a.companions.push(CompanionSpec {
        name: "sk".into(),
        regex: "SECRET_KEY".into(),
        within_lines: 3,
        required: false,
    });
    let mut b = a.clone();
    b.companions[0].required = true;
    assert_ne!(
        compute_spec_hash(&[a]),
        compute_spec_hash(&[b]),
        "companion.required is hashed; flipping it must change the digest"
    );
}

#[test]
fn spec_hash_changes_when_companion_within_lines_changes() {
    let mut a = clean_detector("cwl");
    a.companions.push(CompanionSpec {
        name: "sk".into(),
        regex: "SECRET_KEY".into(),
        within_lines: 3,
        required: false,
    });
    let mut b = a.clone();
    b.companions[0].within_lines = 4;
    assert_ne!(
        compute_spec_hash(&[a]),
        compute_spec_hash(&[b]),
        "companion.within_lines is hashed; changing it must change the digest"
    );
}

#[test]
fn spec_hash_ignores_name_field() {
    // `name` is NOT part of the hashed key set.
    let a = clean_detector("nm");
    let mut b = a.clone();
    b.name = "Completely Different Display Name".into();
    assert_eq!(
        compute_spec_hash(&[a]),
        compute_spec_hash(&[b]),
        "name is not hashed; changing it must NOT change the digest"
    );
}

#[test]
fn spec_hash_ignores_service_field() {
    // `service` is NOT in the key set (only id, sev, patterns, companions, kw).
    let a = clean_detector("svc");
    let mut b = a.clone();
    b.service = "totally-different-service".into();
    assert_eq!(
        compute_spec_hash(&[a]),
        compute_spec_hash(&[b]),
        "service is not hashed; changing it must NOT change the digest"
    );
}

#[test]
fn spec_hash_binds_min_confidence_field() {
    // MIGRATION 2026-07-07: `min_confidence` is now a HASHED per-detector knob
    // (merkle_spec_hash emits `mc:{id}:{bits}` when non-default). It overrides a
    // per-detector suppression threshold, so changing it changes WHICH findings a
    // scan emits — the exact staleness the merkle cache must notice before it
    // trusts a "skip this file" (Law 10 silent staleness, same class as the
    // severity/`client_safe` keys). So changing it MUST change the digest. The
    // sibling macro test `spec_hash_binds_min_confidence` in
    // `regression_compute_spec_hash.rs` pins the same contract via a different
    // construction; this differential a-vs-b form is the complementary check.
    let a = clean_detector("mc");
    let mut b = a.clone();
    b.min_confidence = Some(0.99);
    assert_ne!(
        compute_spec_hash(&[a]),
        compute_spec_hash(&[b]),
        "min_confidence is a hashed recall/precision knob; changing it MUST change the digest"
    );
}

#[test]
fn spec_hash_ignores_description_but_binds_client_safe() {
    // `description` is cosmetic and NOT in the per-pattern key → changing it must
    // NOT change the digest. `client_safe` IS folded in (`cs:` in merkle_spec_hash)
    // because toggling it downgrades every match of the pattern to ClientSafe under
    // `--hide-client-safe` — a material output change that MUST invalidate the cache.
    let a = clean_detector("pdesc");

    let mut desc_only = a.clone();
    desc_only.patterns[0].description = Some("a fresh description".into());
    assert_eq!(
        compute_spec_hash(std::slice::from_ref(&a)),
        compute_spec_hash(&[desc_only]),
        "pattern description is not hashed; must NOT change the digest"
    );

    let mut toggled = a.clone();
    toggled.patterns[0].client_safe = !a.patterns[0].client_safe;
    assert_ne!(
        compute_spec_hash(std::slice::from_ref(&a)),
        compute_spec_hash(&[toggled]),
        "client_safe is a material output change; toggling it MUST change the digest"
    );
}

#[test]
fn spec_hash_ignores_tests_field() {
    let a = clean_detector("ts");
    let mut b = a.clone();
    b.tests.push(keyhog_core::DetectorTestSpec {
        test_positive: Some("demo_ABCD1234".into()),
        test_negative: None,
    });
    assert_eq!(
        compute_spec_hash(&[a]),
        compute_spec_hash(&[b]),
        "tests are not hashed; adding one must NOT change the digest"
    );
}

#[test]
fn spec_hash_changes_when_detector_added() {
    let one = vec![clean_detector("only")];
    let mut two = one.clone();
    two.push(clean_detector("second"));
    assert_ne!(
        compute_spec_hash(&one),
        compute_spec_hash(&two),
        "adding a whole detector must change the digest"
    );
}

#[test]
fn spec_hash_group_none_differs_from_group_zero() {
    // None encodes "" while Some(0) encodes "0" in the per-pattern key, so the
    // two must hash differently even though group 0 == whole match.
    let mut none_d = clean_detector("g0");
    none_d.patterns[0].group = None;
    let mut zero_d = clean_detector("g0");
    zero_d.patterns[0].group = Some(0);
    assert_ne!(
        compute_spec_hash(&[none_d]),
        compute_spec_hash(&[zero_d]),
        "group None vs Some(0) encode differently => distinct digests"
    );
}

#[test]
fn spec_hash_keyword_namespaced_by_id() {
    // Keywords are emitted as "kw:{id}:{keyword}", so the SAME keyword on two
    // detectors with DIFFERENT ids contributes distinct keys. Moving a keyword
    // from one detector to another (different id) must change the digest.
    let mut a1 = clean_detector("idA");
    a1.keywords = vec!["shared_kw".into()];
    let mut a2 = clean_detector("idB");
    a2.keywords = Vec::new();

    let mut b1 = clean_detector("idA");
    b1.keywords = Vec::new();
    let mut b2 = clean_detector("idB");
    b2.keywords = vec!["shared_kw".into()];

    assert_ne!(
        compute_spec_hash(&[a1, a2]),
        compute_spec_hash(&[b1, b2]),
        "keyword key is namespaced by id; moving it across detectors must change the digest"
    );
}

#[test]
fn spec_hash_pattern_and_companion_entries_are_namespaced_by_detector_id() {
    let mut a1 = clean_detector("idA");
    a1.patterns[0].regex = "SHARED_A_[0-9]+".into();
    a1.companions = vec![CompanionSpec {
        name: "shared-companion".into(),
        regex: "COMPANION_A_[0-9]+".into(),
        within_lines: 3,
        required: false,
    }];
    let mut a2 = clean_detector("idB");
    a2.patterns[0].regex = "SHARED_B_[0-9]+".into();
    a2.companions = vec![CompanionSpec {
        name: "shared-companion".into(),
        regex: "COMPANION_B_[0-9]+".into(),
        within_lines: 3,
        required: false,
    }];

    let mut b1 = clean_detector("idA");
    b1.patterns[0].regex = "SHARED_B_[0-9]+".into();
    b1.companions = vec![CompanionSpec {
        name: "shared-companion".into(),
        regex: "COMPANION_B_[0-9]+".into(),
        within_lines: 3,
        required: false,
    }];
    let mut b2 = clean_detector("idB");
    b2.patterns[0].regex = "SHARED_A_[0-9]+".into();
    b2.companions = vec![CompanionSpec {
        name: "shared-companion".into(),
        regex: "COMPANION_A_[0-9]+".into(),
        within_lines: 3,
        required: false,
    }];

    assert_ne!(
        compute_spec_hash(&[a1, a2]),
        compute_spec_hash(&[b1, b2]),
        "moving patterns or companions across detector ids must invalidate the merkle cache"
    );
}

#[test]
fn spec_hash_two_distinct_detectors_differ_from_duplicate_pair() {
    // Sanity: {a, b} must not collide with {a, a}.
    let a = clean_detector("aa");
    let b = clean_detector("bb");
    let mixed = compute_spec_hash(&[a.clone(), b]);
    let dup = compute_spec_hash(&[a.clone(), a]);
    assert_ne!(mixed, dup, "distinct pair vs duplicate pair must differ");
}

// ---------------------------------------------------------------------------
// Proptest-style loop (no external proptest dep): for a family of mutated
// detectors, the hash is deterministic and order-invariant, and any id change
// yields a different digest.
// ---------------------------------------------------------------------------

#[test]
fn spec_hash_proptest_order_invariance_and_id_sensitivity() {
    for n in 0u32..64 {
        let mut a = clean_detector(&format!("det-{n}"));
        a.severity = match n % 6 {
            0 => Severity::Info,
            1 => Severity::ClientSafe,
            2 => Severity::Low,
            3 => Severity::Medium,
            4 => Severity::High,
            _ => Severity::Critical,
        };
        a.keywords = vec![format!("kw{}", (n * 7) % 13), format!("kw{}", (n * 3) % 11)];
        let mut b = clean_detector(&format!("det-{n}-other"));
        b.severity = a.severity;

        // Determinism.
        assert_eq!(
            compute_spec_hash(&[a.clone()]),
            compute_spec_hash(&[a.clone()])
        );
        // Order invariance over the pair.
        assert_eq!(
            compute_spec_hash(&[a.clone(), b.clone()]),
            compute_spec_hash(&[b.clone(), a.clone()]),
            "order invariance must hold for det-{n}"
        );
        // id sensitivity (a and b differ only by id + keywords baseline).
        assert_ne!(
            compute_spec_hash(&[a]),
            compute_spec_hash(&[b]),
            "different ids must produce different digests for det-{n}"
        );
    }
}

#[test]
fn spec_hash_proptest_keyword_permutation_invariance() {
    let base = ["alpha", "bravo", "charlie", "delta", "echo"];
    let canonical = {
        let mut d = clean_detector("permkw");
        d.keywords = base.iter().map(|s| s.to_string()).collect();
        compute_spec_hash(&[d])
    };
    // A handful of distinct permutations of the same keyword multiset must all
    // hash to `canonical` (kws.sort() canonicalizes before hashing).
    let perms: [[&str; 5]; 4] = [
        ["echo", "delta", "charlie", "bravo", "alpha"],
        ["charlie", "alpha", "echo", "bravo", "delta"],
        ["bravo", "charlie", "delta", "echo", "alpha"],
        ["delta", "echo", "alpha", "charlie", "bravo"],
    ];
    for perm in perms {
        let mut d = clean_detector("permkw");
        d.keywords = perm.iter().map(|s| s.to_string()).collect();
        assert_eq!(
            compute_spec_hash(&[d]),
            canonical,
            "permutation {perm:?} must hash identically to the sorted form"
        );
    }
}

// ---------------------------------------------------------------------------
// Round-trip: TOML -> DetectorSpec -> hash matches hand-built equivalent.
// ---------------------------------------------------------------------------

#[test]
fn spec_hash_toml_roundtrip_matches_hand_built() {
    // The hash must depend only on the hashed fields, so a TOML-loaded detector
    // and a hand-built one with the same id/severity/patterns/companions/keywords
    // (but different name/service/verify) must produce the same digest.
    let toml = r#"
[detector]
id = "rt-key"
name = "Round Trip"
service = "roundtrip-svc"
severity = "medium"
keywords = ["rt_"]

[[detector.patterns]]
regex = "rt_[A-Z0-9]{8}"
"#;
    let loaded = keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        toml,
    )
    .expect("rt toml parses");
    let hand = DetectorSpec {
        kind: Default::default(),
        entropy_floor: Vec::new(),
        id: "rt-key".into(),
        name: "A Different Name".into(),     // not hashed
        service: "different-service".into(), // not hashed
        severity: Severity::Medium,
        patterns: vec![PatternSpec {
            regex: "rt_[A-Z0-9]{8}".into(),
            ..Default::default()
        }],
        companions: Vec::new(),
        verify: None,
        keywords: vec!["rt_".into()],
        // `min_confidence` is now a HASHED knob (migration 2026-07-07), so the
        // hand-built detector must AGREE with the TOML-loaded one, which omits
        // `min_confidence` (=> None). A non-None here would emit an `mc:` key the
        // TOML side lacks and diverge the digest — that divergence is CORRECT
        // (the field is bound), so this test keeps proving equality only across
        // the genuinely non-hashed fields (name/service).
        min_confidence: None,
        tests: Vec::new(),
        ..Default::default()
    };
    assert_eq!(
        compute_spec_hash(&loaded),
        compute_spec_hash(&[hand]),
        "digest must match across differing non-hashed fields"
    );
}
