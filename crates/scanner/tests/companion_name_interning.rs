use keyhog_core::{
    Chunk, ChunkMetadata, CompanionSpec, DedupScope, DetectorSpec, PatternSpec, Severity,
    VerificationResult, VerifiedFinding,
};
use keyhog_scanner::CompiledScanner;
use std::sync::Arc;

const ACCESS_KEY_ONE: &str = "AKIAQYLPMN5HFIQR7XYA";
const ACCESS_KEY_TWO: &str = "AKIAZYXWVUTSRQPONMLK";
const SECRET_ONE: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLExYz";
const SECRET_TWO: &str = "pL8mN2qR4sT6vW0xY1zA3bC5dE7fG9hJ2kL4mN6p";
const SESSION_ONE: &str =
    "IQoJb3JpZ2luX2VjEJr//////////wEaCXVzLWVhc3QtMSJGMEQCIEa1Bc2Def3Gh4Ij5Kl6Mn7Op8Qr9St0";
const SESSION_TWO: &str =
    "IQoJb3JpZ2luX2VjEJr//////////wEaCXVzLWVhc3QtMSJGMEQCIFb2Cd3Efg4Hi5Jk6Lm7No8Pq9Rs0Tu1";

fn scanner_with_companion(required: bool) -> CompiledScanner {
    let detector = DetectorSpec {
        id: "aws-companion-allocation-contract".into(),
        name: "AWS Companion Allocation Contract".into(),
        service: "aws".into(),
        severity: Severity::Critical,
        patterns: vec![PatternSpec {
            regex: r"(?-i)(AKIA|ASIA)[0-9A-Z]{16}\b".into(),
            ..Default::default()
        }],
        companions: vec![
            CompanionSpec {
                name: "secret_key".into(),
                regex: r#"(?i:AWS_SECRET_ACCESS_KEY)[=:\s\"']+([0-9a-zA-Z/+=]{40})"#.into(),
                within_lines: 2,
                required,
                ..Default::default()
            },
            CompanionSpec {
                name: "session_token".into(),
                regex: r#"(?i:AWS_SESSION_TOKEN)[=:\s\"']+([0-9a-zA-Z/+=]{80,})"#.into(),
                within_lines: 2,
                required: false,
                ..Default::default()
            },
        ],
        keywords: vec!["AKIA".into(), "ASIA".into()],
        min_confidence: Some(0.0),
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };
    CompiledScanner::compile(vec![detector]).expect("companion contract detector must compile")
}

fn scanner_without_companions() -> CompiledScanner {
    let detector = DetectorSpec {
        id: "no-companion-allocation-contract".into(),
        name: "No Companion Allocation Contract".into(),
        service: "aws".into(),
        severity: Severity::Critical,
        patterns: vec![PatternSpec {
            regex: r"(?-i)(AKIA|ASIA)[0-9A-Z]{16}\b".into(),
            ..Default::default()
        }],
        companions: Vec::new(),
        keywords: vec!["AKIA".into(), "ASIA".into()],
        min_confidence: Some(0.0),
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };
    CompiledScanner::compile(vec![detector]).expect("no-companion detector must compile")
}

fn chunk(access_key: &str, companions: Option<(&str, &str)>) -> Chunk {
    let data = match companions {
        Some((secret, session)) => format!(
            "AWS_ACCESS_KEY_ID={access_key}\nAWS_SECRET_ACCESS_KEY={secret}\nAWS_SESSION_TOKEN={session}"
        ),
        None => format!("AWS_ACCESS_KEY_ID={access_key}"),
    };
    Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            source_type: "unit".into(),
            path: Some("production.env".into()),
            ..Default::default()
        },
    }
}

fn only_match(scanner: &CompiledScanner, chunk: &Chunk) -> keyhog_core::RawMatch {
    let mut matches = scanner
        .scan(chunk)
        .expect("companion fixture scan must succeed");
    assert_eq!(matches.len(), 1, "fixture must produce exactly one finding");
    matches.pop().expect("one finding was asserted")
}

/// Regression KH-1230: AWS-style companion extraction must retain its exact
/// public key/value object rather than exposing an interned-name implementation detail.
#[test]
fn aws_style_companion_value_and_serialized_shape_are_unchanged() {
    let finding = only_match(
        &scanner_with_companion(false),
        &chunk(ACCESS_KEY_ONE, Some((SECRET_ONE, SESSION_ONE))),
    );

    assert_eq!(finding.companions.len(), 2);
    assert_eq!(
        finding.companions.get("secret_key").map(String::as_str),
        Some(SECRET_ONE)
    );
    assert_eq!(
        finding.companions.get("session_token").map(String::as_str),
        Some(SESSION_ONE)
    );

    let mut deduped = keyhog_core::dedup_matches(vec![finding], &DedupScope::None);
    let report = VerifiedFinding::from_deduped(
        deduped.pop().expect("one report group"),
        Severity::Critical,
        VerificationResult::Skipped,
        std::collections::HashMap::new(),
    );
    let serialized = serde_json::to_value(&report).expect("report finding must serialize");
    assert_eq!(
        serialized.get("companions_redacted"),
        Some(&serde_json::json!({
            "secret_key": keyhog_core::redact(SECRET_ONE),
            "session_token": keyhog_core::redact(SESSION_ONE),
        })),
        "interned storage must remain the same report JSON object with string keys"
    );
}

/// Regression KH-1230: repeated findings from one compiled companion must share
/// the compiled name allocation instead of cloning a fresh `String` key per finding.
#[test]
fn repeated_companion_matches_reuse_the_compiled_name_identity() {
    let scanner = scanner_with_companion(false);
    let first = only_match(
        &scanner,
        &chunk(ACCESS_KEY_ONE, Some((SECRET_ONE, SESSION_ONE))),
    );
    let second = only_match(
        &scanner,
        &chunk(ACCESS_KEY_TWO, Some((SECRET_TWO, SESSION_TWO))),
    );

    for name in ["secret_key", "session_token"] {
        let first_name = first
            .companions
            .keys()
            .find(|candidate| candidate.as_ref() == name)
            .expect("first companion name");
        let second_name = second
            .companions
            .keys()
            .find(|candidate| candidate.as_ref() == name)
            .expect("second companion name");
        assert!(
            Arc::ptr_eq(first_name, second_name),
            "{name} must reuse the scanner-construction interner allocation"
        );
    }
    assert_eq!(
        second.companions.get("secret_key").map(String::as_str),
        Some(SECRET_TWO)
    );
    assert_eq!(
        second.companions.get("session_token").map(String::as_str),
        Some(SESSION_TWO)
    );
}

/// Regression KH-1230: a detector without companion metadata must keep the
/// finding's companion map at zero capacity, proving it owns no heap bucket allocation.
#[test]
fn no_companion_finding_owns_zero_companion_allocation() {
    let finding = only_match(&scanner_without_companions(), &chunk(ACCESS_KEY_ONE, None));
    assert!(finding.companions.is_empty());
    assert_eq!(
        finding.companions.capacity(),
        0,
        "the no-companion branch must return the allocation-free empty map"
    );
}

/// Regression KH-1230: interning companion names must not weaken required
/// companion semantics; a missing required AWS secret still suppresses the access-key match.
#[test]
fn missing_required_companion_remains_a_negative_match() {
    let matches = scanner_with_companion(true)
        .scan(&chunk(ACCESS_KEY_ONE, None))
        .expect("missing-companion fixture scan must succeed");
    assert!(
        matches.is_empty(),
        "an access key without its required secret_key companion must not be reported"
    );
}
