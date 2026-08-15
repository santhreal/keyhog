//! Contract coverage for cross-file credential correlation.
//!
//! Correlation is the first keyhog output derived from the RELATIONSHIP between
//! findings rather than from a single match, so the contracts worth defending
//! are the ones a reader would otherwise have to trust:
//!
//! * the Tier-B policy only names detectors that actually ship, otherwise a
//!   whole composite is silently unsatisfiable;
//! * the policy fails closed on shapes that would make correlation claim
//!   corroboration it never computed;
//! * a composite is reported only for a genuine cross-file split, never for
//!   parts that already share a file (companions cover that) and never for an
//!   ambiguous directory;
//! * correlation lifts confidence above the strongest member and never past the
//!   configured ceiling;
//! * the same findings always produce the same bytes.

use keyhog_core::{
    correlate_findings, correlation_composite_part_ids, detector_spec_by_id,
    validate_correlation_policy, CorrelationKind, CorrelationRole, CredentialHash, MatchLocation,
    Severity, VerificationResult, VerifiedFinding,
};
use std::collections::HashMap;
use std::sync::Arc;

fn sha256(value: &str) -> CredentialHash {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    CredentialHash::from_bytes(hasher.finalize().into())
}

fn finding(
    detector_id: &str,
    service: &str,
    credential: &str,
    file: &str,
    confidence: f64,
) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from(detector_id),
        detector_name: Arc::from(detector_id),
        service: Arc::from(service),
        severity: Severity::High,
        credential_redacted: "AK...YA".into(),
        credential_hash: sha256(credential),
        companions_redacted: HashMap::new(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from(file)),
            line: Some(7),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Unverifiable,
        metadata: HashMap::new(),
        additional_locations: Vec::new(),
        entropy: None,
        evidence_score: Some(confidence),
        evidence: keyhog_core::EvidenceVerdict::review_unattributed(),
    }
}

fn with_extra_location(mut finding: VerifiedFinding, file: &str) -> VerifiedFinding {
    finding.additional_locations.push(MatchLocation {
        source: Arc::from("filesystem"),
        file_path: Some(Arc::from(file)),
        line: Some(19),
        offset: 0,
        commit: None,
        author: None,
        date: None,
    });
    finding
}

/// Compare a lifted confidence to its intended value. The lift is one float
/// addition, so `0.60 + 0.30` is `0.8999999999999999`; asserting the exact bits
/// would test IEEE-754, not the contract.
fn assert_confidence(actual: Option<f64>, expected: f64) {
    let actual = actual.expect("correlated confidence must be present");
    assert!(
        (actual - expected).abs() < 1e-9,
        "expected confidence {expected}, got {actual}"
    );
}

const VALID_POLICY: &str = r#"
[settings]
reuse_min_files = 2
reuse_confidence_bonus = 0.15
max_confidence = 0.99
reuse_impact = "reused"

[[composite]]
id = "pair"
service = "svc"
name = "Pair"
severity = "critical"
required = ["a", "b"]
confidence_bonus = 0.30
impact = "both halves"
"#;

#[test]
fn every_tier_b_composite_part_names_a_shipped_detector() {
    let parts = correlation_composite_part_ids();
    assert!(
        parts.len() >= 10,
        "the shipped policy must name real composite parts, got {parts:?}"
    );
    let unknown: Vec<&str> = parts
        .iter()
        .copied()
        .filter(|id| detector_spec_by_id(id).is_none())
        .collect();
    assert_eq!(
        unknown,
        Vec::<&str>::new(),
        "credential-correlation.toml names detectors that do not ship; \
         those composites can never be satisfied"
    );
}

#[test]
fn policy_validation_fails_closed_on_degenerate_shapes() {
    validate_correlation_policy(VALID_POLICY, "<valid>").expect("baseline policy must load");

    let cases = [
        (
            "reuse_min_files = 2",
            "reuse_min_files = 1",
            "reuse_min_files",
        ),
        (
            "reuse_confidence_bonus = 0.15",
            "reuse_confidence_bonus = 0.0",
            "reuse_confidence_bonus",
        ),
        (
            "max_confidence = 0.99",
            "max_confidence = 1.5",
            "max_confidence",
        ),
        (
            "required = [\"a\", \"b\"]",
            "required = [\"a\"]",
            "required parts",
        ),
        (
            "required = [\"a\", \"b\"]",
            "required = [\"a\", \"a\"]",
            "more than once",
        ),
        ("impact = \"both halves\"", "impact = \"\"", "empty impact"),
    ];
    for (from, to, expected) in cases {
        let broken = VALID_POLICY.replace(from, to);
        assert_ne!(
            broken, VALID_POLICY,
            "test case {to:?} did not patch anything"
        );
        let error = validate_correlation_policy(&broken, "<broken>")
            .expect_err(&format!("{to:?} must be rejected"));
        assert!(
            error.contains(expected),
            "rejecting {to:?} must explain {expected:?}, got {error}"
        );
    }

    let duplicated = format!(
        "{VALID_POLICY}\n\
         [[composite]]\n\
         id = \"pair\"\n\
         service = \"svc\"\n\
         name = \"Pair again\"\n\
         severity = \"high\"\n\
         required = [\"c\", \"d\"]\n\
         confidence_bonus = 0.10\n\
         impact = \"shadowed row\"\n"
    );
    let error = validate_correlation_policy(&duplicated, "<duplicate>")
        .expect_err("a duplicate composite id must be rejected");
    assert!(
        error.contains("duplicate id"),
        "duplicate composite id must be named, got {error}"
    );
}

#[test]
fn value_reuse_groups_one_secret_seen_in_several_files() {
    let findings = vec![
        finding("adobe-api-key", "adobe", "SHARED", "a/one.rs", 0.50),
        finding(
            "spotify-client-credentials",
            "spotify",
            "SHARED",
            "b/two.rs",
            0.45,
        ),
        finding("adobe-api-key", "adobe", "OTHER", "a/three.rs", 0.90),
    ];

    let correlations = correlate_findings(&findings);
    assert_eq!(correlations.len(), 1, "only the shared value correlates");

    let group = &correlations[0];
    assert_eq!(group.kind, CorrelationKind::ValueReuse);
    assert_eq!(group.file_count, 2);
    assert_eq!(group.service, "multiple");
    assert_eq!(group.strongest_member_evidence_score, Some(0.50));
    // 0.50 lifted by the Tier-B reuse bonus, below the ceiling.
    assert_eq!(group.evidence_score, Some(0.65));
    assert_eq!(group.members.len(), 2);
    assert!(group
        .members
        .iter()
        .all(|member| member.role == CorrelationRole::SameValue));
    assert_eq!(group.scope, None);
}

#[test]
fn value_reuse_never_exceeds_the_configured_ceiling() {
    let findings = vec![
        finding("adobe-api-key", "adobe", "SHARED", "a/one.rs", 1.0),
        finding("adobe-api-key", "adobe", "SHARED", "b/two.rs", 1.0),
    ];
    let correlations = correlate_findings(&findings);
    assert_eq!(correlations.len(), 1);
    assert_eq!(correlations[0].evidence_score, Some(1.0));
}

#[test]
fn one_finding_spanning_files_is_reuse_but_one_file_is_not() {
    let spread = with_extra_location(
        finding("aws-access-key", "aws", "AKIA0", "dir/a.tf", 0.60),
        "dir/b.env",
    );
    assert_eq!(correlate_findings(&[spread]).len(), 1);

    let single = finding("aws-access-key", "aws", "AKIA0", "dir/a.tf", 0.60);
    assert_eq!(correlate_findings(&[single]).len(), 0);
}

#[test]
fn composite_reports_a_split_pair_and_lifts_severity_from_tier_b() {
    let findings = vec![
        finding("aws-access-key", "aws", "AKIA0", "infra/main.tf", 0.60),
        finding(
            "aws-secret-access-key",
            "aws",
            "SECRET0",
            "infra/.env",
            0.55,
        ),
    ];

    let correlations = correlate_findings(&findings);
    let composites: Vec<_> = correlations
        .iter()
        .filter(|group| group.kind == CorrelationKind::SplitComposite)
        .collect();
    assert_eq!(composites.len(), 1);

    let group = composites[0];
    assert_eq!(group.id, "composite:aws-iam-user@infra");
    assert_eq!(group.scope.as_deref(), Some("infra"));
    assert_eq!(group.service, "aws");
    assert_eq!(group.file_count, 2);
    // Members were `high`; the Tier-B row declares the pair `critical`.
    assert_eq!(group.severity, Severity::Critical);
    assert_eq!(group.strongest_member_evidence_score, Some(0.60));
    assert_confidence(group.evidence_score, 0.90);
    assert_eq!(group.members.len(), 2);
    assert!(group
        .members
        .iter()
        .all(|member| member.role == CorrelationRole::RequiredPart));
    assert_eq!(group.locations.len(), 2);
}

#[test]
fn composite_is_silent_when_one_file_already_holds_both_parts() {
    let findings = vec![
        finding("aws-access-key", "aws", "AKIA0", "infra/all.env", 0.60),
        finding(
            "aws-secret-access-key",
            "aws",
            "SECRET0",
            "infra/all.env",
            0.55,
        ),
    ];
    let composites = correlate_findings(&findings)
        .into_iter()
        .filter(|group| group.kind == CorrelationKind::SplitComposite)
        .count();
    assert_eq!(
        composites, 0,
        "a same-file pair is already covered by the detector's companion regex"
    );
}

#[test]
fn composite_is_silent_when_the_directory_pairing_is_ambiguous() {
    let findings = vec![
        finding("aws-access-key", "aws", "AKIA0", "infra/a.tf", 0.60),
        finding("aws-access-key", "aws", "AKIA1", "infra/b.tf", 0.60),
        finding(
            "aws-secret-access-key",
            "aws",
            "SECRET0",
            "infra/.env",
            0.55,
        ),
    ];
    let composites = correlate_findings(&findings)
        .into_iter()
        .filter(|group| group.kind == CorrelationKind::SplitComposite)
        .count();
    assert_eq!(
        composites, 0,
        "two candidate access keys make the pairing a guess, so nothing is claimed"
    );
}

#[test]
fn composite_admits_an_optional_part_without_requiring_it() {
    let findings = vec![
        finding("aws-access-key", "aws", "AKIA0", "infra/main.tf", 0.60),
        finding(
            "aws-secret-access-key",
            "aws",
            "SECRET0",
            "infra/.env",
            0.55,
        ),
        finding(
            "aws-session-token",
            "aws",
            "TOKEN0",
            "infra/session.sh",
            0.50,
        ),
    ];
    let group = correlate_findings(&findings)
        .into_iter()
        .find(|group| group.kind == CorrelationKind::SplitComposite)
        .expect("the required pair still forms the composite");
    assert_eq!(group.members.len(), 3);
    assert_eq!(
        group
            .members
            .iter()
            .filter(|member| member.role == CorrelationRole::OptionalPart)
            .count(),
        1
    );
}

#[test]
fn correlation_output_is_order_independent() {
    let mut findings = vec![
        finding("aws-access-key", "aws", "AKIA0", "infra/main.tf", 0.60),
        finding(
            "aws-secret-access-key",
            "aws",
            "SECRET0",
            "infra/.env",
            0.55,
        ),
        finding("adobe-api-key", "adobe", "SHARED", "a/one.rs", 0.50),
        finding(
            "spotify-client-credentials",
            "spotify",
            "SHARED",
            "b/two.rs",
            0.45,
        ),
    ];
    let forward = serde_json::to_string(&correlate_findings(&findings)).expect("serialize");
    findings.reverse();
    let reversed = serde_json::to_string(&correlate_findings(&findings)).expect("serialize");
    assert_eq!(forward, reversed);

    findings.rotate_left(2);
    let rotated = serde_json::to_string(&correlate_findings(&findings)).expect("serialize");
    assert_eq!(forward, rotated);
}

#[test]
fn empty_and_uncorrelated_finding_sets_produce_nothing() {
    assert!(correlate_findings(&[]).is_empty());
    let isolated = vec![
        finding("aws-access-key", "aws", "AKIA0", "one/a.tf", 0.60),
        finding("stripe-secret-key", "stripe", "SK0", "two/b.rs", 0.90),
    ];
    assert!(correlate_findings(&isolated).is_empty());
}
