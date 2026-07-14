//! Regression: a verified-REVOKED finding must count as inactive in the text
//! summary, NOT as "unverified". The summary computes
//! `unverified = count - live - dead`; before the fix `Revoked` fell through the
//! tally's `_ => {}` arm, so a secret we DID verify (and found revoked) was
//! reported as having unknown liveness - the exact opposite of the report's
//! verification honesty. `Revoked` now folds into the inactive (`dead`) tally.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use keyhog_core::{
    write_report, MatchLocation, ReportFormat, Severity, VerificationResult, VerifiedFinding,
};

fn finding(v: VerificationResult) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from("aws-access-key"),
        detector_name: Arc::from("AWS Key"),
        service: Arc::from("aws"),
        severity: Severity::High,
        credential_redacted: Cow::Borrowed("AKIA..."),
        credential_hash: [0u8; 32].into(),
        companions_redacted: std::collections::HashMap::new(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from("a.txt")),
            line: Some(1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification: v,
        metadata: HashMap::new(),
        additional_locations: vec![],
        entropy: None,
        confidence: Some(0.9),
    }
}

fn render(findings: &[VerifiedFinding]) -> String {
    let mut buf: Vec<u8> = Vec::new();
    write_report(
        &mut buf,
        ReportFormat::Text {
            color: false,
            example_suppressions: 0,
            dogfood_active: false,
        },
        findings,
    )
    .expect("text report");
    String::from_utf8(buf).expect("utf8")
}

#[test]
fn revoked_counts_as_inactive_not_unverified() {
    // 1 revoked (verified inactive) + 1 skipped (genuinely unverified).
    let out = render(&[
        finding(VerificationResult::Revoked),
        finding(VerificationResult::Skipped),
    ]);
    let summary = out
        .lines()
        .find(|l| l.contains("secret") && l.contains("found"))
        .expect("results summary line present");

    assert!(summary.contains("2 secrets found"), "count: {summary}");
    assert!(
        summary.contains("1 dead"),
        "revoked must roll into the inactive/dead tally: {summary}"
    );
    assert!(
        summary.contains("1 unverified"),
        "only the skipped finding is genuinely unverified: {summary}"
    );
    assert!(
        !summary.contains("2 unverified"),
        "the verified-revoked finding must NOT be mislabeled unverified: {summary}"
    );
}

#[test]
fn dead_and_revoked_both_count_inactive() {
    let out = render(&[
        finding(VerificationResult::Dead),
        finding(VerificationResult::Revoked),
    ]);
    let summary = out
        .lines()
        .find(|l| l.contains("secret") && l.contains("found"))
        .expect("results summary line present");
    assert!(summary.contains("2 secrets found"), "count: {summary}");
    assert!(
        summary.contains("2 dead"),
        "dead + revoked both inactive: {summary}"
    );
    assert!(
        !summary.contains("unverified"),
        "nothing is unverified when both were checked: {summary}"
    );
}
